# Architecture

Jōei is a single Go binary: an HTTP proxy that intercepts package downloads,
runs them through a pipeline of security gates, and serves approved artifacts
from a local cache. An embedded React console observes and tunes it at
runtime. This document maps the packages and the rules that keep them
decoupled.

## The dependency rule

Everything depends inward on `internal/gate`; nothing in `gate` depends on
anything but the standard library.

```
                 cmd/jo-ei  (composition root — the only place that wires concretes)
                     │
   ┌─────────┬───────┼────────┬──────────────┐
   ▼         ▼       ▼        ▼              ▼
 proxy    console  revalidate dockerproxy  … every subsystem
   │         │       │        │
   └─────────┴───┬───┴────────┘
                 ▼
          internal/gate  (domain types + ports; imports stdlib only)
                 ▲
   ┌─────────┬───┴─────┬───────────┬──────────┐
   │         │         │           │          │
 scanner  supplychain  policy   adapters   cache / telemetry
 (implement the ports defined in gate)
```

`internal/gate` holds the domain vocabulary:

- **Types** — `PackageRef`, `PackageMetadata`, `Severity`, `CVEFinding`,
  `ScanResult`, `PolicyDecision`, `FilterResult`, `AVResult`, `Event`,
  verdict/gate constants.
- **Ports** — `RegistryAdapter`, `CVEScanner`, `AVScanner`, `PolicyDecider`,
  `SCFilter`, `ArtifactCache`, `Recorder`.

Implementations satisfy these interfaces structurally; `gate` never imports an
implementation, and `internal/proxy` (the HTTP layer) is imported only by
`cmd/jo-ei`. Interfaces live with their consumer, not their implementation —
that is what makes the graph acyclic.

## Package map

| Package | Role |
|---|---|
| `cmd/jo-ei` | CLI (cobra): `serve` (default), `hashpw`. Loads config, wires every subsystem, owns graceful shutdown. |
| `internal/gate` | Domain types and ports (see above). |
| `internal/proxy` | The package-registry HTTP data path: gate pipeline orchestration (`Handler`), path-prefix routing (`Mux`), transparent proxying of metadata requests. |
| `internal/proxy/adapters` | One `RegistryAdapter` per ecosystem: PyPI, npm (+ Yarn alias), Maven, RubyGems. Adapters normalize download URLs to a `PackageRef`, fetch publish metadata, and enumerate upstream URLs (multi-upstream failover). |
| `internal/proxy/dockerproxy` | Docker Registry v2 pull-through proxy: manifest gate (Trivy + malware engines over config blob and layers), blob cache, tag index, quarantine. Verdicts are decided on the manifest request. |
| `internal/supplychain` | Min-age filter (24h rule) with per-gate allowlist. |
| `internal/scanner` | `CVEScanner` (osv.dev with TTL cache), `AVScanner`s (ClamAV clamd protocol, ICAP RFC 3507), `MultiScanner` fan-out, `LimitedScanner` concurrency semaphore, health probes. |
| `internal/policy` | Policy engine (`PolicyDecider`): severity threshold, per-gate allowlists, denylist; `Runtime` holds the mutable snapshot, seeded from YAML on first boot and persisted via the settings store. |
| `internal/cache` | Artifact cache: SQLite index + files on disk, LRU eviction to `max_size_gb`, revalidation bookkeeping. Satisfies `gate.ArtifactCache`. |
| `internal/revalidate` | Periodic sweep re-running the gates over cached entries; evicts entries that newly fail (new CVE, new AV signature, new denylist entry). |
| `internal/httpx` | Outbound discipline per upstream host: concurrency limiter, token-bucket rate limiter, 429/503 circuit breaker. |
| `internal/telemetry` | `Recorder` implementation: SQLite-backed event store with retention pruning, daily aggregates, SSE broadcaster for the console's live feed. |
| `internal/storage` | Shared embedded SQLite (pure Go, no cgo): PRAGMAs, per-component migrations. `storagetest` holds the retrying temp-dir helper for tests. |
| `internal/settings` | Generic key→JSON settings store on `storage`, used for policy and registry persistence. |
| `internal/config` | YAML + `JOEI_*` env loading (viper) and validation. |
| `internal/auth` | HTTP Basic middleware for the console/API; bcrypt user lists from YAML and `JOEI_CONSOLE_AUTH_USERS`. |
| `internal/console` | Console REST API (`/api/…`) and SSE event stream. |
| `internal/health` | Scanner health registry and probe loop. |
| `web` | Embedded console SPA (React, vendored, compiled by `internal/uibuild` via `go generate` — no npm). |
| `integration` | Black-box tests (build tag `integration`) exercising the full wiring with in-process fakes. |

## The gate pipeline

Every intercepted package download flows through `proxy.Handler`:

```
request ──► adapter.NormalizeRequest ──► PackageRef?
   │ no: transparent proxy (metadata, simple API)
   ▼ yes
1. Cache lookup ──── hit & clean ──► serve from cache      (verdict CACHE)
   │                 hit & dirty ──► 403                   (fail closed)
   ▼ miss
2. Supply-chain gate  (min-age; Maven defers it to the download's
   │                   Last-Modified header — one GET instead of HEAD+GET)
   ▼                                     block ──► 423     (verdict BLOCK)
3. CVE gate           (osv.dev scan + policy evaluation)
   │                                     block ──► 403     (verdict BLOCK)
   ▼
4. Download from upstreams (in order, with failover, rate-limited)
   ▼
5. Malware gate       (all engines scan the artifact; any detection blocks)
   │                                     block ──► 403     (verdict BLOCK)
   ▼
6. Cache put ──► serve                                     (verdict PASS)
```

Design invariants:

- **Fail closed.** A scanner error blocks the request (503) rather than
  letting an unscanned artifact through. A cached entry with a failed scan
  serves 403.
- **Exactly one telemetry event per intercepted request**, emitted at the
  outcome; a nil `Recorder` is a no-op and telemetry can never fail the data
  path.
- **Block responses are JSON** with a machine-readable `reason` and
  `request_id` (see the README's block-response reference).

Docker images take a parallel path in `dockerproxy`: the whole verdict (Trivy
vulnerability/secret scan + malware engines over each layer) is computed when
the client requests the **manifest**, so a rejected image is never partially
served. Verdicts are cached; repeat pulls record `CACHE`.

## Persistence

One SQLite file (`database.path`) shared by three components, each with its
own migration versioning (`internal/storage.ApplyMigrations`):

| Component | Data |
|---|---|
| telemetry | request events (30-day retention), per-day metrics (365-day), lifetime counters |
| settings | runtime policy params, registry enable/disable overlays |
| cache index | artifact metadata, last-hit (LRU), last-validated (revalidation) |

Runtime edits from the console (policy, registries) win over YAML after first
boot; YAML only seeds an empty store.

## Concurrency discipline

- Per-upstream-host limits (`internal/httpx`): concurrency semaphore +
  token-bucket rate + circuit breaker — one shared `http.Client` so metadata,
  downloads, and transparent proxying all count against the same budget.
- Malware scans are capped globally (`malware.max_concurrent_scans`,
  `LimitedScanner`) so download bursts don't overwhelm clamd/ICAP worker
  pools.
- The cache eviction worker and the revalidation sweeper are single background
  goroutines with coalescing triggers.

## Where to start reading

1. `internal/gate/gate.go` — the vocabulary everything else speaks.
2. `internal/proxy/handler.go` — the pipeline above, in ~500 lines.
3. `cmd/jo-ei/main.go` — how everything is wired.
4. `docs/superpowers/` — design docs and implementation plans for every
   shipped feature, in chronological order.
