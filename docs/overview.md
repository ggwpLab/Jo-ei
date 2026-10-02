# Jōei: a proxy that keeps malicious packages out of your build

*[Русская версия](overview.ru.md)*

> 浄衛 — "The Purification Gate". A transparent proxy for package registries and
> Docker images that checks every download before it reaches a developer's
> machine or a CI runner.

## The problem

Supply chain attacks are now a routine part of the threat landscape. An attacker
takes over a maintainer account or publishes a package with a look-alike name,
and within minutes the malicious version is being fetched by thousands of
`pip install`, `npm install` and `docker pull` runs. Typical scenarios:

- **a poisoned release**: a new version of a popular library ships with a
  backdoor; the registry pulls it a few hours later, but plenty of people have
  downloaded it by then;
- **known vulnerabilities**: an old dependency version with a published CVE
  keeps getting installed from a lockfile;
- **malicious code in an artifact**: a package archive or an image layer
  contains a known signature;
- **secrets in images**: keys or tokens left behind in a Docker image layer.

Each of these risks can be covered by a separate tool in CI. Jōei covers them
all in one place, at the point of download, and developers don't have to change
their workflow for it.

## The idea

Jōei is a single Go binary. It sits between the package manager and the
upstream registry. The client talks to the proxy instead of PyPI, npm, Maven
Central, RubyGems, the Go module proxy or Docker Hub. Every artifact download
runs through a pipeline of checks ("gates"). An artifact that passes all of
them goes into the local cache and is served to the client. One that doesn't
gets a structured JSON response explaining why it was blocked.

```
Developer (pip / npm / mvn / go / bundle / docker pull)
        │
        ▼
  ┌──────────────────────────────────────────────┐
  │                 Jōei :8080                   │
  │  1. Cache (a hit is served immediately)      │
  │  2. Supply-chain filter (min package age)    │
  │  3. CVE scanner (osv.dev; Trivy for images)  │
  │  4. Malware scanner (ClamAV / ICAP)          │
  └──────────────────────────────────────────────┘
        │
        ▼
   Upstream registry
```

Index and metadata requests (for example `/simple/requests/` for pip) pass
straight through without scanning. Only what actually gets installed is
checked.

## Four layers of protection

Packages and Docker images go through the same gates. The only difference is
the engine behind an individual check.

### 1. Minimum package age (衛, "guard")

The proxy fetches the version's publish time from the registry. If the version
is younger than `supply_chain.min_age_hours` (24 hours by default), the client
gets **HTTP 423 Locked** with a `block_until` field. For Docker images, the
`created` field of the image config serves as the publish time. Like the CVE
severity threshold, the minimum age is a setting: it lives in `config.yaml` (or
`JOEI_SUPPLY_CHAIN_MIN_AGE_HOURS`) and can be changed at runtime from the
console's policy editor.

The rule is simple but effective: most poisoned releases are spotted and
removed within the first few hours. Even a one-day delay cuts off a whole class of
attacks without any signatures.

Since v0.5.0, npm gets **metadata filtering**. npm resolves a version range
(`^1.0.0`) before it requests a tarball, so a blocked fresh version used to
break the whole install. The proxy now strips disallowed versions from the
metadata document itself, and the range resolves to the newest version the
policy allows. The install goes through. Rewritten documents carry their own
`ETag` so HTTP caching keeps working correctly.

### 2. Known vulnerabilities (浄, "purification")

For packages, the CVE gate is backed by [osv.dev](https://osv.dev): known
vulnerabilities are looked up by name and version. For Docker images, **Trivy**
plays the same role: it scans the image for vulnerabilities and also looks for
secrets (keys, tokens) left in its layers. This is not a separate step but the
same gate with the same policy: one severity threshold and one denylist.

If a finding is at or above `cve.block_on` (`HIGH` by default), the response is
**403** with the list of findings. osv.dev results are cached in memory. For
accepted risks there is an allowlist that can pin an exact version.

### 3. Malware scanning

The artifact is downloaded to a temp file and scanned by **every** configured
engine: ClamAV over its native `INSTREAM` protocol and any ICAP server
(Kaspersky, Dr.Web and the like). A single detection is enough. For a Docker
image, the config blob and every layer are scanned. A malware verdict cannot be
bypassed with the allowlist: the scan runs on every download.

### 4. Denylist

Packages on the **denylist** are always blocked, whatever the scan results.

### How Docker differs

For Docker, Jōei acts as a pull-through registry mirror. All gates for an image
run at once, **on the manifest request**, so a rejected image never reaches the
client, not even partially.

## Fail-closed by design

The project's core invariant: **an unchecked artifact is never served**.

- If a scanner is unreachable, the request is blocked (503), not let through.
- A cache entry with a failed check serves 403.
- With no users configured, the console answers 503 on `/api/` and lets nobody
  in, while the proxy keeps serving.

## A cache that re-checks itself

Approved artifacts are stored locally: an index in SQLite, files on disk, LRU
eviction against the `max_size_gb` limit. Repeat requests are served without
contacting the upstream and are marked with the `X-Joei-Cache: HIT` header.

CVE databases and malware signatures get updated, so a package that was
"clean" yesterday may turn out vulnerable today. Jōei re-checks **lazily**:
each gate has its own TTL (24 hours by default). When a cached entry is
requested after its TTL has expired, the expired gate runs again. If the entry
no longer passes, it is evicted. Re-check load scales with traffic rather than
cache size. Concurrent re-checks of the same entry collapse into a single scan
(singleflight).

Docker images pulled by digest with a fresh verdict are served from the cache
**offline**, without contacting the upstream.

## Supported ecosystems

| Ecosystem | How to connect |
|---|---|
| PyPI | `--index-url http://<jo-ei>/pypi/simple/` |
| npm / Yarn | `--registry http://<jo-ei>/npm/` (Yarn via `/yarn/`) |
| Maven / Gradle | mirror pointing at `http://<jo-ei>/maven/` |
| RubyGems / Bundler | `bundle config mirror.https://rubygems.org http://<jo-ei>/rubygems` |
| Go modules | `GOPROXY=http://<jo-ei>/go` |
| Docker Hub | `"registry-mirrors": ["http://<jo-ei>"]` in `daemon.json` |

Each registry accepts an ordered list of `upstreams` with sequential failover
(Nexus-style): a 404, 5xx, timeout or refused connection moves the request on
to the next mirror. Corporate mirrors with self-signed certificates are
trusted via `tls.ca_files`, without weakening TLS verification for public
registries.

Ready-made client configs live in [`examples/`](../examples/).

## Admin console

A React SPA is embedded in the binary and served at `/console/`. It works
without a CDN and needs no npm toolchain to build: React is vendored and the
bundle is compiled via `go generate`. The console offers:

- **Overview**: the gate pipeline, KPIs (requests, cache hit rate, blocks by
  type), 30-day sparklines, scanner health;
- **a live request feed** over Server-Sent Events with PASS / CACHE / BLOCK
  verdicts;
- **quarantine**: which packages the minimum-age rule is holding right now;
- **a policy editor**: gate modes (`enforce` / `dry_run` / `off`), the CVE
  severity threshold, per-gate allowlists, the denylist;
- **registries and cache**: upstream mirrors, cache usage, cleanup of stale
  entries.

![Console overview](images/console-overview.png)

Policy changes apply **immediately, without a restart**, and are persisted to
the database. After the first boot, the values in `config.yaml` only seed an
empty store; from then on the database is the source of truth.

Scanner health is tracked actively (clamd `PING`, ICAP `OPTIONS`, Trivy
`/healthz`) and passively for osv.dev: its status is derived from real traffic,
with no extra load on the public API.

### Authentication

Console sign-in uses JWT sessions. The browser holds two HttpOnly cookies with
`SameSite=Strict`: an access token for 15 minutes and a refresh token for 7
days. Scripts and CI get a bearer token from `POST /api/auth/login`. Passwords
are stored as bcrypt hashes (via the built-in `jo-ei hashpw` command), and
users can be supplied through the `JOEI_CONSOLE_AUTH_USERS` environment
variable so the hashes stay out of the repository. TLS is deliberately not
built into the binary; a reverse proxy in front of Jōei terminates it.

## Architecture

The project is built around a single dependency rule: **every package depends
on `internal/gate`, and `gate` depends only on the standard library**.

```
                 cmd/jo-ei  (composition root)
                     │
   ┌─────────┬───────────────┬──────────────┐
   ▼         ▼               ▼              ▼
 proxy    console       dockerproxy    … subsystems
   └─────────┴───┬──────────┘
                 ▼
          internal/gate  (domain types + ports)
                 ▲
   ┌─────────┬───┴─────┬───────────┬──────────┐
 scanner  supplychain  policy   adapters   cache / telemetry
```

`gate` defines the domain vocabulary (`PackageRef`, `ScanResult`,
`PolicyDecision`, verdicts) and the ports (`RegistryAdapter`, `CVEScanner`,
`AVScanner`, `ArtifactCache`, `Recorder` and others). Implementations satisfy
these interfaces structurally and are wired together only in `cmd/jo-ei`.
Interfaces are declared next to their consumer, so the dependency graph is
acyclic and every subsystem can be tested in isolation.

Key technical decisions:

- **One SQLite file** (pure Go, no cgo) for telemetry, settings and the cache
  index, with per-component migrations. Every event is written in a
  synchronous transaction, so there is no window for data loss on a crash.
- **Outbound request discipline** (`internal/httpx`): each upstream host gets
  a concurrency semaphore, a token-bucket rate limiter and a circuit breaker
  on 429/503. All requests share one `http.Client` and draw on the same
  budget.
- **Capped concurrent malware scans** (`max_concurrent_scans`, 8 by default):
  a burst of downloads doesn't overwhelm the clamd worker pool.
- **Exactly one telemetry event per intercepted request.** A telemetry failure
  can never break the request path.

Three files make a good starting point for reading the code:
`internal/gate/gate.go` (the vocabulary), `internal/proxy/handler.go` (the
pipeline, around 500 lines) and `cmd/jo-ei/main.go` (the wiring).

## Quick start

The compose file runs the released image `ghcr.io/ggwplab/jo-ei` from GHCR, so
nothing is compiled: the clone only provides `docker-compose.yaml`,
`config.yaml` and `.env.example`.

```bash
git clone https://github.com/ggwpLab/Jo-ei.git && cd Jo-ei
cp .env.example .env

HASH=$(printf '%s' 'change-me' | docker-compose run --rm -T jo-ei hashpw)
echo "JOEI_CONSOLE_AUTH_USERS=admin:$HASH" > .env
docker-compose up -d

pip install requests --index-url http://localhost:8080/pypi/simple/ --trusted-host localhost
```

ClamAV and Trivy run as sidecars in the compose file. For a reproducible
deployment, pin a release tag of the image (for example `:0.5.0`). To run a
local checkout instead, build it from source with `docker-compose up -d --build`.
Prebuilt binaries for Linux, macOS and Windows (amd64/arm64) are published on
the releases page.

## Release history

| Version | Date | Highlights |
|---|---|---|
| 0.1.0 | 2026-07-04 | First public release: PyPI, npm, Maven, RubyGems, Docker; four gates; console; persistent telemetry |
| 0.2.0 | 2026-07-19 | Lazy TTL-based cache re-checks instead of a background sweep; on-demand cache cleanup |
| 0.3.0 | 2026-07-20 | Go modules; offline by-digest Docker pulls; singleflight for re-checks |
| 0.4.0 | 2026-09-06 | JWT authentication instead of HTTP Basic; trusted CAs for upstreams; lower console CPU usage |
| 0.5.0 | 2026-09-28 | npm metadata filtering: blocked versions are hidden and the install goes through |

The project went from its first commit (May 30, 2026) to five releases in about
four months. The Go code, tests included, runs to around 24 thousand lines.
Every feature comes with a design doc and an implementation plan in
`docs/superpowers/`.

## Who it's for

- Teams that want supply chain protection without rebuilding their CI.
- Companies with a corporate ICAP antivirus they want to apply to open-source
  dependencies.
- Air-gapped and semi-isolated environments that need a caching proxy anyway,
  where it makes sense for that proxy to filter as well.

Keep the limitations in mind. Jōei does not replace SCA analysis of source code
and does not catch unknown malicious code that has no signature yet. The
minimum-age rule also delays legitimate urgent fixes; the allowlist exists for
those.

## Links

- Repository: <https://github.com/ggwpLab/Jo-ei>
- Full configuration reference: [`docs/configuration.md`](configuration.md)
- Architecture: [`docs/architecture.md`](architecture.md)
- License: MIT
