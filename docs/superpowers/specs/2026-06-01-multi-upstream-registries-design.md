# Multi-Upstream Registries — Design

**Date:** 2026-06-01
**Branch:** `feature/multi-upstream-registries`
**Status:** Approved (brainstorming complete)

## Problem

Each registry provider (`pypi`, `npm`, `maven`) currently points at a single
upstream URL (`RegistryConfig.Upstream string`). Real deployments need several
repositories per provider — e.g. Maven artifacts split across
`repo1.maven.org/maven2` and `repo.spring.io/release`. We need flexible,
per-provider configuration of multiple upstreams.

## Decisions

| Topic | Decision |
|---|---|
| Resolution strategy | **Sequential fallback** — try upstreams in list order, first that serves the artifact wins. |
| Config shape | **Breaking change**: replace `upstream: <string>` with `upstreams: [<string>, ...]`. No legacy field. |
| Fallback trigger | **Any** failure (404/410, 5xx, timeout, connection refused) → try next. |
| All-fail outcome | If every attempt was 404/410 → client gets **404**; otherwise → **502**. |
| Resolution granularity | **Per-request (like Nexus group repos)** — each operation (metadata fetch, artifact download, transparent proxy) independently walks the list. No package-level repo pinning. |
| Listings / metadata index | **First-hit fallback** (no cross-repo merging). Merging listings is deferred to a later phase. |
| Ordering | Upstreams tried **sequentially in config order** (order = priority). Not parallel. |
| Negative cache | **Out of scope** for this phase; noted as a future optimization. |

### Reference: how Nexus does it

Nexus exposes multiple remotes via a **group repository** aggregating several
**proxy repositories** (one remote URL each). Group resolution is per-file: a
request walks the ordered member list and returns the first member that has the
file; binary artifacts use first-hit, listing metadata (`maven-metadata.xml`) is
merged. Nexus also keeps a negative cache for 404s. This design mirrors the
first-hit, per-request behaviour and defers listing-merge and negative-cache.

## Configuration

```yaml
registries:
  maven:
    enabled: true
    upstreams:
      - "https://repo1.maven.org/maven2"
      - "https://repo.spring.io/release"
  npm:
    enabled: true
    upstreams: ["https://registry.npmjs.org"]
  pypi:
    enabled: true
    upstreams: ["https://pypi.org"]
```

**Validation:** when `enabled: true`, `len(upstreams) >= 1`, otherwise config
load fails with a clear error. Each URL is right-trimmed of `/`.

## Fallback model (per-request)

Each operation independently walks `upstreams` in order, sequentially:

| Operation | Owner | Success | Otherwise |
|---|---|---|---|
| `FetchMetadata` (age check) | adapter | first upstream returning valid metadata | try next |
| Artifact download | handler | first upstream returning HTTP 200 | try next |
| Transparent proxy (listings/metadata) | handler | first upstream with status < 400 | try next |

Any failure (404/410, 5xx, timeout, connection refused) advances to the next
upstream. When the list is exhausted: all-404/410 → client **404**; any other
failure mix → client **502**.

## Interface & component changes

### `RegistryAdapter` (internal/proxy/adapter.go)

Replace:
```go
UpstreamURL(r *http.Request) string
```
with:
```go
UpstreamURLs(r *http.Request) []string  // one candidate per configured upstream
```
Implementation: `[base + r.URL.RequestURI() for base in upstreams]`.

### Adapters (pypi / npm / maven)

- Constructor: `NewXAdapter(upstream string)` → `NewXAdapter(upstreams []string)`
  (right-trim each).
- Field `upstream string` → `upstreams []string`.
- `FetchMetadata`: extract current body into a private
  `fetchMetadataFrom(ctx, base, ref)` parameterised by one base URL; the public
  method iterates `upstreams` until first success, accumulating `lastErr`.

### `Handler` (internal/proxy/handler.go)

- Remove `HandlerConfig.Upstream` (candidates now come from the adapter).
- Download: new helper `downloadFromUpstreams(ctx, urls []string) (tmpPath string, allNotFound bool, err error)` — tries each `downloadToTemp`; handler maps the
  result to HTTP 404 (allNotFound) or 502.
- `proxyTransparent`: iterate over `adapter.UpstreamURLs(r)`; stream the first
  response with status < 400; if all fail, return 404 (all were 404) or 502.

### `main.go`

- `buildHandler` no longer takes `upstream`.
- Adapter constructors receive `cfg.Registries.X.Upstreams`.

### Responsibility boundary

Adapter knows **how to build the URL** for its ecosystem and **how to parse
metadata**. Handler knows the **fallback strategy** (walk candidates + map
errors to HTTP status). Registry-format parsing stays entirely in adapters.

## Testing (TDD)

- **config_test.go:** parse `upstreams: [...]`; error when `enabled:true` and
  empty list.
- **adapters (pypi/npm/maven)_test.go:** update constructors to slices; new
  `FetchMetadata` tests with two mock upstreams — first 404/500 → second used;
  all fail → error. `UpstreamURLs` returns one URL per base.
- **handler_test.go:** download fallback (first 404 → second 200); all 404 →
  404 to client; first 500 → second 200; all fail → 502. Transparent-proxy
  fallback likewise.
- **integration:** multi-upstream scenario with two `httptest` servers.

Tests are written before implementation, one failing test at a time.

## Out of scope (future phases)

- Cross-repo listing/metadata merge (`maven-metadata.xml`, npm package doc,
  pypi simple index).
- Negative cache for 404 responses.
- Per-upstream auth / priority weights / structured repository objects.
- Parallel upstream probing.
