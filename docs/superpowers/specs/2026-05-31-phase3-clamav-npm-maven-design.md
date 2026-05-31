# Phase 3 Design — ClamAV Scanner + npm/Maven Adapters

**Status:** Approved
**Date:** 2026-05-31

## Goal

Add malware scanning (ClamAV) and two new registry adapters (npm, Maven) to
sca-proxy, plus a path-prefix router so a single proxy instance can serve
multiple ecosystems.

## Scope

In scope:
1. **ClamAV scanner** — `internal/scanner/clamav.go`: a clamd INSTREAM client over
   a Unix socket, implementing a new `proxy.AVScanner` interface. Wired into the
   handler pipeline after the artifact is downloaded to a temp file, before caching.
2. **npm adapter** — `internal/proxy/adapters/npm.go`: a `RegistryAdapter` for
   `registry.npmjs.org`.
3. **Maven adapter** — `internal/proxy/adapters/maven.go`: a `RegistryAdapter` for
   `repo1.maven.org/maven2`.
4. **Router multiplexer** — `internal/proxy/mux.go`: path-prefix dispatch to
   per-registry handlers.

Out of scope (later phases): Go adapter, Admin API, Prometheus, S3 cache.

## Tech stack

Go 1.25, stdlib `net`/`net/http`, `httptest` and a TCP mock for clamd in tests,
`testify`. No new external dependencies. Module path
`github.com/sca-proxy/sca-proxy`.

---

## 1. ClamAV scanner

New interface in `internal/proxy/adapter.go` (alongside `CVEScanner`):

```go
// AVResult records the outcome of an antivirus scan of a single file.
type AVResult struct {
    Clean     bool
    Signature string // signature name when infected, "" otherwise
}

// AVScanner scans a file on disk for malware.
// Implementations must be safe for concurrent use.
type AVScanner interface {
    Scan(ctx context.Context, filePath string) (*AVResult, error)
}
```

Client constructor: `NewClamAVScanner(address string, timeout time.Duration)`.

- `address` is `unix:///var/run/clamav/clamd.sock` or `tcp:host:3310`, parsed into
  a (network, addr) pair. Tests use a `tcp:` mock — the INSTREAM protocol is
  identical over both transports.
- Protocol: send `zINSTREAM\0`, then stream the file as chunks of
  `[uint32 big-endian length][data]`, terminate with a `[uint32 0]` chunk, then
  read the response.
- Response parsing: `stream: OK` → `Clean=true`; `stream: <SIG> FOUND` →
  `Clean=false, Signature=<SIG>`; a response containing `ERROR` → return an error.
- A deadline derived from `ctx`/`timeout` is applied to the connection.

## 2. AV in the handler pipeline (`handler.go`)

`HandlerConfig` gains `AVScanner AVScanner` (optional; `nil` disables scanning).

In `ServeHTTP`, after `downloadToTemp` and before `Cache.Put`:

- `AVScanner == nil` → behave as today (`scanClean=true`).
- Scanner error → **fail-closed**: `503` with reason `av_scan_error`.
- Infected → `403` with `reason: "malware_found"`, `blocked_by: ["malware_scanner"]`,
  and a `signature` field. **The artifact is NOT cached** — we do not persist
  malware to disk; a repeat request re-downloads and re-scans (clamd is fast).
- Clean → `Cache.Put(..., scanClean=true, ...)` as today.

Pipeline order: cache → SC filter (24h) → CVE → **download → AV** → cache + serve.

## 3. Router multiplexer (`mux.go`)

New `proxy.Mux` (an `http.Handler`) holding `map[string]*Handler` keyed by prefix
(`pypi` / `npm` / `maven`):

- `/health` is served at the Mux level.
- For a request, it strips the matched prefix (`/npm/foo` → `/foo`), rewrites
  `r.URL.Path` (and `RawPath` so `RequestURI()` reflects the stripped path), then
  delegates to the matching `*Handler`.
- Because the prefix is stripped, the existing PyPI adapter sees exactly
  `/packages/...` and `/simple/...` as before — its code and tests are unchanged.
- Unknown prefix → `404`.

Each `*Handler` gets its own `Adapter` and `Upstream`, but shares the same `Cache`,
`Filter`, `CVEScanner`, `Policy`, and `AVScanner` instances.

## 4. npm adapter

- **Upstream:** `https://registry.npmjs.org`.
- **NormalizeRequest:** intercept tarballs — path contains `/-/` and ends in `.tgz`.
  Package name = path segment(s) before `/-/` (including a `@scope/pkg` scope);
  version = parsed from the filename `<unscoped-name>-<version>.tgz`. Everything
  else (metadata document `/<pkg>`) is proxied transparently.
- **FetchMetadata:** `GET upstream/<pkg>` → JSON. `time[version]` (ISO-8601) →
  `PublishedAt`; license from `versions[version].license`; `dist.shasum` (SHA1) →
  `Checksum`.
- **UpstreamURL:** `upstream + RequestURI`.

## 5. Maven adapter

- **Upstream:** `https://repo1.maven.org/maven2`.
- **NormalizeRequest:** intercept paths ending in `.jar` / `.war` / `.aar`. Parse
  `/<group/as/path>/<artifact>/<version>/<file>` → `Name = "group:artifact"`,
  `Version` from the second-to-last path segment. Sidecar files (`.pom`, `.sha1`,
  `.md5`, `.asc`) are proxied transparently.
- **FetchMetadata:** a **HEAD** request to the artifact URL → `Last-Modified`
  header → `PublishedAt`. `Checksum` is left empty (the pipeline does not require
  it; fetching the `.sha1` sidecar would be an extra request). A missing/unparseable
  `Last-Modified` yields a zero `PublishedAt` (the SC filter treats it as "old");
  this rare edge is logged at warn level.
- OSV ecosystem already maps `maven → Maven`; `Name = group:artifact` is compatible.

## 6. Configuration

`config.go` + `config.yaml`:

```yaml
clamav:
  enabled: true
  address: "unix:///var/run/clamav/clamd.sock"
  timeout_seconds: 30
registries:
  npm:   { upstream: "https://registry.npmjs.org", enabled: true }
  maven: { upstream: "https://repo1.maven.org/maven2", enabled: true }
```

New type:

```go
type ClamAVConfig struct {
    Enabled        bool   `mapstructure:"enabled"`
    Address        string `mapstructure:"address"`
    TimeoutSeconds int    `mapstructure:"timeout_seconds"`
}
```

`Config` gains `ClamAV ClamAVConfig`. The AV scanner is built in `main.go` only
when `clamav.enabled`. The per-profile `MalwareBlock` flag controls whether the
`AVScanner` is attached to the handlers.

## 7. main.go

For each enabled registry, build its adapter + upstream; build one shared ClamAV
scanner (if enabled); construct a `proxy.Mux` mapping prefix → handler. The server
listens on a single port.

## 8. Testing (TDD)

- **clamav_test.go:** TCP mock clamd (responds OK / EICAR-FOUND / ERROR); table:
  clean, infected+signature, protocol error, timeout.
- **npm_test.go / maven_test.go:** `httptest` + path-parse tables (including scoped
  npm names), FetchMetadata (mock JSON / `Last-Modified`).
- **mux_test.go:** prefix routing, prefix stripping, 404, `/health`.
- **handler_test.go:** AV block (403 `malware_found`), fail-closed on AV error
  (503), no AVScanner → pass-through.
- **integration/phase3_test.go** (`//go:build integration`): mock clamd + mock npm
  + mock maven; scenarios: malware blocked, clean npm passes, Maven 24h via
  `Last-Modified`.

## 9. Ancillary

- **README:** update to reflect that clients now use `/pypi/...`, `/npm/...`,
  `/maven/...` prefixes, plus a note on the malware block response (403
  `malware_found`). Tracked as its own task in the plan.
- **Dockerfile:** verify the binary can reach the socket (the volume is already
  mounted in compose); likely no change needed.

## Trade-offs (decided)

- **Malware is not cached** to disk (security over repeat-request speed).
- **Maven Checksum is empty** (HEAD does not return a SHA conveniently; the `.sha1`
  sidecar would be an extra request).
- **Prefix routing changes the URLs** documented in the current README → README is
  updated within this phase.
