# P2 Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the audit's P2 items that matter for the first production release.

**Architecture:** Small, independent fixes: security headers on the console and API; a size cap for package artifacts; WAL and a busy timeout for the cache index (and busy timeout first for the state DB); a startup warning when Docker is enabled without an image scanner; a pinned Go builder image; and a Docker manifest gate that answers `503` + `Retry-After` instead of letting containerd's 30 s header timeout cut a long first scan.

**Tech Stack:** Go (toolchain go1.26.10).

**Spec:** `docs/superpowers/specs/2026-10-25-production-readiness-audit.md` — P2 #11, #14, #15, #16, #17, #19 (and the deferred busy_timeout ordering). Owner: "добьём P2" (2026-10-25).

## Global Constraints

- **Headers** (console shell, `/api/`, favicon): `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. Registry traffic is untouched.
- **Artifact cap:** `server.max_artifact_mb`, default **2048** (matches the shipped ClamAV stream limit), `0` = unlimited. Over the cap: no cache write, `403` with reason `artifact_too_large`, telemetry `ERROR` / gate `cache` / reason `artifact_too_large`. Checked against `Content-Length` before reading and enforced while reading.
- **SQLite:** `PRAGMA busy_timeout=5000` runs before `journal_mode=WAL` in `internal/storage`; the cache index applies `busy_timeout=5000` and `journal_mode=WAL` too.
- **Docker without scanner:** `registries.docker.enabled: true` with `image_scan.enabled: false` logs a startup warning `docker registry enabled but image_scan is disabled; /v2/ is not served`.
- **Builder:** `Dockerfile` uses `golang:1.26.10-alpine` (= go.mod toolchain). Distroless stays on its rolling tag (security updates); Dependabot already watches the Dockerfile.
- **Docker client wait:** `image_scan.client_wait_seconds`, default **25** (under containerd's 30 s), `0` = wait for the verdict. When the gate has not answered by then: `503` `TOOMANYREQUESTS`-style envelope with code `UNAVAILABLE`, message `image scan in progress; retry shortly`, `Retry-After: 30`; the flight keeps running and caches the verdict; telemetry `ERROR` / gate `image_scan` / reason `scan_in_progress`.
- Tests in a container; lint `0 issues.`
- Branch `fix/p2-hardening`, stacked on `chore/static-analysis` (PR #112).

## Review Focus

1. **CSP breaks the console** — every asset the shell loads must be allowed; pinned by `TestConsoleSecurityHeaders` + manual load of `/console/` by the owner.
2. **Artifact without Content-Length** — cap enforced while streaming; pinned by `TestHandler_ArtifactOverCapStreamed`.
3. **Retry after `scan_in_progress`** — served from the finished flight; pinned by `TestHandlerSlowGateAnswersRetryLater`.
4. **Cap 0** — unlimited; pinned by `TestHandler_ArtifactCapZeroUnlimited`.
5. **Registry traffic carries no CSP** — pinned by `TestConsoleSecurityHeaders`.

---

### Task 1: Console/API security headers
Files: `cmd/jo-ei/console.go` (wrap `/favicon.ico`, `/console/`, `/api/` with `securityHeaders`), `cmd/jo-ei/console_test.go`.
- [ ] `TestConsoleSecurityHeaders`: root handler built for a test; `/console/` and `/api/health…` (any `/api/` path) carry the four headers; a registry path (`/pypi/simple/x/`) does not carry CSP.
- [ ] Implement; commit `feat(console): security headers on the console and API`.

### Task 2: Package artifact size cap
Files: `internal/config/config.go` (+ default), `internal/proxy/handler.go` (`HandlerConfig.MaxArtifactBytes`, `tryDownload`), `cmd/jo-ei/routes.go`, `config.yaml`, tests in `internal/proxy/handler_test.go`.
- [ ] `TestHandler_ArtifactOverCapByContentLength` (Content-Length 2 MiB, cap 1 MiB → 403 `artifact_too_large`, upstream body not fully read is fine), `TestHandler_ArtifactOverCapStreamed` (chunked 2 MiB, cap 1 MiB → 403), `TestHandler_ArtifactCapZeroUnlimited`.
- [ ] Implement (sentinel `errArtifactTooLarge` from `tryDownload`, not retried on other mirrors); commit `feat(proxy): cap package artifact size`.

### Task 3: SQLite pragmas
Files: `internal/storage/storage.go`, `internal/cache/index.go` (+ tests).
- [ ] `TestNewIndex_UsesWAL` (`PRAGMA journal_mode` → `wal`); storage pragma order covered by inspection + existing tests.
- [ ] Commit `fix(storage): busy timeout first; WAL for the cache index`.

### Task 4: Docker-without-scanner warning, pinned builder
Files: `cmd/jo-ei/routes.go` (warn), `cmd/jo-ei/routes_test.go`, `Dockerfile`.
- [ ] `TestBuildProxyRoutes_WarnsDockerWithoutImageScan` (log buffer contains the warning; `v2` absent).
- [ ] Commit `fix: warn when docker is enabled without image scan; pin Go builder`.

### Task 5: Docker client wait
Files: `internal/config/config.go` (+ default), `internal/proxy/dockerproxy/handler.go` (`HandlerDeps.ClientWait`, `serveManifest`), `cmd/jo-ei/routes.go`, `config.yaml`, tests.
- [ ] `TestHandlerSlowGateAnswersRetryLater`: gate whose scanner sleeps 300 ms, ClientWait 50 ms → first request 503 with `Retry-After`; after the flight finishes, a second request → 200.
- [ ] Commit `fix(docker): answer a long first scan with 503 Retry-After`.

### Task 6: Docs, full suite, review, PR
- [ ] CHANGELOG, README/docs, audit marks; full suite + lint; final review; PR `--base chore/static-analysis`.
