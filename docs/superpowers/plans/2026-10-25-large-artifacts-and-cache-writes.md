# Large Artifacts & Atomic Cache Writes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Large artifacts (multi-GB wheels, CUDA image layers) and slow cold Docker pulls go through the proxy, and concurrent cold requests can no longer corrupt a served cache file.

**Architecture:** Replace total-request timeouts with *progress* timeouts: an idle-timeout `RoundTripper` on the upstream chain (no bytes for 60 s → abort), and per-chunk write deadlines when serving to clients. Drop the main server's `ReadTimeout`/`WriteTimeout` (both kill long gated requests) in favour of `ReadHeaderTimeout`/`IdleTimeout`. `LocalCache.Put` writes a temp file in the destination directory and renames it into place. Download/layer temp files move from the container's `/tmp` to `<cache.local.path>/tmp`.

**Tech Stack:** Go (toolchain go1.26.10), net/http, `http.ResponseController`, zerolog, golangci-lint v2.

**Spec:** `docs/superpowers/specs/2026-10-25-production-readiness-audit.md` — P0 #1, P0 #2, P1 #8 (and the `Content-Length` part of P2 #13, which makes truncation detectable).

## Global Constraints

- Upstream idle timeout: **60 s** without a byte (headers or body) aborts the request. Constant `httpx.DefaultUpstreamIdleTimeout = 60 * time.Second`.
- Client write progress: each chunk written to a client must complete within **60 s**. Constant `httpx.DefaultWriteIdleTimeout = 60 * time.Second`. Chunk size 256 KiB.
- Main server: `ReadHeaderTimeout: 10s`, `IdleTimeout: 120s`, **no** `ReadTimeout`, **no** `WriteTimeout`. (In Go, an expired `ReadTimeout` also cancels a running handler's request context through the background read — that is why the SSE handler clears it today.) Metrics server unchanged.
- HTTP clients: `adapter` keeps `Timeout: 30s` (metadata documents, bounded). `download` and `docker` get **no** `Timeout`; the idle timeout bounds them.
- Temp dir: `<cache.local.path>/tmp`, created at startup; leftover `jo-ei-*` files in it are removed at startup. Handlers take it via config; `""` keeps `os.TempDir()` (tests, other callers).
- No new config keys, no new dependencies, no API/console changes.
- OWNER RULE: every Go test run in a container: `MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD":/src -v jo-ei-gomod:/go/pkg/mod -v jo-ei-gobuild:/root/.cache/go-build -w /src golang:1.26.10 go test -race <pkgs>`.
- `golangci-lint run ./...` → `0 issues.` before every commit.
- Branch `fix/large-artifacts-and-cache-writes`, stacked on `refactor/split-main` (PR #105); PR base is `refactor/split-main` until #105 merges, then retarget `main`.
- CHANGELOG `Unreleased` → `### Fixed` entries (Task 6).

## Review Focus

1. **Slow but steady upstream** — a 2 GB body arriving over 5 minutes must succeed (only *silence* aborts); pinned by Task 1 `TestIdleTimeout_SlowSteadyBodySucceeds`.
2. **Reader of an old cache file during re-Put** — must still read the complete old bytes; pinned by Task 3 `TestPut_ConcurrentReaderSeesCompleteFile`.
3. **Crash mid-download leaves temp files** — the next start cleans `<cache>/tmp`; pinned by Task 5 `TestPrepareTempDir_RemovesLeftovers`.
4. **Client that stops reading** — the serving goroutine must not hang forever; pinned by Task 2 `TestCopyWithWriteDeadline_ArmsDeadlinePerChunk`.
5. **Context cancellation still propagates** — a client disconnect during download aborts the upstream fetch (idle wrapper must derive from the request context, not replace it); pinned by Task 1 `TestIdleTimeout_ParentCancelAborts`.

---

### Task 1: Idle-timeout transport; no total timeout on download clients

**Files:**
- Create: `internal/httpx/idletimeout.go`, `internal/httpx/idletimeout_test.go`
- Modify: `cmd/jo-ei/upstream.go`

**Interfaces:**
- Produces:
  ```go
  const DefaultUpstreamIdleTimeout = 60 * time.Second
  // NewIdleTimeout aborts a request when no progress is seen for idle: no
  // response headers within idle of sending, or no body bytes read within idle
  // of the previous read. The request context is derived from the caller's, so
  // caller cancellation still aborts. The error surfaced is context.DeadlineExceeded-wrapped
  // ("upstream idle for 60s").
  func NewIdleTimeout(next http.RoundTripper, idle time.Duration) http.RoundTripper
  ```
  Implementation shape: `context.WithCancelCause` on `req.Context()`, a `time.AfterFunc(idle, cancel(errIdle))` reset on each body `Read` that returns n>0 and stopped/cancelled on `Close` or EOF.
- `buildUpstream`: wrap the chain — `NewIdleTimeout(cb, DefaultUpstreamIdleTimeout)` inside `mx.WrapTransport` (metrics observe idle aborts). `download` and `docker` clients drop `Timeout`; `adapter` keeps 30 s.

- [ ] **Step 1: Write failing tests** (httptest servers):
  - `TestIdleTimeout_NoHeadersAborts`: handler sleeps 300 ms before writing; idle 100 ms → `RoundTrip` error, `errors.Is(err, context.DeadlineExceeded)`.
  - `TestIdleTimeout_StalledBodyAborts`: handler writes+flushes 1 byte then sleeps 300 ms; idle 100 ms → `io.ReadAll(resp.Body)` errors.
  - `TestIdleTimeout_SlowSteadyBodySucceeds`: handler writes 10 chunks, flushing, 50 ms apart (500 ms total); idle 100 ms → `io.ReadAll` returns all 10 chunks, no error.
  - `TestIdleTimeout_ParentCancelAborts`: handler blocks until request ctx done; caller cancels its ctx after 50 ms with idle 10 s → error within 1 s, `errors.Is(err, context.Canceled)`.
  - `TestIdleTimeout_CloseStopsTimer`: read full fast body, `Close`, sleep 2×idle → no panic/leak (goleak not available: assert via `runtime.NumGoroutine()` returning to baseline ±2 within 1 s).
- [ ] **Step 2:** Run `go test -race ./internal/httpx/` in the container. Expected: FAIL, `undefined: NewIdleTimeout`.
- [ ] **Step 3:** Implement; wire into `buildUpstream`.
- [ ] **Step 4:** Container `go test -race ./internal/httpx/ ./cmd/jo-ei/` → PASS; lint `0 issues.`
- [ ] **Step 5: Commit** — `fix(upstream): bound downloads by idle time, not total time`.

### Task 2: Progress-bounded serving to clients; server timeouts

**Files:**
- Create: `internal/httpx/copy.go`, `internal/httpx/copy_test.go`
- Modify: `internal/proxy/handler.go` (`serveFromCache`, `proxyTransparent`), `internal/proxy/metadata.go:340` (oversized stream), `internal/proxy/dockerproxy/handler.go` (`serveManifest`, `serveBlob`), `cmd/jo-ei/serve.go` (`bindServers`), `cmd/jo-ei/serve_test.go`

**Interfaces:**
- Produces:
  ```go
  const DefaultWriteIdleTimeout = 60 * time.Second
  // CopyWithWriteDeadline copies src to w in 256 KiB chunks, arming a write
  // deadline of idle before each chunk via http.ResponseController. A writer
  // without deadline support (ErrNotSupported) is copied without deadlines.
  // Clears the deadline before returning.
  func CopyWithWriteDeadline(w http.ResponseWriter, src io.Reader, idle time.Duration) (int64, error)
  ```
- `serveFromCache` and Docker `serveBlob`: `f.Stat()` → set `Content-Length` before `WriteHeader`; copy via `CopyWithWriteDeadline`. `proxyTransparent`, metadata oversized stream, `serveManifest`: copy via `CopyWithWriteDeadline` (Content-Length passthrough unchanged).
- `bindServers` main server: per Global Constraints.

- [ ] **Step 1: Write failing tests:**
  - `TestCopyWithWriteDeadline_CopiesAll`: 1 MiB + 7 bytes through `httptest.NewRecorder()` (no deadline support) → body equals source, n correct.
  - `TestCopyWithWriteDeadline_ArmsDeadlinePerChunk`: fake `ResponseWriter` implementing `SetWriteDeadline(time.Time) error` recording calls; 600 KiB source, idle 5 s → ≥3 non-zero deadlines each within `[now, now+5s+slack]`, last call is the zero `time.Time{}`.
  - `TestServeFromCache_SetsContentLength` (package `proxy`, internal test): cache entry file of 1234 bytes → recorder `Content-Length: 1234`.
  - `TestBindServers_MainServerTimeouts` (cmd): `bindServers` on `127.0.0.1:0` (metrics disabled) → main `srv.ReadTimeout == 0`, `WriteTimeout == 0`, `ReadHeaderTimeout == 10s`, `IdleTimeout == 120s`.
- [ ] **Step 2:** Container tests for `./internal/httpx/ ./internal/proxy/... ./cmd/jo-ei/` → FAIL on the new tests.
- [ ] **Step 3:** Implement and switch the five copy sites; set server timeouts.
- [ ] **Step 4:** Container tests → PASS; lint `0 issues.`
- [ ] **Step 5: Commit** — `fix(server): stop cutting long gated requests; bound client writes by progress`.

### Task 3: Atomic `LocalCache.Put`

**Files:**
- Modify: `internal/cache/local.go` (`Put`)
- Test: `internal/cache/local_test.go`

**Interfaces:**
- `Put` signature unchanged. Body: `os.CreateTemp(filepath.Dir(destPath), ".put-*")` → copy → `Sync()` → `Close()` → `os.Rename(tmp, destPath)`; on any error remove the temp file. Index insert after the rename, as now.

- [ ] **Step 1: Write failing tests:**
  - `TestPut_ConcurrentReaderSeesCompleteFile`: `Put` ref with content A (1 MiB of `'a'`); open `entry.ArtifactPath` for reading; `Put` the same ref with content B (2 MiB of `'b'`); read the already-open handle to EOF → exactly 1 MiB of `'a'`. A fresh `Get`+open reads 2 MiB of `'b'`.
  - `TestPut_LeavesNoTempFiles`: after two `Put`s, walking `<root>/artifacts` finds no name starting with `.put-`.
  - `TestPut_FailedCopyKeepsOldEntry`: `Put` A; then `Put` with a `tmpPath` that does not exist → error; `Get` still returns the entry and the file still reads as A.
- [ ] **Step 2:** Container `go test -race ./internal/cache/` → `TestPut_ConcurrentReaderSeesCompleteFile` FAILS (truncated read).
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Container tests → PASS; lint `0 issues.`
- [ ] **Step 5: Commit** — `fix(cache): write cache entries atomically via rename`.

### Task 4: Temp files in a configurable directory

**Files:**
- Modify: `internal/proxy/handler.go` (`HandlerConfig.TempDir`, `tryDownload`), `internal/proxy/dockerproxy/handler.go` (`HandlerDeps.TempDir` → `gateDeps`), `internal/proxy/dockerproxy/gate.go` (`scanLayer`, `cacheVerdict`)
- Test: `internal/proxy/handler_test.go` (or a new internal test file), `internal/proxy/dockerproxy/gate_test.go`

**Interfaces:**
- Produces: `proxy.HandlerConfig.TempDir string` and `dockerproxy.HandlerDeps.TempDir string` — directory for download/layer/manifest temp files; `""` = `os.TempDir()`. All three `os.CreateTemp("", …)` calls use it.

- [ ] **Step 1: Write failing tests:**
  - `TestTryDownload_UsesTempDir` (package `proxy`): handler with `TempDir: t.TempDir()`, httptest upstream returning 200 → `filepath.Dir(tmpPath) == TempDir`.
  - `TestScanLayer_UsesTempDir` (package `dockerproxy`): gate with a temp dir and a recording AV fake capturing the scanned path → `filepath.Dir(path) == TempDir`.
- [ ] **Step 2:** Container tests → FAIL (`unknown field TempDir`).
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Container tests for `./internal/proxy/...` → PASS; lint `0 issues.`
- [ ] **Step 5: Commit** — `fix(proxy): keep download temp files in a configurable directory`.

### Task 5: Wire the cache temp dir at startup

**Files:**
- Modify: `cmd/jo-ei/state.go` (create + clean temp dir; expose it on `state`), `cmd/jo-ei/routes.go` (`sharedDeps.tempDir` → `buildHandler`, Docker `TempDir`)
- Test: `cmd/jo-ei/state_test.go`

**Interfaces:**
- Produces:
  ```go
  // prepareTempDir creates dir (0o755) and removes leftover "jo-ei-*" entries
  // from a previous run. Other files are left alone.
  func prepareTempDir(dir string) error
  ```
  `state.tempDir = filepath.Join(cfg.Cache.Local.Path, "tmp")`, prepared in `openState` right after the cache opens (error: `"cache temp dir %q: %w"`).

- [ ] **Step 1: Write failing tests:**
  - `TestPrepareTempDir_CreatesDir`: non-existent `t.TempDir()/x/tmp` → exists afterwards.
  - `TestPrepareTempDir_RemovesLeftovers`: dir containing `jo-ei-artifact-123`, `jo-ei-layer-9`, `keep.txt` → only `keep.txt` remains.
- [ ] **Step 2:** Container `go test -race ./cmd/jo-ei/` → FAIL, `undefined: prepareTempDir`.
- [ ] **Step 3:** Implement and wire.
- [ ] **Step 4:** Container tests → PASS; lint `0 issues.`
- [ ] **Step 5: Commit** — `fix(cmd): put proxy temp files under the cache volume`.

### Task 6: Docs, changelog, full verification, PR

**Files:**
- Modify: `CHANGELOG.md` (`Unreleased` → `### Fixed`), `docs/superpowers/specs/2026-10-25-production-readiness-audit.md` (mark P0 #1, #2, P1 #8 as fixed in this PR)

- [ ] **Step 1:** CHANGELOG entries in the 0.1.0 bold-lead style:
  - **Large artifacts and cold Docker pulls no longer time out.** Upstream fetches are bounded by 60 s of silence instead of a 60/120 s total, and the server no longer cuts gated requests at 120 s.
  - **Concurrent first requests for one artifact can no longer corrupt the served file.** Cache entries are written to a temporary file and renamed into place; cached artifacts are served with `Content-Length`.
  - **Download temp files live under the cache volume** (`<cache.local.path>/tmp`) instead of the container's root filesystem; leftovers are removed at startup.
- [ ] **Step 2:** Full suite: container `go test -race ./...` → all `ok`; `golangci-lint run ./...` → `0 issues.`
- [ ] **Step 3: Manual check** — build the image; run with a pypi-only config and `max_size_gb: 20`; `pip download --no-deps --index-url http://localhost:18080/pypi/simple torch` (≈ 900 MB+ wheel, cold) → completes and the log shows one PASS outcome for it; `ls` of the cache volume `tmp/` is empty afterwards. Known limitation to note in the PR, not fix: a client with a short read timeout (pip's default 15 s socket timeout) still waits silently while the proxy downloads and scans; `pip --timeout 600` is needed for multi-GB cold artifacts.
- [ ] **Step 4: Commit** — `docs: changelog for large-artifact and cache-write fixes`.
- [ ] **Step 5:** Push; `gh pr create --base refactor/split-main` titled `fix: large artifacts, atomic cache writes, cache-volume temp dir`; body notes the stack on #105 and the pip timeout limitation.
