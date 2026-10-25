# Shutdown, Health & Compose Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `docker compose stop` drains cleanly, Docker knows whether Jō-ei is healthy, and the shipped compose file is safe to run on a production VM behind a reverse proxy.

**Architecture:** Close SSE streams on server shutdown (broadcaster close hook), bound the drain by a configurable timeout that force-closes stragglers instead of failing. Add `/ready` (DB + scanner health) next to `/health`, and a `jo-ei healthcheck` subcommand the distroless image can run. Harden compose: healthcheck, grace period, loopback-only port, log rotation, pinned and matched scanner images, ClamAV size limits that fail closed. Add `.dockerignore`.

**Tech Stack:** Go (toolchain go1.26.10), cobra, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-25-production-readiness-audit.md` — P1 #3, #5, #6, #7.

## Global Constraints

- Drain timeout: `server.shutdown_timeout_seconds`, default **30** (0/absent → 30); present (uncommented) in `config.yaml` so `JOEI_SERVER_SHUTDOWN_TIMEOUT_SECONDS` works. When the drain deadline passes: log warn `shutdown deadline passed; closing remaining connections`, `srv.Close()`, return **nil** (a slow client is not a process failure).
- SSE streams end on shutdown: `telemetry.Broadcaster.Close()` closes every subscriber channel and makes later `Subscribe` return an already-closed channel; registered with `srv.RegisterOnShutdown` on the main server.
- `/ready`: `200 {"status":"ready"}` when a `SELECT 1` on the main DB succeeds within 2 s **and** no enabled scanner in the health snapshot is `down`; otherwise `503 {"status":"not_ready","failing":[...]}` naming `"database"` and/or the down scanners. `unknown` does not fail readiness (osv.dev is passive and unknown until traffic). Public, outside `/api/`, like `/health`.
- `jo-ei healthcheck [--ready]`: reads `server.listen` from `--config`, GETs `http://127.0.0.1:<port>/health` (or `/ready`) with a 3 s timeout; exit 0 on 200, non-zero otherwise. A listen host of `""`, `0.0.0.0` or `::` probes `127.0.0.1`; any other host is used as-is.
- Compose (`docker-compose.yaml`):
  - jo-ei `healthcheck`: `["CMD", "/jo-ei", "--config", "/etc/jo-ei/config.yaml", "healthcheck", "--ready"]`, interval 30s, timeout 5s, retries 3, start_period 60s.
  - `stop_grace_period: 45s` (drain 30 s + margin).
  - `ports: "127.0.0.1:8080:8080"` with a comment on exposing it via the reverse proxy.
  - Log rotation on every service via an `x-logging` anchor: `json-file`, `max-size: "50m"`, `max-file: "5"`.
  - `trivy` image `aquasec/trivy:0.76.1` (= the client in the jo-ei image); `clamav/clamav:1.5`.
  - ClamAV env: `CLAMD_CONF_StreamMaxLength=2048M`, `CLAMD_CONF_MaxFileSize=2048M`, `CLAMD_CONF_MaxScanSize=4095M`, `CLAMD_CONF_AlertExceedsMax=yes` (matches `image_scan.max_layer_bytes` 2 GB; over-limit content is reported FOUND → blocked, never silently unscanned).
- `config.yaml`: clamav `timeout_seconds: 300` (a 2 GB stream cannot be scanned in 30 s).
- `.dockerignore`: `.git`, `.env`, `.claude`, `.superpowers`, `.vscode`, `*.db`, `*.exe`, `dist/`.
- Tests in a container only (`golang:1.26.10`, `-race`); `golangci-lint run ./...` → `0 issues.` before every commit.
- Branch `fix/shutdown-health-compose`, stacked on `fix/pypi-index-rewrite` (PR #107).

## Review Focus

1. **SSE + in-flight download at stop** — SSE must end at once while a download keeps draining up to the deadline; pinned by Task 1 `TestServeListener_ShutdownHooksRunAndDrain`.
2. **Client that never finishes** — stop must still complete at the deadline with exit 0; pinned by Task 1 `TestServeListener_DeadlineClosesStragglers`.
3. **Scanner down at boot** — `/ready` 503 names it; osv.dev unknown does not; pinned by Task 2 `TestReady_*`.
4. **`server.listen: "10.0.0.5:8080"`** — healthcheck must probe that host, not loopback; pinned by Task 2 `TestHealthcheckURL`.
5. **ClamAV limits really applied** — env must reach `clamd.conf`; pinned by Task 3 manual `clamconf` check.

---

### Task 1: Drain on shutdown; SSE ends

**Files:** `internal/telemetry/broadcaster.go` (+ test), `cmd/jo-ei/serve.go` (+ test), `cmd/jo-ei/main.go`, `internal/config/config.go` (`ServerConfig.ShutdownTimeoutSeconds`), `config.yaml`

**Interfaces:**
- `func (b *Broadcaster) Close()` — idempotent.
- `boundServer` gains `drain time.Duration`; `serveListener(ctx, srv, ln, drain)`; `bindServers` sets main `drain` from config (default 30 s), metrics `drain` 5 s; `run` registers `srv.RegisterOnShutdown(st.broadcaster.Close)` on the main server (expose main server from `bindServers` result: the last element).

- [ ] **Step 1: Failing tests:**
  - `TestBroadcaster_CloseEndsSubscriptions`: subscribe twice; `Close()`; both channels read closed; `Close()` again no panic; `Subscribe()` after close returns a closed channel.
  - `TestServeListener_ShutdownHooksRunAndDrain`: server with handler `/slow` sleeping 300 ms then writing "done", and `/stream` blocking on a channel closed by a `RegisterOnShutdown` hook; start both requests, cancel ctx → `/stream` returns promptly, `/slow` completes with "done", `serveListener` returns nil.
  - `TestServeListener_DeadlineClosesStragglers`: handler blocks forever ignoring ctx; drain 200 ms; cancel → `serveListener` returns nil within 1 s.
  - `TestConfig_ShutdownTimeoutDefault` (config pkg): unset → `30`.
- [ ] **Step 2:** Container tests → FAIL. **Step 3:** Implement. **Step 4:** PASS + lint. **Step 5:** Commit `fix(server): end SSE streams and bound the drain on shutdown`.

### Task 2: `/ready` and `jo-ei healthcheck`

**Files:** create `cmd/jo-ei/ready.go`, `cmd/jo-ei/ready_test.go`, `cmd/jo-ei/healthcheck.go`, `cmd/jo-ei/healthcheck_test.go`; modify `cmd/jo-ei/console.go` (register `/ready` on the root mux), `cmd/jo-ei/main.go` (add command).

**Interfaces:**
- `func readinessHandler(db *sql.DB, scanners func() []health.ScannerHealth) http.Handler`
- `func healthcheckURL(listen string, ready bool) (string, error)`; `func probe(ctx context.Context, url string) error`; cobra `healthcheck` with `--ready`.

- [ ] **Step 1: Failing tests:**
  - `TestReady_AllHealthy` → 200 `{"status":"ready"}`.
  - `TestReady_ScannerDown` (snapshot: clamav enabled down, osv.dev enabled unknown, trivy disabled down) → 503, `failing == ["clamav"]`.
  - `TestReady_DatabaseClosed` (closed `*sql.DB`) → 503, `failing` contains `"database"`.
  - `TestHealthcheckURL`: `":8080"`→`http://127.0.0.1:8080/health`; `"0.0.0.0:9000"`+ready→`…:9000/ready`; `"[::]:8080"`→`127.0.0.1`; `"10.0.0.5:8080"`→`http://10.0.0.5:8080/health`; `"bad"`→error.
  - `TestProbe`: httptest 200 → nil; 503 → error mentioning `503`.
- [ ] **Step 2–4** as usual. **Step 5:** Commit `feat(health): readiness endpoint and healthcheck command`.

### Task 3: Compose, Dockerfile context, docs

**Files:** `docker-compose.yaml`, `.dockerignore` (new), `config.yaml`, `CHANGELOG.md`, `README.md` (deployment notes), audit doc.

- [ ] **Step 1:** Apply Global Constraints to compose/config; create `.dockerignore`.
- [ ] **Step 2:** `docker compose config -q` → exit 0.
- [ ] **Step 3: Manual:** `docker compose up -d --build`; wait → `docker inspect -f '{{.State.Health.Status}}' <jo-ei>` = `healthy` once ClamAV is up; `docker compose exec clamav clamconf | grep -E 'StreamMaxLength|MaxFileSize|MaxScanSize|AlertExceedsMax'` shows the new values; `ss`/`docker port` shows `127.0.0.1:8080`; open an SSE stream (`curl -N` to `/api/events` with a session from `/api/auth/login`), then `time docker compose stop jo-ei` → under 10 s, exit code 0, log has no shutdown error. `docker compose down` (keep volumes).
- [ ] **Step 4:** CHANGELOG (`Fixed`/`Added`/`Changed`), README deployment notes, audit marks. Full suite + lint.
- [ ] **Step 5:** Commit `chore(compose): production-safe defaults`; final review; PR `--base fix/pypi-index-rewrite`.
