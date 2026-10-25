# Production-readiness audit — 2026-10-25

Input for the first production release. Target deployment, as decided by the
owner: **one VM, docker compose, a reverse proxy in front, single replica**
(throughput is bound by the AV engines, so replicas are out of scope). The
audit covers code quality, the `main.go` split, production readiness for that
deployment, and a "cloud-ready" gap list that is documented but not fixed.

Priorities: **P0** — breaks real traffic, fix before the release; **P1** —
fix before the release unless consciously accepted; **P2** — polish /
next release.

## Coverage

Read in depth: `cmd/jo-ei` (wiring, serve, logging), `Dockerfile*`,
`docker-compose.yaml`, `config.yaml`, `.env.example`, `internal/proxy/handler.go`,
`internal/proxy/mux.go`, `internal/proxy/dockerproxy/{handler,gate}.go` (manifest
and layer paths), `internal/cache/local.go`, `internal/storage`,
`internal/telemetry/store.go`, the console SSE handler, auth cookie handling,
login limiter keying, upstream/OSV/Trivy HTTP clients.

Not reviewed in depth (second wave): registry adapters' parsing,
`internal/proxy/metadata.go` beyond the lint hits, console API handlers,
`internal/users` + `internal/auth/handlers.go` (reviewed task-by-task in PR #98),
`internal/metrics`, the web console.

## P0 — breaks real traffic

### 0. pip downloads bypass the proxy entirely (found 2026-10-25, during manual testing) — FIXED (`fix/pypi-index-rewrite`; e2e: pip on a network reaching only the proxy downloads and `--require-hashes`-installs six 1.16.0, PASS/CACHE recorded)
PyPI simple-index pages are proxied untouched (`proxyTransparent`), and
pypi.org's pages link every file with an **absolute** URL
(`https://files.pythonhosted.org/packages/...`). pip follows those links
straight to Fastly, so with the default `https://pypi.org` upstream no pip
download ever reaches `/pypi/packages/...`: no supply-chain, CVE or malware
gate runs, nothing is cached or recorded. Observed: `pip download torch`
against the proxy held a connection to 151.101.64.223 while the proxy's temp
dir stayed empty. The gates only work for clients that request
`/pypi/packages/...` themselves, or for an upstream mirror that emits relative
links (devpi, Nexus). npm is believed unaffected — npm ≥ 9 rewrites
`registry.npmjs.org` tarball URLs to the configured registry
(`replace-registry-host=npmjs`) — but this needs verifying, as do yarn and
pnpm, RubyGems and Go.
- Fix shape: rewrite file URLs in simple-index responses (HTML and PEP 691
  JSON) whose host is a known upstream file host to the proxy's
  `/pypi/packages/...`, keeping the `#sha256=` fragment; same treatment for
  the JSON API `urls[].url` if clients use it. Add an end-to-end test that
  drives real pip through the proxy.


### 1. Timeouts cut large artifacts and cold Docker pulls — FIXED (`fix/large-artifacts-and-cache-writes`)
- `http.Client.Timeout` covers reading the **body**. Package downloads use
  `downloadClient` with 60 s (`cmd/jo-ei/main.go`, `adapterClient`/`downloadClient`),
  Docker uses 120 s (`dockerClient`) for every blob fetch in
  `manifestGate.scanLayer`. A 1–2 GB PyTorch wheel or CUDA image layer cannot
  arrive in that window on an ordinary link → `upstream_unavailable` / `gate_error`
  on **every** attempt, since the partial download is discarded.
- The main server has `WriteTimeout: 120s`, armed when the request is read. A
  gated download is *download + CVE + AV scan + serve* inside one handler; a
  cold Docker manifest request is *fetch every layer + Trivy (up to
  `image_scan.timeout_seconds`=120) + AV every layer*. Past 120 s the client
  connection dies. For Docker the singleflight keeps running
  (`WithoutCancel`) so a retry may hit the cached verdict, but `docker pull`
  shows a failure first.
- Fix shape: per-attempt *response-header* timeout + idle-read timeout on the
  transport instead of a total `Client.Timeout`; drop the server-wide
  `WriteTimeout` for proxy routes (keep `ReadHeaderTimeout`, `IdleTimeout`) or
  extend it per request with `http.ResponseController`, as the SSE handler
  already does.

### 2. Concurrent cold requests can corrupt a served artifact — FIXED (`fix/large-artifacts-and-cache-writes`)
`LocalCache.Put` writes straight into the final path with `os.Create`
(truncate in place). Two cold requests for the same artifact (a CI fleet
resolving one lockfile) both download, both `Put`: the second `Create`
truncates the inode the first request is already streaming from
`serveFromCache` → the client receives a short/garbled body (no
`Content-Length` is sent, so nothing detects it but the package manager's
checksum). Same pattern in the Docker blob store.
- Fix: write to a temp file in the **same directory**, fsync, `os.Rename` onto
  the final path (atomic; open readers keep the old inode). Optionally coalesce
  first downloads per key with singleflight (also saves duplicate scans).

## P1 — fix before release

### 3. Graceful shutdown never completes with an open console tab — FIXED (`fix/shutdown-health-compose`)
`http.Server.Shutdown` does not cancel request contexts; the SSE handler only
exits on `r.Context().Done()`. Any open console tab holds `Shutdown` until its
30 s deadline, `run` then returns `context deadline exceeded` (exit 1).
Compose's default `stop_grace_period` is 10 s, so Docker SIGKILLs the process
first anyway — in-flight downloads are cut, nothing is drained.
- Fix: `srv.RegisterOnShutdown` (or a server `BaseContext` cancelled on
  shutdown) to end SSE streams; set `stop_grace_period` in compose above the
  drain timeout; make the drain timeout configurable.

### 4. Behind the reverse proxy, the login limiter keys every client on the proxy IP
The login limiter counts failures per IP as well as per (user, IP). With
`server.trusted_proxies` unset (the shipped default), every client is the
reverse proxy's address, so anyone hammering the login locks **all** admins
out. `trusted_proxies` is only commented out in `config.yaml`, so
`JOEI_SERVER_TRUSTED_PROXIES` cannot set it (viper only overrides keys present
in the file). Docs are silent.
- Fix: uncomment the key with an empty default, document the reverse-proxy
  setup (compose network CIDR), log a startup warning when requests arrive with
  `X-Forwarded-For` from an untrusted peer.

### 5. Compose file is a dev setup, not a production one — FIXED (`fix/shutdown-health-compose`; resource limits left to the operator, see README "Running in Production")
- No `healthcheck` for `jo-ei` (distroless has no shell/curl → needs a
  `jo-ei healthcheck` subcommand hitting `/health`).
- `/health` is liveness only; there is no readiness signal (DB writable,
  required scanners reachable). The data is already in the health monitor.
- `ports: "8080:8080"` publishes on `0.0.0.0` — clients can bypass the reverse
  proxy. Bind `127.0.0.1:8080` or keep it on the compose network only.
- No log rotation: Docker's `json-file` driver grows unbounded and fills the
  VM disk. Set `logging.options.max-size/max-file`.
- Trivy version skew: the image ships the Trivy **client 0.76.1**
  (`Dockerfile`), compose runs **server 0.71.2**. Trivy client/server must
  match. `clamav/clamav:stable` and `jo-ei:latest` are floating tags.
- No resource limits (`mem_limit`/`cpus`) — ClamAV alone needs ~1.5–3 GB.

### 6. No `.dockerignore` — FIXED (`fix/shutdown-health-compose`)
`docker build .` sends `.env` (JWT secret), `.git`, `.claude/`,
`.superpowers/` into the build context and the builder layer cache. The final
image is clean (only the binary and `config.yaml` are copied), but the secret
sits in local/CI build cache.

### 7. ClamAV size limits are invisible — FIXED (`fix/shutdown-health-compose`)
- clamd's `StreamMaxLength` (25 MB in clamd's stock config) makes INSTREAM
  answer `size limit exceeded` → `av_scan_error` → **503 fail-closed** for
  every larger artifact or layer. Needs verifying against the
  `clamav/clamav:stable` image defaults.
- clamd's `MaxFileSize`/`MaxScanSize` make content past the limit go
  **unscanned yet reported `OK`** unless `AlertExceedsMax yes` — a silent
  security gap.
- Nothing in compose or docs configures or mentions either. Ship a
  `clamd.conf` override (or env) in compose and document the trade-off.

### 8. Temp files live on the container's writable layer — FIXED (`fix/large-artifacts-and-cache-writes`; `read_only: true` still to do with #5)
`os.CreateTemp("", …)` → `/tmp` inside the container: not a volume, so 2 GB
layers land on the overlay filesystem of the VM's root disk, and `Put` then
*copies* across filesystems into the cache volume. Use a temp dir under the
cache path (same FS → `rename`, also needed for fix #2) and allow
`read_only: true` for the container.

### 9. No backup/restore story for the SQLite state
Two databases: `/var/lib/jo-ei/jo-ei.db` (users, JWT secret, policy,
registries, telemetry) and `<cache>/index.db`. Copying a WAL database while it
is being written is not safe. Provide `jo-ei backup <path>` (`VACUUM INTO`) or
document the procedure; document that the cache volume is disposable but
`index.db` must match the artifact files.

### 10. OSV scanner bypasses the shared upstream transport
`scanner.NewOSVScanner` builds `&http.Client{Timeout: 15s}` on the default
transport: it ignores `tls.ca_files`, the rate/concurrency caps and the
upstream metrics. Behind a TLS-inspecting corporate proxy the CVE gate fails
→ every non-cached request 503s. Pass the shared transport in.

## P2 — polish

18. **`npm pack <remote spec>` drops the `/npm` prefix** (npm 10.9.9, found
    2026-10-25 by e2e; first misread as "npm installs fail", corrected after
    the owner's report and a full re-check). `npm install` (`.npmrc`, `--registry`
    or env), `npm ci` with a lockfile resolved to `https://registry.npmjs.org/…`,
    and `npm exec`/`npx` all fetch tarballs through `/npm/<pkg>/-/…` and are
    gated. Only `npm pack left-pad@1.3.0` fetches
    `http://<jo-ei>/left-pad/-/left-pad-1.3.0.tgz` → `404 unknown_registry`
    (fails closed, no bypass). Untested: `replace-registry-host=never`, which
    would follow the packument's absolute registry.npmjs.org URL; yarn and pnpm.

11. **Console on the proxy listener, no security headers.** `/console/` and
    `/api/` share `:8080` with registry traffic; no CSP, `frame-ancestors`,
    `X-Content-Type-Options`. Add headers; consider an optional
    `console.listen`.
12. **Synchronous SQLite writes on one shared connection.** Every request
    writes a telemetry event, every cache hit runs `IncrementHit`; console
    `LIKE` search and the prune `DELETE` hold the same single connection. Fine
    at moderate load; worth a metric (DB wait time) before tuning.
13. **`serveFromCache` sends no `Content-Length`, `ETag`, range support,
    real `Content-Type`.** `http.ServeContent` gives these for free and lets
    clients detect truncation.
14. **No max artifact size for package ecosystems** (Docker has
    `max_layer_bytes`) — one huge artifact can fill the cache volume.
15. **Cache `index.db` has no WAL / `busy_timeout` pragmas**, unlike
    `internal/storage`.
16. **Docker silently disabled without image scan.** `registries.docker.enabled:
    true` with `image_scan.enabled: false` drops `/v2/` with no startup log
    (only a console warning on edit). Warn or fail at startup.
17. **Floating base images**: `golang:1.27-alpine` while `go.mod` pins
    `toolchain go1.26.10`; distroless by tag, not digest.

## Static analysis triage

- CI gate (`.golangci.yml`): **0 issues**.
- Extended one-off run (bodyclose, noctx, errorlint, contextcheck,
  forcetypeassert, gocritic, unparam, wastedassign, goconst, perfsprint,
  gocyclo, funlen, …): 162 hits in non-test code.
  - `noctx` 48 — all store methods call `Exec/Query` without a context. Worth
    threading `ctx` through `cache.Index`, `telemetry`, `users`, `settings`,
    `storage` so shutdown and client cancellation stop queries. Mechanical.
  - `contextcheck` 10 — false positives (`ctx := r.Context()` aliasing,
    deliberate `WithoutCancel`).
  - Real but trivial: `errorlint` `internal/scanner/icap.go:137`
    (`err != io.EOF`); `forcetypeassert` `internal/proxy/metadata.go:306`,
    `dockerproxy/gate.go:232`, `httpx/tls.go:61` (all safe by construction);
    `wastedassign` `internal/metrics/scanner.go:194`; `unparam`
    `cache/index.go:178`; `predeclared` `dockerproxy/tagindex.go:29`.
  - Noise: `goconst` 59, `perfsprint` 25.
  - Complexity: `gocyclo`/`funlen` flag `run()` in `cmd/jo-ei/main.go` and
    `proxy.Handler.ServeHTTP`.
- Proposal: add `errorlint`, `bodyclose`, `wastedassign`, `unconvert` to CI
  now; `noctx` after the context migration.

## `main.go` split

`cmd/jo-ei/main.go` is 725 lines; `run()` alone is ~420 lines with 10+ `defer`s.
Proposed, behaviour-preserving:
- `app.go` — an `app` struct owning every closable (DB, cache, store, OSV,
  health monitor) with one `Close()` in reverse order, replacing the defer
  chain; `run` becomes *load → build app → bind → serve*.
- `upstream.go` — transport chain (CA pool, limits, breaker, metrics) and the
  three HTTP clients.
- `scanners.go` — OSV, AV engines + limiter, Trivy, health monitor
  registration.
- `routes.go` — `buildHandlers`, Docker raw handler, proxy mux, root mux,
  route prefixes.
- `console.go` — users, initial admin, JWT, sessions, console config.
- `settings_adapters.go` — `policySettingsStore`, `registrySettingsStore`,
  `applyStoredRegistries`, `registryInfo`.
- Existing `serve.go`, `logging.go` absorb listener binding and logger setup.
Done as its own PR before the behavioural fixes so their diffs stay small.

## Cloud-ready gaps (document only)

Already fine: JSON logs to stdout, Prometheus on a separate port, SIGTERM
handling, nonroot distroless image, state confined to two volumes, JWT secret
auto-generated and persisted.

Gaps:
- **Env config is partial**: only keys present in `config.yaml` can be
  overridden; lists (`malware.scanners`, `registries.*.upstreams`,
  `trusted_proxies`) can't be set from env at all.
- **Config is not the source of truth**: policy and registries persist in the
  DB and override `config.yaml` after first boot — drift for GitOps-style
  deployments.
- **Single-replica state**: SQLite, local filesystem cache, and in-memory
  singleflight, circuit breaker, rate limiter, login limiter, tag index, OSV
  cache. Horizontal scaling needs a shared DB, S3 cache and shared limiter
  state.
- **No readiness endpoint** (see #5).
- **Writable root filesystem required** today (see #8).

## Suggested order

1. PR: `main.go` split (no behaviour change).
2. PR: P0 #1 timeouts + #2 atomic cache writes (+ temp dir, #8).
3. PR: shutdown (#3) + healthcheck/readiness (#5) + compose hardening (#5, #6, #7).
4. PR: reverse-proxy correctness (#4) + OSV transport (#10) + backup (#9).
5. PR: static-analysis wave (ctx threading, linter additions, trivial hits).
6. P2 items, then a second-wave review of the unreviewed packages.
