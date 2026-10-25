# Split `cmd/jo-ei/main.go` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Break the 725-line `cmd/jo-ei/main.go` (a ~420-line `run()` with 10+ `defer`s) into focused files with no behaviour change.

**Architecture:** A small `app` lifecycle type owns every closable resource and releases them in reverse order, replacing the defer chain. `run()` becomes a short sequence: load config → logging → state → upstream clients → scanners → routes/console → bind → serve. Each stage moves into its own file inside `package main`; nothing leaves the package.

**Tech Stack:** Go (toolchain go1.26.10), cobra, zerolog, golangci-lint v2.

**Spec:** `docs/superpowers/specs/2026-10-25-production-readiness-audit.md` — section "`main.go` split".

## Global Constraints

- Behaviour-preserving: same startup log lines and fields, same error messages and wrapping (`"metrics.listen %s: %w"`, `"server.listen %s: %w"`, `"upstream TLS trust: %w"`, `"console users: %w"`, `"console auth: %w"`, `"server.trusted_proxies: %w"`, `"active_profile %q not found in policy.profiles"`, `"no registries enabled; …"`), same order of side effects (DB opened before settings, registries overlay applied before cache/handlers, initial admin created before JWT secret resolution, every listener bound before any serves).
- Existing test names and the helper names they call stay: `run`, `buildHandlers`, `sharedDeps`, `buildTelemetryStore`, `applyStoredRegistries`, `registryInfo`, `serveAll`, `boundServer`, `serveListener`, `logWriter`, `ensureInitialAdmin`, `resolveJWTSecret`, `authTTLs`.
- No new dependencies. All new code is in `package main` under `cmd/jo-ei/`.
- OWNER RULE: every Go test run happens in a container, never natively:
  `docker run --rm -v "$PWD":/src -w /src golang:1.26.10 go test -race ./cmd/jo-ei/...`
- Lint before every commit: `golangci-lint run ./...` → `0 issues.`
- Work on branch `refactor/split-main` off `main`; PR into `main`.

## Review Focus

1. **Close order on startup failure** — a failure halfway through `run()` (e.g. metrics port in use) must still close the DB, cache and store that were already opened; pinned by Task 2's `TestApp_CloseRunsInReverseOrder` and the existing `TestRunProxy_MetricsPortInUse`.
2. **Health monitor still sees raw AV scanners** — the `scanner.Prober` type assertion must run on unwrapped scanners, not the metrics wrappers; pinned by existing `TestRunProxy_AVProbeStillRegistered`.
3. **Docker-only deployments** — `registryCount` must still count `v2` and subtract the `yarn` alias; pinned by Task 5's `TestRegistryCount`.
4. **Close errors** — one closer failing must not stop the remaining closers; pinned by Task 2's `TestApp_CloseContinuesAfterError`.
5. **CA file failure still stops startup before listening** — pinned by existing `TestRunProxy_FailsFastOnUnusableCAFile`.

---

### Task 1: Branch, baseline, move settings adapters

**Files:**
- Create: `cmd/jo-ei/settings_adapters.go`
- Modify: `cmd/jo-ei/main.go` (remove the moved code)
- Add to commit: `docs/superpowers/specs/2026-10-25-production-readiness-audit.md`, this plan

**Interfaces:**
- Produces (unchanged signatures, moved verbatim): `policySettingsStore`, `registrySettingsStore`, `applyStoredRegistries(cfg *config.Config, st *settings.Store) error`, `registryInfo(cfg *config.Config) []console.RegistryInfo`.

- [ ] **Step 1:** `git switch -c refactor/split-main`
- [ ] **Step 2: Baseline** — run the container test command and `golangci-lint run ./...`. Expected: all PASS, `0 issues.` Record the `cmd/jo-ei` test count from `go test -v` output for later comparison.
- [ ] **Step 3:** Move `policySettingsStore`, `registrySettingsStore` (with their methods), `applyStoredRegistries`, `registryInfo` into `settings_adapters.go` verbatim with their doc comments.
- [ ] **Step 4:** Tests + lint as in Step 2. Expected: same PASS count, `0 issues.`
- [ ] **Step 5: Commit** — `refactor(cmd): move settings-store adapters out of main.go` (include the audit doc and this plan as `docs:` content in the same commit or a preceding `docs:` commit).

### Task 2: `app` lifecycle replaces the defer chain

**Files:**
- Create: `cmd/jo-ei/app.go`, `cmd/jo-ei/app_test.go`
- Modify: `cmd/jo-ei/main.go` (`run`)

**Interfaces:**
- Produces:
  ```go
  // app owns the resources run opens and releases them in reverse order.
  type app struct{ closers []func() error }
  func (a *app) onClose(fn func() error)
  func (a *app) close() // LIFO; runs every closer even if one errors; errors ignored (as the current defers do)
  ```

- [ ] **Step 1: Write the failing tests** in `app_test.go`:
  - `TestApp_CloseRunsInReverseOrder`: register closers appending `"a"`, `"b"`, `"c"` to a slice; after `close()` the slice equals `[]string{"c","b","a"}`.
  - `TestApp_CloseContinuesAfterError`: closers `"a"`, then one returning `errors.New("boom")`, then `"c"`; after `close()` the slice equals `[]string{"c","a"}`.
  - `TestApp_CloseTwiceIsNoop`: a closer counting calls; `close()` twice → count is 1.
- [ ] **Step 2:** Run container tests. Expected: FAIL, `undefined: app`.
- [ ] **Step 3:** Implement `app` in `app.go`. In `run()`, create `a := &app{}` right after `config.Load`, `defer a.close()`, and replace each resource `defer` (log file, DB, cache, telemetry store, OSV scanner, health monitor) with `a.onClose(...)` at the same point. `healthMon.Close` and `osvScanner.Close` keep their current semantics. Listener cleanup (`servers` loop) stays in `run` for now (moves in Task 6).
- [ ] **Step 4:** Container tests + lint. Expected: PASS (old + 3 new), `0 issues.`
- [ ] **Step 5: Commit** — `refactor(cmd): own run's resources in an app closer stack`.

### Task 3: Logging setup and upstream clients

**Files:**
- Modify: `cmd/jo-ei/logging.go`, `cmd/jo-ei/main.go`
- Create: `cmd/jo-ei/upstream.go`

**Interfaces:**
- Produces:
  ```go
  // logging.go — builds the base logger and the "server" component logger;
  // registers the log file closer on a. Warns (via serverLog) on an unknown level.
  func setupLogging(a *app, cfg config.LoggingConfig) (base, serverLog zerolog.Logger, err error)

  // upstream.go
  type upstreamClients struct {
      breaker  *httpx.CircuitBreaker // also the upstream.ThrottleLookup
      adapter  *http.Client          // 30s
      download *http.Client          // 60s
      docker   *http.Client          // 120s
  }
  func buildUpstream(cfg *config.Config, mx *metrics.Metrics, serverLog zerolog.Logger) (upstreamClients, error)
  ```
  `buildUpstream` owns: the `maxConc`/`rate` defaults, `httpx.RootPool` (+ its info log and `"upstream TLS trust: %w"` error), the breaker→rate→concurrency→transport chain, `metrics.UpstreamHosts`, `mx.WrapTransport`, `mx.RegisterCircuitBreaker`. The constants `upstreamRetryBaseDelay`/`upstreamRetryMaxDelay` move with it. Timeouts stay exactly 30/60/120 s (changing them is PR 2).

- [ ] **Step 1:** Extract `setupLogging`; `run` calls it. Container tests + lint → PASS.
- [ ] **Step 2:** Extract `buildUpstream`; `run` fills `sharedDeps.adapterClient/downloadClient/throttles` and the Docker `HTTPClient`/`Throttles` from it. Container tests + lint → PASS (`TestRunProxy_FailsFastOnUnusableCAFile` covers the error path).
- [ ] **Step 3: Commit** — `refactor(cmd): extract logging setup and upstream client wiring`.

### Task 4: Scanners and health monitor

**Files:**
- Create: `cmd/jo-ei/scanners.go`
- Modify: `cmd/jo-ei/main.go`

**Interfaces:**
- Produces:
  ```go
  type scanners struct {
      cve         gate.CVEScanner              // nil when cve.enabled is false
      av          gate.AVScanner               // limited multi-scanner; nil when not attached
      trivy       *dockerproxy.TrivyScanner    // nil when image_scan disabled
      health      *health.Monitor              // started
      engineCount int
  }
  func buildScanners(a *app, cfg *config.Config, profile config.PolicyProfile, mx *metrics.Metrics, serverLog zerolog.Logger) (scanners, error)
  ```
  Owns: OSV scanner (+ closer on `a`), the `cve.enabled is false` warning, AV engines + `LimitedScanner` + `mx.SetScanConcurrencyLimit`, the "scanners configured but malware_block:false" warning, Trivy, health monitor registration (active probes on the **unwrapped** AV scanners), `healthMon.Start()` (+ closer on `a`), `mx.RegisterScannerHealth`. `defaultOSVBaseURL` and `defaultMaxConcurrentScans` move here. `run` keeps setting `shared.policy = policyRuntime` only when `cfg.CVE.Enabled` (as today).

- [ ] **Step 1:** Extract `buildScanners`; wire `run` to it.
- [ ] **Step 2:** Container tests + lint → PASS (`TestRunProxy_AVProbeStillRegistered` is the guard).
- [ ] **Step 3: Commit** — `refactor(cmd): extract scanner and health-monitor wiring`.

### Task 5: Routes and console

**Files:**
- Create: `cmd/jo-ei/routes.go`, `cmd/jo-ei/console.go`, `cmd/jo-ei/routes_test.go`
- Modify: `cmd/jo-ei/main.go`

**Interfaces:**
- Produces:
  ```go
  // routes.go — buildHandlers, buildHandler, minEnabledTTL and sharedDeps move here unchanged.
  type proxyRoutes struct {
      handlers map[string]*proxy.Handler
      raw      map[string]http.Handler
  }
  func buildProxyRoutes(cfg *config.Config, shared sharedDeps, sc scanners, up upstreamClients, policyRuntime *policy.Runtime, artifactCache cache.Cache, logger zerolog.Logger, mx *metrics.Metrics) (proxyRoutes, error) // returns the "no registries enabled" error
  func (r proxyRoutes) registryCount() int  // len(handlers) − yarn alias + v2
  func (r proxyRoutes) prefixes() []string  // keys of handlers ∪ raw, for metrics.NewRouteFunc

  // console.go — users store, ensureInitialAdmin, JWT secret, signer, TTLs,
  // client-IP resolver, sessions (+ locked warning), and the /favicon.ico,
  // /console/, /api/auth/, /api/ routes on a new root mux with "/" → proxy mux.
  type consoleDeps struct { /* exactly the values run currently passes to console.Config + auth */ }
  func buildRootHandler(d consoleDeps, proxyMux http.Handler) (http.Handler, error)
  ```
  Use the real types from the code being moved for `policyRuntime` and `artifactCache` (check `policy.NewRuntimeWithStore` and `cache.New` return types; adjust the signature to them, not the other way round).

- [ ] **Step 1: Write the failing test** `TestRegistryCount` in `routes_test.go`, table-driven over `proxyRoutes`:
  - `{pypi}` → 1; `{npm, yarn}` → 1; `{npm, yarn, maven}` + raw `{v2}` → 3; only raw `{v2}` → 1.
  And `TestPrefixes` → `{npm, yarn}` + raw `{v2}` yields exactly `npm, yarn, v2` (order-insensitive, `assert.ElementsMatch`).
- [ ] **Step 2:** Container tests. Expected: FAIL, `undefined: proxyRoutes`.
- [ ] **Step 3:** Move/implement per Interfaces; `run` uses `buildProxyRoutes`, `proxy.NewMux`, `buildRootHandler`.
- [ ] **Step 4:** Container tests + lint → PASS.
- [ ] **Step 5: Commit** — `refactor(cmd): extract proxy routing and console wiring`.

### Task 6: Listener binding; final shape of `run`

**Files:**
- Modify: `cmd/jo-ei/serve.go`, `cmd/jo-ei/serve_test.go`, `cmd/jo-ei/main.go`

**Interfaces:**
- Produces:
  ```go
  // Binds metrics (when mx != nil) then the main listener; on any bind error
  // closes what it already bound and returns the error. Registers listener
  // closers on a.
  func bindServers(a *app, cfg *config.Config, handler http.Handler, mx *metrics.Metrics) ([]boundServer, error)
  ```
  The main `http.Server` keeps `ReadTimeout`/`WriteTimeout` at 120 s (changed in PR 2); the metrics server keeps `ReadHeaderTimeout` 10 s / `WriteTimeout` 30 s.
- Removes: `serve(ctx, srv)` — only its own test used it. Rewrite `TestServe_ShutsDownOnContextCancel` against `serveListener` with a pre-bound `net.Listen("tcp", "127.0.0.1:0")`.

- [ ] **Step 1:** Rewrite the serve test against `serveListener`; container tests → PASS (still compiles while `serve` exists).
- [ ] **Step 2:** Delete `serve`; extract `bindServers`; `run` ends with the "Jōei starting" log and `serveAll`.
- [ ] **Step 3:** Check shape: `wc -l cmd/jo-ei/main.go` → under 200 lines; `run` under ~120 lines and reads as the stage sequence in Architecture.
- [ ] **Step 4:** Container tests (compare count with Task 1 baseline: baseline + 5 new tests) + lint → PASS, `0 issues.`
- [ ] **Step 5: Manual smoke** — `docker compose up --build`; `curl -s localhost:8080/health` → `{"status":"ok"}`; logs contain one `"Jōei starting"` line with the same fields as on `main`; `docker compose stop jo-ei` exits cleanly.
- [ ] **Step 6: Commit** — `refactor(cmd): extract listener binding; drop unused serve helper`.
- [ ] **Step 7:** Push, open PR into `main`: title `refactor(cmd): split main.go wiring`, body lists the new files and states "no behaviour change; production-readiness audit attached". CHANGELOG: no entry (not user-facing).
