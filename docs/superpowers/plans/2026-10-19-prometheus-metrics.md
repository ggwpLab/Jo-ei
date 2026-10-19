# Prometheus Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose Prometheus metrics (RED for inbound HTTP, upstreams, scanners; Go runtime/process; verdicts; cache) on a dedicated `:9464` listener, plus a Grafana dashboard and alert rules.

**Architecture:** New package `internal/metrics` owns a private `prometheus.Registry` and every metric. It exposes nil-safe `Wrap*`/`Register*` methods on `*metrics.Metrics`; `cmd/jo-ei` calls them while wiring, so with metrics disabled (`mx == nil`) every wrapper returns its input unchanged. Other packages never import `client_golang`; where a measurement must happen inside them they expose an optional observer.

**Tech Stack:** Go 1.26, `github.com/prometheus/client_golang` (prometheus, promauto, promhttp, collectors, testutil), `github.com/felixge/httpsnoop`, `golang.org/x/sync/errgroup` (already a dependency), testify.

**Spec:** `docs/superpowers/specs/2026-10-19-prometheus-metrics-design.md`

## Global Constraints

- Metric prefix `jo_ei_`; base units (`_seconds`, `_bytes`); counters end `_total`.
- Only `internal/metrics` (and its tests) imports `github.com/prometheus/client_golang`.
- Never use `prometheus.DefaultRegisterer` / `MustRegister` on globals.
- Every label value comes from a closed set; unknown inputs map to `other`.
- Duration buckets: `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120`, plus `NativeHistogramBucketFactor: 1.1`.
- Config defaults: `metrics.enabled: true`, `metrics.listen: ":9464"`, `metrics.path: "/metrics"`.
- Metrics bind failure is fatal (non-zero exit naming `metrics.listen`).
- Local checks: `go test ./...`, `golangci-lint run`, `gofmt -l .` (no `-race` locally: CGO off; CI runs it). Check CRLF doesn't mask gofmt.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Streaming responses through the HTTP middleware** — SSE `/api/events` and large artifact downloads must still flush/stream; the wrapped writer must keep `http.Flusher`. Test in Task 3.
2. **Wrapping AV engines breaks health probes** — `health.Monitor` type-asserts `avScanners[i].(scanner.Prober)`; the wrapped value must not be what the monitor sees. Wiring test in Task 7.
3. **Metrics port equals proxy port / port in use** — config rejects equal listens (Task 1); bind failure returns an error from `runProxy` (Task 7).
4. **Upstream hosts outside config (Docker blob CDN redirects, IP literals)** — label `other`, never the raw host. Test in Task 4.
5. **Scrape while scanner health / cache stats error** — collectors must emit nothing for that metric rather than fail the whole scrape. Tests in Tasks 5 and 6.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/config/config.go` | `MetricsConfig`, defaults, validation |
| `internal/metrics/metrics.go` | `Metrics`, `New`, `BuildInfo`, `Handler`, buckets, shared label helpers |
| `internal/metrics/http.go` | inbound HTTP metrics, `RouteFunc`, `WrapHandler` |
| `internal/metrics/upstream.go` | outbound `RoundTripper`, error classification, circuit collector |
| `internal/metrics/scanner.go` | AV/CVE/Image wrappers, queue observer, concurrency gauge, `scanner_up` collector |
| `internal/metrics/domain.go` | verdict recorder wrapper, cache collector |
| `internal/metrics/*_test.go` | unit tests, lint test, asset drift test |
| `internal/httpx/circuitbreaker.go` | add `OpenHosts()` |
| `internal/scanner/limited.go` | add `LimitedOption`, `WithWaitObserver` |
| `cmd/jo-ei/main.go`, `cmd/jo-ei/serve.go` | wiring, second server, errgroup |
| `examples/monitoring/{prometheus.yml,alerts.yml,README.md,grafana/jo-ei-dashboard.json}` | assets |
| `docs/metrics.md`, `docs/configuration.md`, `README.md`, `CHANGELOG.md`, `config.yaml`, `docker-compose.yaml`, `Dockerfile*` | docs/deploy |

Note vs spec: the spec sketches exported sub-structs (`m.HTTP`, `m.Upstream`…). The plan uses unexported sub-structs behind nil-safe methods on `*Metrics` instead; same metrics, simpler disabled mode. The spec leaves file split to the builder.

---

### Task 1: Metrics config

**Files:**
- Modify: `internal/config/config.go` (Config struct ~line 11, `Validate`, `Load` defaults ~line 318)
- Modify: `config.yaml` (add commented block)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.MetricsConfig{Enabled bool "enabled"; Listen string "listen"; Path string "path"}`, field `Config.Metrics MetricsConfig` (`mapstructure:"metrics"`).

- [ ] **Step 1: Write failing tests**

```go
func TestLoad_MetricsDefaults(t *testing.T)        // config without metrics block → Enabled=true, Listen=":9464", Path="/metrics"
func TestLoad_MetricsEnvOverride(t *testing.T)     // t.Setenv("JOEI_METRICS_LISTEN", "127.0.0.1:9999"), JOEI_METRICS_ENABLED=false → Listen=="127.0.0.1:9999", Enabled==false
func TestValidate_MetricsListenEqualsServer(t *testing.T) // server.listen ":8080", metrics.listen ":8080", enabled → error containing "metrics.listen"
func TestValidate_MetricsPathMustStartWithSlash(t *testing.T) // path "metrics" → error containing "metrics.path"
func TestValidate_MetricsDisabledSkipsChecks(t *testing.T)    // enabled=false, listen==server.listen → nil
```

Use the existing test helpers in `config_test.go` for writing a temp config.

- [ ] **Step 2: Run** `go test ./internal/config/ -run Metrics -v` — Expected: FAIL (no `Metrics` field).

- [ ] **Step 3: Implement**: struct + `v.SetDefault("metrics.enabled", true)`, `("metrics.listen", ":9464")`, `("metrics.path", "/metrics")` in `Load`; validation in `Validate` only when `Enabled`: listen non-empty, `listen != Server.Listen`, path has prefix `/`. Add to `config.yaml`:

```yaml
# Prometheus metrics on a separate listener reachable only by monitoring.
# Do not publish this port to proxy clients. See docs/metrics.md.
metrics:
  enabled: true
  listen: ":9464"
  path: "/metrics"
```

- [ ] **Step 4: Run** `go test ./internal/config/ -v` — Expected: PASS.

- [ ] **Step 5: Commit** `feat(config): add metrics listener settings`

---

### Task 2: `internal/metrics` core — registry, runtime/process collectors, build info, handler

**Files:**
- Create: `internal/metrics/metrics.go`, `internal/metrics/metrics_test.go`
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Produces:
  - `type BuildInfo struct{ Version, Commit string }`
  - `type Metrics struct{ Registry *prometheus.Registry; /* unexported sub-structs added by later tasks */ }`
  - `func New(info BuildInfo, log zerolog.Logger) *Metrics`
  - `func (m *Metrics) Handler() http.Handler`
  - package-level `var durationBuckets = []float64{...}` and `func newDurationHistogramOpts(name, help string) prometheus.HistogramOpts` (sets buckets + `NativeHistogramBucketFactor: 1.1`, `NativeHistogramMaxBucketNumber: 100`, `NativeHistogramMinResetDuration: time.Hour`)
  - `func oneOf(v string, allowed map[string]struct{}) string` → `v` if allowed else `"other"`

- [ ] **Step 1: Add deps** `go get github.com/prometheus/client_golang@latest github.com/felixge/httpsnoop@latest` then `go mod tidy` after code exists.

- [ ] **Step 2: Write failing tests**

```go
func TestNew_RegistersRuntimeProcessAndBuildInfo(t *testing.T) {
    m := metrics.New(metrics.BuildInfo{Version: "1.2.3", Commit: "abc"}, zerolog.Nop())
    mfs, err := m.Registry.Gather()
    require.NoError(t, err)
    names := map[string]bool{}
    for _, mf := range mfs { names[mf.GetName()] = true }
    for _, n := range []string{"go_goroutines", "go_gc_duration_seconds", "jo_ei_build_info"} {
        assert.True(t, names[n], n)
    }
    // process_* only where procfs works; assert on linux only:
    if runtime.GOOS == "linux" { assert.True(t, names["process_cpu_seconds_total"]) }
}
func TestBuildInfoLabels(t *testing.T)  // testutil.GatherAndCompare with expected
    // jo_ei_build_info{commit="abc",goversion=runtime.Version(),version="1.2.3"} 1
func TestHandler_ServesOpenMetricsAndSelfMetrics(t *testing.T)
    // httptest GET → 200, body contains "jo_ei_build_info"; second GET body contains "promhttp_metric_handler_requests_total"
func TestNoDefaultRegistererPollution(t *testing.T)
    // two New() calls do not panic (duplicate registration would)
func TestLint(t *testing.T) {
    m := newFullyWired(t) // helper in metrics_test.go; later tasks extend it to touch every metric
    problems, err := testutil.GatherAndLint(m.Registry)
    require.NoError(t, err)
    // go_*/process_* are third-party; filter to jo_ei_ prefix
    assert.Empty(t, filterJoEi(problems))
}
```

- [ ] **Step 3: Run** `go test ./internal/metrics/ -v` — Expected: FAIL (package missing).

- [ ] **Step 4: Implement `metrics.go`**: `prometheus.NewRegistry()`; register `collectors.NewGoCollector(collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsGC, collectors.MetricsMemory, collectors.MetricsScheduler))`, `collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})`, `jo_ei_build_info` gauge (`goversion` = `runtime.Version()`) set to 1. `Handler()` = `promhttp.InstrumentMetricHandler(reg, promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg, EnableOpenMetrics: true, MaxRequestsInFlight: 4, Timeout: 10 * time.Second, ErrorLog: <adapter writing log.Error() with component "metrics">}))`. Package doc comment states the hook rule and the extension recipe in 4 lines.

- [ ] **Step 5: Run** `go test ./internal/metrics/ -v` — Expected: PASS.

- [ ] **Step 6: Commit** `feat(metrics): registry with Go runtime, process and build info`

---

### Task 3: Inbound HTTP metrics

**Files:**
- Create: `internal/metrics/http.go`, `internal/metrics/http_test.go`

**Interfaces:**
- Consumes: `Metrics`, `newDurationHistogramOpts`, `oneOf` (Task 2).
- Produces:
  - `type RouteFunc func(path string) string`
  - `func NewRouteFunc(proxyPrefixes []string) RouteFunc`
  - `func (m *Metrics) WrapHandler(next http.Handler, route RouteFunc) http.Handler` — returns `next` when `m == nil`.
  - Metrics: `jo_ei_http_requests_total{route,method,code}`, `jo_ei_http_request_duration_seconds{route,method}`, `jo_ei_http_requests_in_flight{route}`, `jo_ei_http_requests_aborted_total{route}`.

Route mapping (exact, in order):
- `/favicon.ico` → `favicon`; `/health` → `health`
- prefix `/console/` or path `/console` → `console`
- prefix `/api/auth/` → `auth`; prefix `/api/` → `api`
- first segment ∈ `proxyPrefixes` → that segment, except `v2` → `docker`
- else → `other`

Method: `GET HEAD POST PUT PATCH DELETE OPTIONS` kept; else `other`. SSE exclusion: path `== "/api/events"` skips the duration observation only.

- [ ] **Step 1: Write failing tests** (table + behaviour):

```go
func TestRouteFunc(t *testing.T) {
    rf := metrics.NewRouteFunc([]string{"pypi", "npm", "yarn", "v2"})
    cases := map[string]string{
        "/pypi/simple/requests/": "pypi", "/yarn/x": "yarn", "/v2/library/alpine/manifests/3": "docker",
        "/maven/x": "other", "/console/": "console", "/api/auth/login": "auth",
        "/api/overview": "api", "/health": "health", "/favicon.ico": "favicon",
        "/": "other", "/.well-known/x": "other",
    }
    for in, want := range cases { assert.Equal(t, want, rf(in), in) }
}
func TestWrapHandler_CountsCodeAndMethod(t *testing.T)   // handler writes 404 for "PROPFIND /npm/x" → requests_total{route="npm",method="other",code="404"} == 1
func TestWrapHandler_ImplicitOK(t *testing.T)           // handler only Write()s → code="200"
func TestWrapHandler_InFlightReturnsToZero(t *testing.T)// inside handler: testutil.ToFloat64(gauge{route="pypi"}) == 1; after: 0
func TestWrapHandler_PreservesFlusher(t *testing.T)     // inner asserts w.(http.Flusher) ok == true
func TestWrapHandler_SSEExcludedFromHistogram(t *testing.T) // GET /api/events → requests_total{route="api"}==1, histogram sample count for route="api" == 0
func TestWrapHandler_CountsAbort(t *testing.T)          // request ctx cancelled before handler returns → aborted_total{route="pypi"} == 1
func TestWrapHandler_NilMetricsPassThrough(t *testing.T){ var m *metrics.Metrics; h := &stubHandler{}; assert.Same(t, h, m.WrapHandler(h, nil).(*stubHandler)) }
```

Extend `newFullyWired` to issue one request through `WrapHandler`.

- [ ] **Step 2: Run** `go test ./internal/metrics/ -run 'Route|WrapHandler' -v` — Expected: FAIL.

- [ ] **Step 3: Implement** with `httpsnoop.CaptureMetrics(next, w, r)` (preserves Flusher/ReaderFrom/Hijacker); compute route once from the original `r.URL.Path` **before** calling next (the proxy mux rewrites `r.URL.Path`). Abort = `r.Context().Err() != nil` after next returns. Help text for aborted: `"Inbound requests whose client went away before the handler finished."`

- [ ] **Step 4: Run** `go test ./internal/metrics/ -v` — Expected: PASS.

- [ ] **Step 5: Commit** `feat(metrics): inbound HTTP RED and in-flight metrics`

---

### Task 4: Upstream metrics + circuit state

**Files:**
- Create: `internal/metrics/upstream.go`, `internal/metrics/upstream_test.go`
- Modify: `internal/httpx/circuitbreaker.go`, `internal/httpx/circuitbreaker_test.go`

**Interfaces:**
- Produces:
  - `func (c *httpx.CircuitBreaker) OpenHosts() []string` — hosts (`req.URL.Host` form) whose `openUntil` is after `c.now()`, sorted.
  - `func UpstreamHosts(upstreamLists ...[]string) []string` — `url.Parse(u).Host` of each, deduplicated; unparseable/empty skipped.
  - `func (m *Metrics) WrapTransport(rt http.RoundTripper, hosts []string) http.RoundTripper` — nil-safe.
  - `type OpenHostsReporter interface{ OpenHosts() []string }`
  - `func (m *Metrics) RegisterCircuitBreaker(cb OpenHostsReporter, hosts []string)` — nil-safe.
  - `func classifyUpstreamError(err error) string` (unexported, tested in-package).
  - Metrics: `jo_ei_upstream_requests_total{host,code}`, `jo_ei_upstream_request_duration_seconds{host}`, `jo_ei_upstream_requests_in_flight{host}`, `jo_ei_upstream_errors_total{host,reason}`, `jo_ei_upstream_circuit_open{host}`.

Classification order (first match wins):
`errors.Is(err, httpx.ErrCircuitOpen)` → `circuit_open`; `errors.Is(err, context.Canceled)` → `canceled`; `errors.Is(err, context.DeadlineExceeded)` or `net.Error` with `Timeout()` → `timeout`; `*net.DNSError` → `dns`; `*tls.CertificateVerificationError`, `x509.UnknownAuthorityError`, `x509.HostnameError`, `x509.CertificateInvalidError`, `tls.RecordHeaderError` → `tls`; `*net.OpError` → `connection`; else `other`.

- [ ] **Step 1: Write failing tests**

```go
// httpx
func TestCircuitBreaker_OpenHosts(t *testing.T) // trip "a:443" via a 429 response; OpenHosts()==[]string{"a:443"}; advance c.now past cooldown → empty

// metrics (package metrics, internal test for classify)
func TestClassifyUpstreamError(t *testing.T) // table: fmt.Errorf("x: %w", httpx.ErrCircuitOpen)→"circuit_open", context.Canceled→"canceled",
    // context.DeadlineExceeded→"timeout", &net.DNSError{}→"dns", &tls.CertificateVerificationError{}→"tls",
    // &net.OpError{Op:"dial", Err: errors.New("refused")}→"connection", errors.New("x")→"other"
func TestUpstreamHosts(t *testing.T) // ([]string{"https://pypi.org/simple","https://pypi.org"}, []string{"http://nexus:8081/x", "::bad"}) → ["pypi.org","nexus:8081"]
func TestWrapTransport_StatusAndUnknownHost(t *testing.T)
    // fake RoundTripper returning 200; hosts=["pypi.org"]; request to https://pypi.org/x → requests_total{host="pypi.org",code="200"}==1
    // request to https://cdn.example.net/blob → requests_total{host="other",code="200"}==1
func TestWrapTransport_ErrorCountsReason(t *testing.T) // fake returns context.DeadlineExceeded → requests_total{code="error"}==1, errors_total{reason="timeout"}==1, in_flight==0
func TestCircuitCollector(t *testing.T) // fake reporter OpenHosts()=["pypi.org","evil:1"]; hosts=["pypi.org","npmjs.org"]
    // → circuit_open{host="pypi.org"}=1, {host="npmjs.org"}=0, {host="other"}=1
```

- [ ] **Step 2: Run** `go test ./internal/httpx/ ./internal/metrics/ -v` — Expected: FAIL.

- [ ] **Step 3: Implement.** Wrapper: increment in-flight, time `rt.RoundTrip(req)`, observe duration, label host via the closed host set from `hosts`. Circuit collector is a `prometheus.Collector` with a `*prometheus.Desc`, emitting a 0/1 const gauge for every configured host plus `other` only when an unknown host is open.

- [ ] **Step 4: Run** same command — Expected: PASS.

- [ ] **Step 5: Commit** `feat(metrics): upstream request, error and circuit-breaker metrics`

---

### Task 5: Scanner metrics

**Files:**
- Create: `internal/metrics/scanner.go`, `internal/metrics/scanner_test.go`
- Modify: `internal/scanner/limited.go`, `internal/scanner/limited_test.go` (create if absent)

**Interfaces:**
- Produces (scanner pkg): `type LimitedOption func(*LimitedScanner)`; `func WithWaitObserver(f func(time.Duration)) LimitedOption`; signature becomes `func NewLimitedScanner(inner gate.AVScanner, limit int, opts ...LimitedOption) gate.AVScanner` (existing callers compile unchanged). Observer called once per `Scan` with the semaphore wait, only after a slot is acquired.
- Produces (metrics pkg), all nil-safe:
  - `func (m *Metrics) WrapAVScanner(engine string, s gate.AVScanner) gate.AVScanner`
  - `func (m *Metrics) WrapCVEScanner(engine string, s gate.CVEScanner) gate.CVEScanner`
  - `func (m *Metrics) WrapImageScanner(engine string, s dockerproxy.ImageScanner) dockerproxy.ImageScanner` (forwards `Health()`)
  - `func (m *Metrics) ScanWaitObserver() func(time.Duration)` — nil when `m == nil`
  - `func (m *Metrics) SetScanConcurrencyLimit(n int)`
  - `func (m *Metrics) RegisterScannerHealth(snapshot func() []health.ScannerHealth)`
  - Metrics: `jo_ei_scans_total{scanner,result}`, `jo_ei_scan_duration_seconds{scanner}`, `jo_ei_scans_in_flight{scanner}`, `jo_ei_scan_queue_wait_seconds`, `jo_ei_scan_concurrency_limit`, `jo_ei_scanner_up{scanner}`.

Rules: `scanner` label closed set `clamav icap osv trivy`, else `other`. `result`: err==nil → `clean`/`detected` (AV: `!res.Clean`; CVE: `!res.Clean`; Image: `len(res.Findings) > 0`); err != nil → `timeout` if `errors.Is(err, context.DeadlineExceeded)` or `net.Error.Timeout()`, else `error`. `scanner_up`: skip entries with `!Enabled` or `Status == StatusUnknown`; value 1 for `ok`/`warn`, 0 for `down`; name mapping `"osv.dev"` → `osv`, other names through the closed set.

- [ ] **Step 1: Write failing tests**

```go
// scanner pkg
func TestLimitedScanner_WaitObserverCalled(t *testing.T) // limit 1, first Scan blocks on a channel, second Scan waits ≥20ms → observer got 2 calls, one ≥ 20ms
func TestLimitedScanner_NoObserverWhenCtxCancelledWhileWaiting(t *testing.T) // observer not called; returns ctx.Err()

// metrics pkg
func TestWrapAVScanner_Results(t *testing.T) // fakes: clean, infected (Clean:false), err=context.DeadlineExceeded, err=errors.New("x")
    // → scans_total{scanner="clamav",result=clean|detected|timeout|error} each 1; in_flight back to 0; duration count 4
func TestWrapCVEScanner_Detected(t *testing.T)  // ScanResult{Clean:false} → {scanner="osv",result="detected"}
func TestWrapImageScanner_ForwardsHealth(t *testing.T) // wrapped.Health() == fake.Health(); Findings non-empty → detected
func TestScannerUpCollector(t *testing.T)
    // snapshot: {osv.dev, ok, enabled}, {clamav, down, enabled}, {icap, unknown, enabled}, {trivy, off, enabled:false}
    // → scanner_up{scanner="osv"}=1, {scanner="clamav"}=0; no series for icap/trivy
func TestScanQueueMetrics(t *testing.T) // SetScanConcurrencyLimit(8) → gauge 8; ScanWaitObserver()(time.Second) → histogram count 1
func TestScannerNilMetrics(t *testing.T) // nil m: Wrap* return the same value; ScanWaitObserver()==nil
```

- [ ] **Step 2: Run** `go test ./internal/scanner/ ./internal/metrics/ -v` — Expected: FAIL.

- [ ] **Step 3: Implement.** Scanner-up is a scrape-time `prometheus.Collector`.

- [ ] **Step 4: Run** same — Expected: PASS.

- [ ] **Step 5: Commit** `feat(metrics): scanner throughput, latency, queue and health metrics`

---

### Task 6: Verdict and cache metrics

**Files:**
- Create: `internal/metrics/domain.go`, `internal/metrics/domain_test.go`

**Interfaces:**
- Produces (nil-safe):
  - `func (m *Metrics) WrapRecorder(r gate.Recorder) gate.Recorder` — records then delegates.
  - `type CacheStatter interface{ Stats() (cache.CacheStats, error) }`
  - `func (m *Metrics) RegisterCache(s CacheStatter, maxBytes int64)`
  - Metrics: `jo_ei_verdicts_total{ecosystem,verdict,gate}`, `jo_ei_cache_size_bytes`, `jo_ei_cache_max_bytes`.

Label sets: ecosystem `pypi npm maven rubygems go docker` else `other`; verdict = lowercase of `PASS CACHE BLOCK ERROR` else `other`; gate `cache supply cve malware image_scan`, empty → `none`, else `other`.

- [ ] **Step 1: Write failing tests**

```go
func TestWrapRecorder_CountsAndDelegates(t *testing.T)
    // Event{Ecosystem:"npm",Verdict:"BLOCK",Gate:"cve"} → verdicts_total{ecosystem="npm",verdict="block",gate="cve"}==1; fake inner got the event
    // Event{Ecosystem:"cargo",Verdict:"PASS",Gate:""} → {ecosystem="other",verdict="pass",gate="none"}==1
func TestCacheCollector(t *testing.T)      // Stats → SizeBytes 1024, maxBytes 4096 → size 1024, max 4096
func TestCacheCollector_StatsError(t *testing.T) // Stats err → no jo_ei_cache_size_bytes series, Gather() returns no error
func TestCacheCollector_NoMax(t *testing.T)      // maxBytes 0 → no jo_ei_cache_max_bytes series
```

- [ ] **Step 2: Run** `go test ./internal/metrics/ -run 'Recorder|Cache' -v` — Expected: FAIL.

- [ ] **Step 3: Implement**: cache size via scrape-time collector (skip on error); max as a constant gauge registered only when `maxBytes > 0`. Extend `newFullyWired` so the lint test covers Tasks 3–6 metrics.

- [ ] **Step 4: Run** `go test ./internal/metrics/ -v` — Expected: PASS incl. `TestLint`.

- [ ] **Step 5: Commit** `feat(metrics): verdict and cache metrics`

---

### Task 7: Wire into `jo-ei` with a dedicated listener

**Files:**
- Modify: `cmd/jo-ei/main.go` (transport ~225–234, scanners ~260–330, recorder ~240, handler ~449–455), `cmd/jo-ei/serve.go`
- Modify: `Dockerfile`, `Dockerfile.goreleaser` (`EXPOSE 8080 9464`), `docker-compose.yaml` (comment, no port)
- Test: `cmd/jo-ei/serve_test.go`, `cmd/jo-ei/main_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1–6.
- Produces: `func serveAll(ctx context.Context, srvs ...*http.Server) error` in `serve.go` — `errgroup.WithContext`, each runs existing `serve(gctx, srv)`; first error cancels the rest; returns that error.

Wiring order in `runProxy` (`mx` is `*metrics.Metrics`, nil when disabled):
1. Right after config/logger: `if cfg.Metrics.Enabled { mx = metrics.New(metrics.BuildInfo{Version: version, Commit: commit}, logger) }`.
2. Keep `cb := httpx.NewCircuitBreaker(...)` in its own variable; `hosts := metrics.UpstreamHosts(<Upstreams of each of the six registries in cfg.Registries>)` (cfg already has the stored overlay applied); `upstreamLimiter := mx.WrapTransport(cb, hosts)`; `mx.RegisterCircuitBreaker(cb, hosts)`. The three clients keep using `upstreamLimiter`.
3. `recorder: mx.WrapRecorder(&telemetry.Hub{...})`.
4. `shared.cveScanner = mx.WrapCVEScanner("osv", osvScanner)` (health keeps using concrete `osvScanner.Health`).
5. AV: keep `avScanners` unwrapped (the health loop type-asserts `scanner.Prober` on it); build `wrapped[i] = mx.WrapAVScanner(cfg.Malware.Scanners[i].Type, avScanners[i])`; `scanner.NewLimitedScanner(scanner.NewMultiScanner(wrapped...), limit, scanner.WithWaitObserver(mx.ScanWaitObserver()))`; `mx.SetScanConcurrencyLimit(limit)`. `WithWaitObserver(nil)` must be a no-op.
6. Docker: `Scanner: mx.WrapImageScanner("trivy", trivyScanner)` (only when `trivyScanner != nil`; avoid wrapping a typed-nil).
7. After `healthMon.Start()`: `mx.RegisterScannerHealth(healthMon.Snapshot)`. After cache creation: `mx.RegisterCache(artifactCache, int64(cfg.Cache.Local.MaxSizeGB)<<30)`.
8. Root handler: `Handler: logx.Middleware(mx.WrapHandler(root, metrics.NewRouteFunc(keys of handlers ∪ keys of rawHandlers)))`.
9. Servers: if `mx != nil`, build `metricsSrv` (mux: `cfg.Metrics.Path` → `mx.Handler()`, `ReadHeaderTimeout: 10s`, `WriteTimeout: 30s`) and pre-bind with `net.Listen("tcp", cfg.Metrics.Listen)`; on error return `fmt.Errorf("metrics.listen %s: %w", cfg.Metrics.Listen, err)`. Bind before starting either server so a port clash exits before the proxy accepts traffic. Serve the pre-bound listener (`srv.Serve(ln)`) — adapt `serve` to take an optional listener or add `serveListener`; builder's choice, but `serveAll` stays the entry point.
10. Startup log: add `Str("metrics", cfg.Metrics.Listen+cfg.Metrics.Path)` or `"disabled"`.

- [ ] **Step 1: Write failing tests**

```go
func TestServeAll_OneFailureStopsOthers(t *testing.T)
    // srvA on a listener already closed (Serve returns error immediately), srvB healthy → serveAll returns error within 2s, srvB shut down (GET fails)
func TestServeAll_CtxCancelShutsDownAll(t *testing.T) // cancel → nil error
func TestRunProxy_MetricsOnSeparateListener(t *testing.T)
    // follow the existing main_test.go pattern for starting runProxy with a temp config (free ports for server.listen and metrics.listen);
    // GET metrics-port/metrics → 200 and body contains "jo_ei_build_info";
    // GET proxy-port/metrics → 404 and body has "unknown_registry";
    // GET proxy-port/health then metrics-port body contains `jo_ei_http_requests_total{code="200",method="GET",route="health"}`
func TestRunProxy_MetricsPortInUse(t *testing.T) // occupy metrics port → runProxy returns error containing "metrics.listen"
func TestRunProxy_MetricsDisabled(t *testing.T)  // enabled:false → nothing listens on that port
func TestRunProxy_AVProbeStillRegistered(t *testing.T) // with a clamav scanner configured, /api/overview health (or healthMon snapshot via test hook) shows clamav as active, not "off"
```

If `main_test.go` has no harness to boot `runProxy`, extract the server-building section into `func buildServers(cfg *config.Config, ...) (proxy, metrics *http.Server, err error)` and test that instead; keep `runProxy` thin.

- [ ] **Step 2: Run** `go test ./cmd/jo-ei/ -v` — Expected: FAIL.

- [ ] **Step 3: Implement** per the wiring order above. `docker-compose.yaml` comment above `ports:`:

```yaml
    # Prometheus metrics listen on 9464 (metrics.listen). Not published on
    # purpose: attach Prometheus to this compose network and scrape jo-ei:9464.
```

- [ ] **Step 4: Run** `go test ./... && golangci-lint run && gofmt -l .` — Expected: all pass, gofmt prints nothing.

- [ ] **Step 5: Manual smoke**: delete the local DB (policy persists over config), `go run ./cmd/jo-ei --config config.yaml`, `curl -s localhost:9464/metrics | grep -c '^jo_ei_'` > 0, `curl -si localhost:8080/metrics` → 404.

- [ ] **Step 6: Commit** `feat: serve Prometheus metrics on a dedicated listener`

---

### Task 8: Monitoring assets + drift test

**Files:**
- Create: `examples/monitoring/prometheus.yml`, `examples/monitoring/alerts.yml`, `examples/monitoring/grafana/jo-ei-dashboard.json`, `examples/monitoring/README.md`
- Create: `internal/metrics/assets_test.go`
- Modify: `examples/README.md` (one line linking monitoring)

**Interfaces:**
- Consumes: metric names from Tasks 2–6.

Alert rules (group `jo-ei`; `for`, `severity`; every rule has `summary` and `description`):

| Alert | Expr (shape) | for | severity |
|---|---|---|---|
| `JoEiDown` | `up{job="jo-ei"} == 0` | 5m | critical |
| `JoEiHighErrorRatio` | `sum by (instance)(rate(jo_ei_http_requests_total{code=~"5.."}[5m])) / sum by (instance)(rate(jo_ei_http_requests_total[5m])) > 0.05` | 10m | warning |
| `JoEiHighLatency` | `histogram_quantile(0.95, sum by (le, instance)(rate(jo_ei_http_request_duration_seconds_bucket{route!~"console\|api\|auth\|health\|favicon"}[5m]))) > 10` | 15m | warning |
| `JoEiRequestsAborted` | `sum by (instance)(rate(jo_ei_http_requests_aborted_total[5m])) > 1` | 10m | info |
| `JoEiUpstreamErrors` | errors/requests by host `> 0.1` | 10m | warning |
| `JoEiUpstreamCircuitOpen` | `jo_ei_upstream_circuit_open == 1` | 5m | warning |
| `JoEiScannerDown` | `jo_ei_scanner_up == 0` | 5m | critical |
| `JoEiScanTimeouts` | `sum by (instance, scanner)(rate(jo_ei_scans_total{result="timeout"}[10m])) > 0` | 10m | warning |
| `JoEiScanQueueSaturated` | `sum by (instance)(jo_ei_scans_in_flight) >= on(instance) jo_ei_scan_concurrency_limit` | 10m | warning |
| `JoEiFileDescriptorsHigh` | `process_open_fds / process_max_fds > 0.8` | 10m | warning |
| `JoEiCacheNearlyFull` | `jo_ei_cache_size_bytes / jo_ei_cache_max_bytes > 0.9` | 30m | warning |

Dashboard: importable JSON with `__inputs` `DS_PROMETHEUS`, `schemaVersion` current, uid `jo-ei-overview`, variables `job` (default `jo-ei`), `instance` (multi), `route` (multi, from `label_values(jo_ei_http_requests_total, route)`). Rows exactly as spec §"Monitoring assets" (Overview / By route / Upstreams / Scanners / Verdicts & cache / Process & Go runtime). Use the dataviz skill for colors/units before writing it.

- [ ] **Step 1: Write failing drift test**

```go
func TestAssetsReferenceOnlyRegisteredMetrics(t *testing.T) {
    m := newFullyWired(t)
    known := registeredNames(m) // from Gather(); for histograms add name+"_bucket","_sum","_count"
    known["up"] = true
    // process collector is a no-op on Windows dev boxes; whitelist the names the assets use
    for _, n := range []string{"process_cpu_seconds_total", "process_resident_memory_bytes", "process_open_fds", "process_max_fds", "process_start_time_seconds"} { known[n] = true }
    for _, f := range []string{"../../examples/monitoring/alerts.yml", "../../examples/monitoring/grafana/jo-ei-dashboard.json"} {
        for _, name := range regexp.MustCompile(`\b(jo_ei_[a-z0-9_]+|process_[a-z0-9_]+|go_[a-z0-9_]+)\b`).FindAllString(read(t, f), -1) {
            assert.True(t, known[name], "%s references unregistered metric %s", f, name)
        }
    }
}
func TestAlertsYAMLParses(t *testing.T) // yaml.Unmarshal into struct{Groups []struct{Name string; Rules []struct{Alert, Expr, For string; Labels, Annotations map[string]string}}}; every rule has Labels["severity"], Annotations["summary"], Annotations["description"]
func TestDashboardJSONParses(t *testing.T) // json.Unmarshal ok; uid=="jo-ei-overview"
```

Use `go.yaml.in/yaml/v3` (already an indirect dep) for YAML. `newFullyWired` must have touched every labelled vector so series exist (the drift test reads family names, which `Gather` only returns for vectors with ≥1 child — touch each one).

- [ ] **Step 2: Run** `go test ./internal/metrics/ -run 'Assets|Alerts|Dashboard' -v` — Expected: FAIL (files missing).

- [ ] **Step 3: Write the four asset files.** If `promtool` is available run `promtool check rules examples/monitoring/alerts.yml`; otherwise note it was not run.

- [ ] **Step 4: Run** same — Expected: PASS.

- [ ] **Step 5: Commit** `feat(monitoring): Grafana dashboard and Prometheus alert examples`

---

### Task 9: Documentation

**Files:**
- Create: `docs/metrics.md`
- Modify: `docs/configuration.md` (metrics section), `README.md` ("Monitoring" section, 5–8 lines, link to docs/metrics.md and examples/monitoring), `CHANGELOG.md` (`### Added` under Unreleased)

`docs/metrics.md` contents: enabling/config + env vars; network isolation (bind `127.0.0.1:9464` or internal interface; don't publish in compose; no auth by design); scrape config snippet; full catalogue table (name, type, labels with their closed value sets, meaning) — copy from spec §Metric catalogue updated to as-built names; note "aborted = client went away"; "Adding a metric" recipe (4 steps from spec §Extension pattern + hook rule + naming rules + "the lint and drift tests will fail if you break the rules").

- [ ] **Step 1: Write docs.**
- [ ] **Step 2: Verify** every `jo_ei_` name in `docs/metrics.md` exists: extend `TestAssetsReferenceOnlyRegisteredMetrics` file list with `../../docs/metrics.md`; run `go test ./internal/metrics/ -v` — Expected: PASS.
- [ ] **Step 3: Final gate**: `go test ./... && golangci-lint run && gofmt -l . && govulncheck ./...` — Expected: pass / empty / no vulns (if a stdlib advisory appears, bump `toolchain` in go.mod).
- [ ] **Step 4: Commit** `docs: Prometheus metrics and monitoring setup`
