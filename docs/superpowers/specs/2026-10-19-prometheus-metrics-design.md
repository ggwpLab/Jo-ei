# Prometheus Metrics Endpoint — Design

**Date:** 2026-10-19
**Status:** Draft
**Stage:** Post-v0.5.1 iteration

## Problem

Jō-ei has no machine-readable health signal. The console's
`/api/metrics/daily` is business telemetry for humans (verdict tallies per
day), and the only liveness probe is `GET /health` returning a constant
`{"status":"ok"}`. An operator running Jō-ei in front of a build farm cannot
answer the questions that matter during an incident — is the proxy slow, is it
erroring, is it an upstream or a scanner, is the process starved — without
reading logs.

Users already run Prometheus and Grafana. Jō-ei should plug into that stack the
way any well-behaved Go service does.

## Goal

Expose a Prometheus `/metrics` endpoint on a dedicated listener, carrying
service-health metrics that follow Go/Prometheus best practice, plus a ready
Grafana dashboard and example alert rules. Make adding a metric later a
routine, low-friction change.

Decisions fixed during brainstorming (user's):

1. **Focus:** service health first — request rate, error ratio, latency
   distribution, in-flight requests, errors and timeouts, process CPU/memory,
   Go runtime. Domain (verdict) counters are welcome but secondary.
2. **Separate port.** `/metrics` is served on its own listener reachable only
   by monitoring, never on the proxy port (`server.listen`, `:8080`).
3. **Extensible.** Adding a metric must be easy and follow one documented
   pattern.
4. **Deliverables include** a Grafana dashboard (JSON) and example Prometheus
   alert rules.

## Non-goals

- Authentication / TLS on the metrics listener. Isolation is by network
  (separate port, not published in compose). Documented, not implemented.
- OpenTelemetry, tracing, push gateway, exemplars.
- Replacing `/api/metrics/daily` or the console's charts.
- Per-package or per-path labels (cardinality).
- Response/egress byte metrics. Easy follow-up via the extension recipe.

## Anti-goals (would be a failure even if it "works")

- Unbounded label cardinality: any label whose values come from request input
  (path, package name, arbitrary host) is a bug.
- Metrics on the proxy port, or reachable through `/api/` without auth.
- Measurable overhead on the proxy data path when metrics are disabled.
- Package-level globals (`prometheus.MustRegister` on the default registry)
  that make tests order-dependent.

## Configuration

```yaml
metrics:
  enabled: true          # default true (my call — see "Calls made")
  listen: ":9464"        # not 9090: that is Prometheus's own default port
  path: "/metrics"
```

- Env overrides via the existing viper `JOEI_` prefix
  (`JOEI_METRICS_ENABLED`, `JOEI_METRICS_LISTEN`, `JOEI_METRICS_PATH`); add
  `SetDefault`s for all three so `AutomaticEnv` picks them up (see the
  compose-env-file note: env overrides need the key known to viper).
- Validation: `listen` non-empty and not equal to `server.listen`; `path`
  starts with `/`.
- `config.yaml` (repo root) gets a commented `metrics:` block.
- `docker-compose.yaml`: port 9464 is **not** published. A comment explains
  that Prometheus should join the compose network and scrape `jo-ei:9464`.
  `Dockerfile`/`Dockerfile.goreleaser` add `EXPOSE 9464` (documentation only).
- Default port `:9464` (the OpenTelemetry Prometheus-exporter convention) so a
  host that also runs Prometheus (`:9090`) or node_exporter (`:9100`) does not
  collide after upgrade.

## Architecture

### Package `internal/metrics`

Owns the registry and every metric definition. Nothing else imports
`prometheus/client_golang` except `cmd/jo-ei` wiring and tests.

```go
type Metrics struct {
    Registry *prometheus.Registry
    HTTP     *HTTPMetrics
    Upstream *UpstreamMetrics
    Scanner  *ScannerMetrics
    Verdicts *VerdictMetrics
}

func New(info BuildInfo) *Metrics      // creates a fresh prometheus.Registry
func (m *Metrics) Handler() http.Handler
```

- A fresh `prometheus.NewRegistry()` — never `DefaultRegisterer`.
- Registers `collectors.NewGoCollector(...)` with
  `collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsGC,
  collectors.MetricsMemory, collectors.MetricsScheduler)` (GC pauses,
  scheduler latency, heap classes) and
  `collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})`
  (`process_cpu_seconds_total`, `process_resident_memory_bytes`,
  `process_open_fds`, `process_max_fds`, `process_start_time_seconds`).
- `jo_ei_build_info{version,commit,goversion}` gauge fixed at 1, fed from
  `main.version` / `main.commit` and `runtime.Version()`.
- `Handler()` = `promhttp.InstrumentMetricHandler(reg, promhttp.HandlerFor(reg,
  promhttp.HandlerOpts{Registry: reg, EnableOpenMetrics: true,
  MaxRequestsInFlight: 4, Timeout: 10s, ErrorLog: <zerolog adapter>}))` —
  this adds `promhttp_metric_handler_*` self-metrics.

**Disabled mode:** when `metrics.enabled=false`, `cmd/jo-ei` does not call
`metrics.New` and passes `nil` to every hook. Each hook (`HTTPMetrics.Middleware`,
upstream `RoundTripper` wrapper, scanner wrapper, recorder wrapper) is a
constructor that returns its input unchanged when given a `nil` metrics
struct, so the data path is byte-for-byte today's code.

### Extension pattern

Each subsystem's metrics are a small struct in `internal/metrics` with a
`newXxx(reg prometheus.Registerer)` constructor that creates and registers its
vectors via `promauto.With(reg)`, plus the hook (middleware / wrapper /
collector) that feeds them. To add a metric:

1. Add the field to the relevant struct (or a new struct + field on `Metrics`).
2. Create it in the constructor with `promauto.With(reg)`.
3. Feed it from the hook, or — for state that already exists somewhere —
   implement a `prometheus.Collector` that reads it at scrape time (the
   pattern used by scanner health and cache size below).
4. A test with `prometheus/testutil`.

Rules (documented in `docs/metrics.md`, enforced by a test that runs
`testutil.GatherAndLint` over the full registry and fails on any problem):
`jo_ei_` prefix; base units (`_seconds`, `_bytes`); counters end `_total`;
labels only with values from a closed, code- or config-defined set.

### Metrics listener

`cmd/jo-ei` builds a second `http.Server` when enabled: mux with
`metrics.path` → `m.Handler()` only; `ReadHeaderTimeout: 10s`,
`WriteTimeout: 30s`. Both servers run under one `errgroup.WithContext`
(`golang.org/x/sync` is already a dependency); each goroutine calls the
existing single-server `serve(gctx, srv)` helper, so an error from one cancels
the group context and gracefully shuts the other down. A bind failure (port in
use) is **fatal**: `jo-ei` exits non-zero with a clear error naming
`metrics.listen` — a silently missing metrics endpoint is worse than a loud
startup failure. Startup log line
adds `metrics=<listen><path>` or `metrics=disabled`.

## Metric catalogue

Histogram buckets for request durations (seconds), chosen because artifact
downloads and Docker blobs legitimately take tens of seconds:
`0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120`.
All duration histograms also set `NativeHistogramBucketFactor: 1.1` (exposed
alongside classic buckets; used automatically by Prometheus servers that have
native histograms enabled).

### Inbound HTTP (RED + saturation)

Middleware wraps `root` in `cmd/jo-ei/main.go` (inside `logx.Middleware`).

| Metric | Type | Labels |
|---|---|---|
| `jo_ei_http_requests_total` | counter | `route`, `method`, `code` |
| `jo_ei_http_request_duration_seconds` | histogram | `route`, `method` |
| `jo_ei_http_requests_in_flight` | gauge | `route` |
| `jo_ei_http_requests_aborted_total` | counter | `route` |

- **`route`** is computed from the first path segment against a closed set
  built at startup: each registered proxy prefix (`pypi`, `npm`, `yarn`,
  `maven`, `rubygems`, `go`, `v2` → reported as `docker`), plus `console`,
  `api`, `auth` (`/api/auth/`), `health`, `favicon`, and `other` for anything
  else (unknown prefixes, browser noise). Disabled registries are absent from
  the set and fall into `other`.
- **`method`**: the standard methods; anything else → `other`.
- **`code`**: status as written (default 200 if the handler wrote a body
  without `WriteHeader`). Bounded in practice. The response-writer wrapper must
  preserve `http.Flusher` (SSE `/api/events`, streaming downloads) — use
  `httpsnoop` or an equivalent that also preserves `io.ReaderFrom`; the
  builder picks.
- **Duration** covers until the handler returns, i.e. the full streamed body.
  `GET /api/events` (SSE, long-lived) is excluded from the duration histogram
  but still counted in `requests_total` and `in_flight`.
- **Aborted**: incremented when the request context is done
  (`r.Context().Err() != nil`) by the time the handler returns. In Go this
  means the client went away (disconnect, client-side timeout); the server's
  `WriteTimeout` does **not** cancel `r.Context()`, so it is not claimed to be
  covered. Timeouts Jō-ei itself hits are measured where they happen:
  `jo_ei_upstream_errors_total{reason="timeout"}` and
  `jo_ei_scans_total{result="timeout"}`. Help text says "client aborted".
- Error ratio is derived in PromQL (`code=~"5.."`); 403/423 blocks are policy
  outcomes, not errors.

### Upstream registries (outbound)

A `RoundTripper` wrapper is installed as the **outermost** layer of the
shared upstream transport chain (`CircuitBreaker → RateLimiter →
ConcurrencyLimiter → Transport`, `cmd/jo-ei/main.go:225`), so measured
latency includes local queueing and circuit-breaker rejections are visible.
Every outbound registry client (adapter, download, and the Docker proxy's
client — builder verifies which clients the Docker path uses) goes through it.

| Metric | Type | Labels |
|---|---|---|
| `jo_ei_upstream_requests_total` | counter | `host`, `code` |
| `jo_ei_upstream_request_duration_seconds` | histogram | `host` |
| `jo_ei_upstream_requests_in_flight` | gauge | `host` |
| `jo_ei_upstream_errors_total` | counter | `host`, `reason` |

- **`host`**: upstream hostname only if it belongs to the set of hosts from
  configured registry upstreams (incl. Docker registries), else `other`.
  Docker blob redirects to CDN/S3 hosts land in `other` — deliberate.
- **`code`**: HTTP status, or `error` when `RoundTrip` returned an error.
- **Duration** is time to response headers (what `RoundTrip` measures); body
  transfer is covered by the inbound histogram.
- **`reason`** ∈ `timeout` (deadline exceeded / `net.Error.Timeout()`),
  `canceled`, `circuit_open`, `tls`, `dns`, `connection`, `other`.
  `circuit_open` matches the existing `httpx.ErrCircuitOpen` via `errors.Is`.
- Scope: registry traffic only. OSV (CVE) and Trivy have their own HTTP
  clients and are covered by scanner metrics, not upstream metrics.

Circuit breaker state:

| Metric | Type | Labels |
|---|---|---|
| `jo_ei_upstream_circuit_open` | gauge (0/1) | `host` |

Collected at scrape time from `CircuitBreaker` (add a read-only accessor that
reports currently-open hosts; same `host` → `other` mapping).

### Scanners

Three scanner interfaces exist and all are instrumented, each engine wrapped
individually so per-engine figures are distinct:

| Interface | Engines | `scanner` label | `detected` means |
|---|---|---|---|
| `gate.AVScanner` | ClamAV, ICAP (wrapped before `MultiScanner`/`LimitedScanner`) | `clamav`, `icap` | signature matched |
| `gate.CVEScanner` | `scanner.OSVScanner` | `osv` | findings non-empty |
| `dockerproxy.ImageScanner` | Trivy (`ScanImage`) | `trivy` | findings non-empty |

| Metric | Type | Labels |
|---|---|---|
| `jo_ei_scans_total` | counter | `scanner`, `result` |
| `jo_ei_scan_duration_seconds` | histogram | `scanner` |
| `jo_ei_scans_in_flight` | gauge | `scanner` |
| `jo_ei_scan_queue_wait_seconds` | histogram | — |
| `jo_ei_scan_concurrency_limit` | gauge | — |
| `jo_ei_scanner_up` | gauge (0/1) | `scanner` |

- **`scanner`**: engine type (`clamav`, `icap`, `osv`, `trivy`). Two engines
  of the same type would merge — acceptable; noted.
- **`result`** ∈ `clean`, `detected` (malware signature / CVE findings
  present), `error`, `timeout` (ctx deadline / `net.Error.Timeout()`).
- Queue wait and concurrency limit come from `LimitedScanner` (time spent
  waiting on its semaphore; the configured `malware.max_concurrent_scans`).
  **Hook rule:** packages outside `internal/metrics` never import
  `client_golang`. Where a measurement must happen inside another package
  (here: semaphore wait in `LimitedScanner`), that package gets a small
  optional observer — e.g. a `func(time.Duration)` field or a one-method
  interface set via constructor option, nil by default — and
  `internal/metrics` supplies the implementation. This is the general
  pattern for future metrics too.
- `scanner_up` is a scrape-time collector over `health.Monitor.Snapshot()`;
  1 when the engine is healthy, 0 otherwise; disabled engines are omitted.
  Builder maps the monitor's status values (slow counts as up).

### Gate verdicts (domain)

Recorder wrapper around the existing `telemetry.Hub` (`gate.Recorder`):

| Metric | Type | Labels |
|---|---|---|
| `jo_ei_verdicts_total` | counter | `ecosystem`, `verdict`, `gate` |

- `ecosystem` (not `registry`): from `gate.Event.Ecosystem`, mapped through a
  closed set of known ecosystems (`other` fallback). Yarn is recorded by the
  npm adapter, so it appears as `npm` here — expected.
- `verdict`: lowercased `gate.Verdict*` (`pass`, `cache`, `block`, `error`).
- `gate`: all `gate.Gate*` constants incl. `GateImageScan`.

### Cache

| Metric | Type | Labels |
|---|---|---|
| `jo_ei_cache_size_bytes` | gauge | — |
| `jo_ei_cache_max_bytes` | gauge | — |

`size` from a scrape-time collector over `LocalCache.Stats()` (cheap SQL
sums; only when the backend provides it). `max` is a constant gauge from
config `cache.local.max_size_gb` (`CacheStats` has no max field); omitted when
the limit is 0/unset.

## Monitoring assets — `examples/monitoring/`

- `prometheus.yml` — minimal scrape job `jo-ei` → `jo-ei:9464`.
- `alerts.yml` — rule group `jo-ei`:
  - `JoEiDown` — `up{job="jo-ei"} == 0` for 5m.
  - `JoEiHighErrorRatio` — 5xx share of `jo_ei_http_requests_total` > 5% for 10m.
  - `JoEiHighLatency` — p95 of `jo_ei_http_request_duration_seconds` for
    `route!~"console|api|auth"` > 10s for 15m (downloads skew high;
    threshold commented as tunable).
  - `JoEiRequestsAborted` — client-abort rate > 1/s for 10m (severity
    `info`: often build tools cancelling; worth seeing, rarely paging).
  - `JoEiUpstreamErrors` — upstream error ratio > 10% per host for 10m.
  - `JoEiUpstreamCircuitOpen` — `jo_ei_upstream_circuit_open == 1` for 5m.
  - `JoEiScannerDown` — `jo_ei_scanner_up == 0` for 5m.
  - `JoEiScanTimeouts` — `result="timeout"` rate > 0 for 10m.
  - `JoEiScanQueueSaturated` — in-flight scans ≥ concurrency limit for 10m.
  - `JoEiFileDescriptorsHigh` — `process_open_fds / process_max_fds > 0.8`.
  - `JoEiCacheNearlyFull` — size/max > 0.9 for 30m.
  Each with `severity` label and `summary`/`description` annotations.
- `grafana/jo-ei-dashboard.json` — importable (`__inputs` with
  `DS_PROMETHEUS`), variables `job`, `instance`, `route`. Rows:
  1. **Overview** — RPS, error ratio, p50/p95/p99 latency, in-flight, aborted.
  2. **By route** — rate and p95 per `route`, status-code breakdown.
  3. **Upstreams** — rate/errors by `reason`/p95 per host, circuit state.
  4. **Scanners** — scan rate by result, p95 duration, queue wait,
     in-flight vs limit, up/down.
  5. **Verdicts & cache** — verdicts by type/ecosystem, cache fill.
  6. **Process & Go runtime** — CPU (`rate(process_cpu_seconds_total)`), RSS,
     heap, goroutines, GC pause, scheduler latency, FDs.
- `README.md` — how to wire it into an existing stack.

## Documentation

- `docs/metrics.md` — configuration, network-isolation guidance (bind to an
  internal interface, do not publish the port), full metric catalogue with
  label values, the extension recipe and naming rules.
- Root `README.md`: short "Monitoring" section linking to it.
- `CHANGELOG.md` Unreleased entry.

## Testing

- `internal/metrics` unit tests with `prometheus/testutil`:
  - middleware: route mapping (incl. `other`, `docker`), method folding,
    implicit 200, `Flusher` preserved, SSE excluded from histogram, abort
    counted on cancelled ctx;
  - upstream wrapper: status vs `error`, each `reason` classification,
    unknown host → `other`, circuit-open gauge;
  - scanner wrapper: each `result`, in-flight returns to 0;
  - `nil` metrics → wrappers return their input unchanged;
  - lint: `testutil.GatherAndLint` over a fully wired registry reports nothing.
- **Asset drift test:** a Go test reads `examples/monitoring/alerts.yml` and
  the dashboard JSON, extracts every `jo_ei_*` metric name referenced, and
  asserts each is registered by `metrics.New` (histogram `_bucket/_sum/_count`
  suffixes resolved). Prevents dashboards rotting when metrics are renamed.
- `cmd/jo-ei`: config validation (same listen as server rejected; defaults);
  integration-style test that `/metrics` answers on the metrics listener and
  404s on the proxy listener.
- `config` tests for env overrides.
- Local: `go test ./...`, `golangci-lint run`, `gofmt`. `-race` runs in CI only.

## Dependencies

- `github.com/prometheus/client_golang` (+ transitive `client_model`,
  `common`, `procfs`). Current release at implementation time.
- Optionally `github.com/felixge/httpsnoop` for the response-writer wrapper.
- Run `govulncheck` after adding.

## Calls made (my calls, not discussed — check while reading)

1. Metrics **enabled by default** on `:9464`; bind failure is fatal.
2. No auth on the metrics listener; network isolation only.
3. Route label `docker` for the `v2` prefix; `yarn` kept separate from `npm`.
4. `upstream` latency = time to headers incl. local queueing (outermost wrapper).
5. Bucket layout up to 120 s, plus native histograms.
6. SSE stream excluded from the duration histogram.
7. Scanner label is the engine *type*, not the address; OSV and Trivy
   included alongside AV engines.
8. Assets live in `examples/monitoring/`, alongside the existing client examples.
9. "Aborted" = client went away; server-side timeouts are measured at the
   upstream and scanner layers instead.
10. Verdict label is `ecosystem` (what the event carries), so yarn shows as npm.
11. Hook rule: other packages expose optional observers, never import
    `client_golang`.

## Left to the builder

Exact file split inside `internal/metrics`; choice of response-writer wrapper;
how the circuit breaker exposes open hosts; mapping of `health` statuses to
`scanner_up`; dashboard panel layout details; alert thresholds within the
spirit above.
