# Prometheus Metrics

Jō-ei exposes Prometheus metrics on a **dedicated listener**, separate from the
proxy port. Starter assets (scrape config, alert rules, a Grafana dashboard) live
in [`examples/monitoring/`](../examples/monitoring/).

## Enabling

Metrics are on by default.

| Key | Env var | Default | Description |
|---|---|---|---|
| `metrics.enabled` | `JOEI_METRICS_ENABLED` | `true` | Serve metrics. When `false` no listener is started and nothing is instrumented. |
| `metrics.listen` | `JOEI_METRICS_LISTEN` | `:9464` | TCP address of the metrics listener. Must differ from `server.listen`. |
| `metrics.path` | `JOEI_METRICS_PATH` | `/metrics` | URL path that serves the metrics. |

If the metrics address cannot be bound (port in use, bad address), startup stops
with an error naming `metrics.listen`. Environment overrides need the key to be
present in `config.yaml`, as for every other setting.

## Network isolation

The metrics port has **no authentication, by design**: Prometheus scrapes are
expected to stay on an internal network. The metrics expose package-registry
traffic shape, scanner health and cache size, not package contents.

- The provided `docker-compose.yaml` does **not** publish port 9464; reach it from
  other containers on the compose network (`jo-ei:9464`).
- Outside compose, bind to loopback (`127.0.0.1:9464`) or an internal interface
  address instead of `:9464` unless a firewall already restricts the port.

## Scraping

```yaml
scrape_configs:
  - job_name: jo-ei
    metrics_path: /metrics
    static_configs:
      - targets: ["jo-ei:9464"]
```

The full minimal config is
[`examples/monitoring/prometheus.yml`](../examples/monitoring/prometheus.yml).
The example alert rules `JoEiDown` and `JoEiFileDescriptorsHigh` hardcode
`job="jo-ei"`: if your scrape job has a different name, edit those two
expressions. Duration histograms are exposed both as classic
`_bucket` series and as native histograms (bucket factor 1.1). When Prometheus
has native-histogram scraping enabled it drops the classic buckets by default,
which would silence every `histogram_quantile` panel and `JoEiHighLatency`; the
example scrape job therefore sets `always_scrape_classic_histograms: true`.

## Metric catalogue

Every label value comes from a closed set; anything unexpected is reported as
`other`, so cardinality stays bounded.

### HTTP (inbound)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `jo_ei_http_requests_total` | counter | `route`, `method`, `code` | Inbound requests. |
| `jo_ei_http_request_duration_seconds` | histogram | `route`, `method` | Request duration; the SSE stream (`/api/events`) is excluded. |
| `jo_ei_http_requests_in_flight` | gauge | `route` | Requests currently being served. |
| `jo_ei_http_requests_aborted_total` | counter | `route` | The client went away, or writing the response failed (including the server's own write timeout). |

`route` is one of the enabled registry prefixes (`pypi`, `npm`, `yarn`,
`maven`, `rubygems`, `go`), `docker` (the `/v2/` API), `console`, `auth`, `api`,
`health`, `favicon` or `other`. The `route` label keeps `yarn` separate from
`npm`, unlike `ecosystem` on `jo_ei_verdicts_total`, where yarn is reported as
`npm`. `method` is a standard HTTP method or `other`.

"Aborted" means the client went away, or writing the response failed,
including the server's own write timeout (Go cancels the request context once a
write fails). Each open console tab's SSE stream (`/api/events`) counts as one
permanent in-flight `api` request and adds one aborted `api` request when the
tab closes. Jō-ei's own upstream and scan timeouts are visible as
`jo_ei_upstream_errors_total{reason="timeout"}` and
`jo_ei_scans_total{result="timeout"}`.

### Upstream (outbound)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `jo_ei_upstream_requests_total` | counter | `host`, `code` | Outbound requests; `code="error"` when no response arrived. |
| `jo_ei_upstream_request_duration_seconds` | histogram | `host` | Time until response headers or error. |
| `jo_ei_upstream_requests_in_flight` | gauge | `host` | Outbound requests in flight. |
| `jo_ei_upstream_errors_total` | counter | `host`, `reason` | Requests that failed without a response. |
| `jo_ei_upstream_circuit_open` | gauge | `host` | 1 when the circuit breaker for the host is open, else 0. |

`host` is one of the configured upstream hosts, as `host[:port]` exactly as written in the configured upstream URL; everything else (for example
the CDN hosts Docker blob redirects point to) is `other`. `reason` is
`circuit_open`, `canceled`, `timeout`, `dns`, `tls`, `connection` or `other`.
Calls to osv.dev and the Trivy server are not part of the upstream metrics;
see the scanner metrics below.

### Scanners

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `jo_ei_scans_total` | counter | `scanner`, `result` | Scans by scanner and result. |
| `jo_ei_scan_duration_seconds` | histogram | `scanner` | Scan duration. |
| `jo_ei_scans_in_flight` | gauge | `scanner` | Scans currently running. |
| `jo_ei_scan_queue_wait_seconds` | histogram | none | Time an antivirus scan waited for a concurrency slot. |
| `jo_ei_scan_concurrency_limit` | gauge | none | Configured maximum concurrent antivirus scans; 0 only when no antivirus engine is attached. |
| `jo_ei_scanner_up` | gauge | `scanner` | 1 when the last health check passed (ok or warn), 0 when it failed. Absent while unknown or disabled. |

`scanner` is `clamav`, `icap`, `osv` or `trivy`; `result` is `clean`,
`detected`, `timeout` or `error`. The concurrency limit and queue-wait metrics
apply to the antivirus engines (`clamav`, `icap`) only, see
`malware.max_concurrent_scans`. The `osv` scan metrics include in-memory TTL-cache
hits (the instrumented wrapper sits outside OSV's cache), so the `osv` rate is
inflated and its p95 is low.

### Verdicts and cache

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `jo_ei_verdicts_total` | counter | `ecosystem`, `verdict`, `gate` | Gate verdicts. |
| `jo_ei_cache_size_bytes` | gauge | none | Current cache size, read at scrape time. |
| `jo_ei_cache_max_bytes` | gauge | none | Configured cache size limit; absent when no limit is set. |

`ecosystem` is `pypi`, `npm`, `maven`, `rubygems`, `go`, `docker` or `other`
(Yarn traffic is reported as `npm`). `verdict` is `pass`, `cache`, `block`,
`error` or `other`. `gate` is the deciding gate: `cache`, `supply`, `cve`,
`malware`, `image_scan`, `none` or `other`.

### Build and runtime

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `jo_ei_build_info` | gauge | `version`, `commit`, `goversion` | Always 1. |
| `go_*` | various | | Go runtime: GC, memory and scheduler metrics. |
| `process_*` | various | | Standard process metrics (CPU, memory, file descriptors); Linux only. |

## Adding a metric

All metrics live in `internal/metrics`; no other package imports
`client_golang`. Other packages expose optional observer hooks (a func or a small
interface) and `cmd/jo-ei` wires them to the methods of `*metrics.Metrics`.
A nil `*Metrics` means metrics are disabled, so every method must be nil-safe.

1. Add the collector as an unexported field on a sub-struct of `Metrics` and
   register it in `New` (or a helper it calls) on `m.Registry`. Never use
   `prometheus.DefaultRegisterer` or global `MustRegister`.
2. Expose a nil-safe `Wrap*`/`Register*`/`Observe*` method that updates it.
3. Constrain every label value to a closed set with `oneOf`; build latency
   histograms with `newDurationHistogramOpts`.
4. Touch it in `newFullyWired` (`internal/metrics/metrics_test.go`) so the lint
   and drift tests see it.

Naming rules: prefix `jo_ei_`, base units (`_seconds`, `_bytes`), counters end in
`_total`. `TestLint` (promlint) fails on violations of these conventions, and the
asset drift test fails when the example alerts, the dashboard or this document
reference a metric that is not registered.
