# Monitoring examples

Starter assets for the Prometheus metrics Jō-ei exposes on its dedicated
metrics listener (`metrics.listen`, default `:9464`, path `/metrics`).

| File | Purpose |
|---|---|
| [`prometheus.yml`](prometheus.yml) | Minimal scrape config: job `jo-ei` scraping `jo-ei:9464`, loading `alerts.yml` |
| [`alerts.yml`](alerts.yml) | Alert rule group `jo-ei` (down, 5xx ratio, latency, upstream/circuit, scanners, FDs, cache) |
| [`grafana/jo-ei-dashboard.json`](grafana/jo-ei-dashboard.json) | Importable Grafana dashboard (uid `jo-ei-overview`) |

## Wiring into an existing stack

1. **Scrape.** Add the `jo-ei` job from `prometheus.yml` to your Prometheus
   config and adjust the target. The metrics port is not the proxy port; keep
   it on an internal network and do not publish it.
2. **Alerts.** Copy `alerts.yml` next to your Prometheus config, list it under
   `rule_files`, and reload. The rules assume the scrape job is named `jo-ei`
   (`JoEiDown` matches `up{job="jo-ei"}`). Thresholds are starting points.
   Validate with `promtool check rules alerts.yml`.
3. **Dashboard.** In Grafana choose Dashboards, then Import, upload
   `grafana/jo-ei-dashboard.json`, and pick your Prometheus data source for
   `DS_PROMETHEUS`. Use the `job`, `instance` and `route` variables to filter.

A drift test (`internal/metrics/assets_test.go`) fails if the alerts or
dashboard reference a metric that Jō-ei does not register.
