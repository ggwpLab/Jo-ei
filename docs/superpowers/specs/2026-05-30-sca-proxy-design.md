# SCA Proxy — Design Document

**Date:** 2026-05-30  
**Status:** Approved  
**Language:** Go 1.22+  
**Deployment:** Docker + Kubernetes  

---

## 1. Overview

SCA Proxy is a transparent forward proxy between developers and public package registries (PyPI, npm, Maven, Go). It intercepts every package download, applies a Supply Chain Filter (24h rule), scans for CVEs (osv.dev), scans for malware (ClamAV), enforces policy rules, caches artifacts, and logs everything.

Clients (pip, npm, mvn) require no changes — only the registry URL is updated to point to the proxy.

---

## 2. Architecture

```
[pip/npm/mvn] → [SCA Proxy :8080]
                    │
                    ├─ ProxyHandler (net/http)
                    │   └─ RegistryAdapter (PyPI/npm/Maven/Go)
                    │
                    ├─ ScanPipeline
                    │   ├─ SCFilter     (sync, metadata-only)
                    │   └─ [CVEScanner || AVScanner]  ← goroutines (errgroup)
                    │
                    ├─ Cache (Local FS + SQLite index | S3)
                    │
                    ├─ PolicyEngine  (YAML hot-reload via viper)
                    │
                    └─ AuditLog + Prometheus Metrics + Alerting
```

Single binary, single port `:8080`. Registry adapter is selected per-request: the proxy inspects the `Host` header (e.g. `pypi.proxy.internal:8080`) or a configurable path prefix (`/pypi/`, `/npm/`) depending on the `routing_mode` config setting (`host` | `path`). Clients are configured to point to the corresponding URL.

---

## 3. Request Lifecycle

### Cache miss (new package)

1. `ProxyHandler` intercepts `GET /pypi/requests/2.32.0/...`
2. `RegistryAdapter` normalizes → `PackageRef{Ecosystem, Name, Version}`
3. `Cache.Get()` → miss
4. `SCFilter.Check()` (sync) — fetches upstream metadata, checks publication age
   - age < 24h AND not in allowlist → **423 Locked**, log, optional alert
   - OK → continue
5. `Upstream.Download()` → artifact streamed to temp file on disk (`os.CreateTemp`)
6. `go CVEScanner.Scan(ctx, ref, tmpPath)` and `go AVScanner.Scan(ctx, ref, tmpPath)` start simultaneously via `errgroup`
   - First non-clean result → `context.Cancel()` stops the other scanner
   - Both clean → merge OK
7. `Cache.Put()` — saves artifact + scan result + TTL
8. `AuditLog.Record()` — JSON-line to stdout
9. Respond → `200 OK` + stream artifact

### Cache hit

1–3. Same as above  
4. `Cache.Get()` → hit with `scan_result = clean` and entry within TTL  
5. `SCFilter.Check()` still runs (metadata-only, no re-download) — package may have entered denylist since caching  
6. Respond → `200 OK` + stream from cache  
   Target latency: < 100ms

---

## 4. Component Interfaces

### RegistryAdapter

```go
type RegistryAdapter interface {
    Name() string                              // "pypi", "npm", "maven", "go"
    NormalizeRequest(r *http.Request) (*PackageRef, bool)
    FetchMetadata(ctx context.Context, ref *PackageRef) (*PackageMetadata, error)
    DownloadURL(ref *PackageRef) string
}

type PackageRef struct {
    Ecosystem string
    Name      string
    Version   string
}

type PackageMetadata struct {
    PublishedAt time.Time
    Maintainer  string
    License     string
    Checksum    string
}
```

Registries: `pypi.go`, `npm.go`, `maven.go`, `goproxy.go` — each independently testable.

### Scanner

```go
type Scanner interface {
    Name() string
    // artifactPath is a path to a temp file on disk — avoids buffering large
    // artifacts (e.g. .jar) in RAM across 1000+ concurrent requests.
    // ClamAV clamd supports SCAN /path natively; osv.dev uses ref only.
    Scan(ctx context.Context, ref *PackageRef, artifactPath string) (*ScanResult, error)
}

type ScanResult struct {
    Clean    bool
    Findings []Finding
    CachedAt time.Time
}

type Finding struct {
    Type     string   // "cve" | "malware"
    ID       string   // CVE-2026-12345 | signature name
    Severity string   // CRITICAL | HIGH | MEDIUM | LOW
    Summary  string
    Score    float64  // CVSS
}
```

`ScanPipeline` runs `CVEScanner` and `AVScanner` via `golang.org/x/sync/errgroup`. On first block → `context.Cancel()`.

### Cache

```go
type CacheEntry struct {
    ArtifactPath string
    Scan         *ScanResult
    StoredAt     time.Time
    ExpiresAt    time.Time
    HitCount     int64
}

type Cache interface {
    Get(ref *PackageRef) (*CacheEntry, bool)
    // Put stores the artifact at artifactPath (temp file) into the cache store.
    Put(ref *PackageRef, artifactPath string, scan *ScanResult) error
    Invalidate(ref *PackageRef) error
    Stats() CacheStats
}
```

**Local backend:** artifacts on filesystem at `SHA256(ecosystem+name+version)` path; SQLite index tracks LRU ordering, TTL, hit count, eviction. Max 100GB with auto-eviction.  
**S3 backend:** `aws-sdk-go-v2` with MinIO-compatible endpoint. Used for clustered deployments.  
Both backends implement the same `Cache` interface — selected via `config.yaml`.

### PolicyEngine

Loads `config.yaml` via `viper.WatchConfig()` (hot-reload without restart). Three checks per request:

- `IsAllowlisted(ref)` → disable SC Filter for this package
- `IsDenylisted(ref)` → immediate 403 block
- `Profile(name).ShouldBlock(finding)` → dev / staging / production severity thresholds

### AuditLog + Metrics + Alerting

- `zerolog` → structured JSON-lines to stdout; optionally to OpenSearch/Loki
- Prometheus counters/histograms via `/metrics` endpoint:
  - `sca_requests_total{ecosystem,result}`
  - `sca_scan_duration_seconds{scanner}`
  - `sca_cache_hits_total`, `sca_cache_size_bytes`
  - `sca_blocks_total{reason}`
- Alerting: dedicated goroutine consumes blocking channel, dispatches to Slack/Telegram webhooks for `cve_critical` and `malware_detected` events

---

## 5. Error Handling & Fail-Closed

If any external component is unavailable, the request is blocked:

| Failure | Response |
|---|---|
| ClamAV socket timeout / error | 503 + `av_scanner_unavailable` |
| osv.dev API error | 503 + `cve_scanner_unavailable` |
| Upstream registry down + cache miss | 502 + `upstream_unavailable` |
| Upstream registry down + cache hit | 200 from cache (NFR-02) |
| SQLite I/O error | 503 + `cache_error` |
| Version < 24h (enforce mode) | 423 Locked |
| CVE found (above threshold) | 403 Forbidden |
| Malware found | 403 Forbidden |
| Denylist match | 403 Forbidden |

`dry_run` mode: all blocks are logged but requests pass through.

Every blocked response includes a JSON body with `request_id` (UUID per request), `package`, `version`, `reason`, `blocked_by`, `policy_profile`.

---

## 6. Project Structure

```
sca-proxy/
├── cmd/sca-proxy/main.go
├── internal/
│   ├── proxy/
│   │   ├── handler.go           # HTTP handler, request interception
│   │   ├── adapter.go           # RegistryAdapter interface
│   │   └── adapters/
│   │       ├── pypi.go
│   │       ├── npm.go
│   │       ├── maven.go
│   │       └── goproxy.go
│   ├── scanner/
│   │   ├── scanner.go           # Scanner interface + ScanPipeline (errgroup)
│   │   ├── cve.go               # CVEScanner: osv.dev API + optional NVD
│   │   ├── malware.go           # AVScanner: ClamAV unix socket
│   │   └── virustotal.go        # Optional VirusTotal client
│   ├── supplychain/
│   │   ├── filter.go            # SCFilter: 24h rule
│   │   └── metadata.go          # Package metadata fetcher per ecosystem
│   ├── cache/
│   │   ├── cache.go             # Cache interface
│   │   ├── local.go             # Local FS + SQLite LRU
│   │   ├── s3.go                # S3-compatible backend
│   │   └── index.go             # SQLite schema + queries
│   ├── policy/
│   │   ├── engine.go            # PolicyEngine: hot-reload viper
│   │   ├── config.go            # YAML config loader
│   │   └── rules.go             # Allowlist, denylist, license, profile
│   ├── audit/
│   │   ├── logger.go            # zerolog structured logging
│   │   ├── metrics.go           # Prometheus metrics
│   │   └── alert.go             # Slack/Telegram alerting
│   └── config/
│       └── config.go            # Global config struct
├── pkg/scaproxy/client.go       # Optional public client library
├── config.yaml
├── Dockerfile
├── docker-compose.yaml
├── k8s/
│   ├── deployment.yaml
│   ├── service.yaml
│   └── configmap.yaml
├── Makefile
└── go.mod
```

---

## 7. Testing Strategy

### Unit tests (target >85% coverage)

- `SCFilter`: boundary cases 23h59m / 24h01m / allowlist bypass / dry_run
- `PolicyEngine`: all allowlist/denylist/profile combinations
- `Cache`: hit / miss / eviction / LRU ordering / TTL expiry / concurrent access
- Each adapter: URL normalization → `PackageRef`
- `ScanPipeline`: context cancellation on first block, errgroup propagation

### Integration tests

- `httptest.Server` mock upstream (test PyPI / verdaccio for npm)
- Full pipeline: request → scan → cache → response
- Fail-closed: ClamAV socket unavailable → 503
- Fail-closed: osv.dev mock returns 500 → 503
- Cache fallback: upstream down + cache hit → 200

### Load tests

- k6 scripts: 1000 concurrent clients
- P50 / P95 / P99 latency, cached vs uncached
- Memory profiling under load

### Security tests

- Path traversal in cache keys (SHA256-keyed paths mitigate this)
- TLS 1.3 only (no TLS 1.0/1.1/1.2 fallback)
- Dependency scan: grype / trivy on the Docker image

---

## 8. Deployment

### Docker

Distroless base image, target < 20MB. ClamAV runs as sidecar container (clamd daemon accessible via unix socket mounted as shared volume).

```yaml
# docker-compose.yaml (dev)
services:
  sca-proxy:
    build: .
    ports: ["8080:8080"]
    volumes:
      - clamav-socket:/var/run/clamav
      - ./config.yaml:/etc/sca-proxy/config.yaml
      - cache-data:/var/cache/sca-proxy
  clamav:
    image: clamav/clamav:latest
    volumes:
      - clamav-socket:/var/run/clamav

volumes:
  clamav-socket:
  cache-data:
```

### Kubernetes

`Deployment` + `Service` + `ConfigMap` for config.yaml. ClamAV as sidecar container in the same Pod sharing a `emptyDir` volume for the clamd socket. HPA on `sca_requests_total` rate metric.

---

## 9. Key Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | Go 1.22+ | Performance, stdlib HTTP proxy, goroutines |
| Scan pipeline | Parallel fan-out (errgroup) | ~50% lower latency vs sequential |
| CVE source | osv.dev + optional NVD mirror | Free, open, multi-source |
| AV scanner | ClamAV unix socket | Free, open-source, sidecar-friendly |
| Cache index | SQLite | No external deps, LRU support, fast |
| Config | viper + YAML hot-reload | No restart needed for policy changes |
| Fail mode | Fail-closed | Supply chain security is primary concern |
| Proxy model | Pull-through (not full mirror) | Scans only what is actually requested |
