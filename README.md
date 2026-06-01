# sca-proxy

A transparent supply chain security proxy for package registries. Supports PyPI, npm, and
Maven (Go support ships in a later phase).
Point your package manager at sca-proxy instead of the upstream registry — it intercepts
every download and enforces four layers of protection before serving the artifact.

```
Developer (pip/npm/mvn)
        │
        ▼
  ┌─────────────────────────────────────────────┐
  │               SCA Proxy :8080               │
  │  1. Cache lookup (HIT served immediately)   │
  │  2. Supply Chain Filter (24h rule)          │
  │  3. CVE Scanner (osv.dev)                   │
  │  4. Malware Scanner (ClamAV / ICAP)         │
  └─────────────────────────────────────────────┘
        │
        ▼
   Upstream registry (PyPI / npm / Maven)
```

**What gets blocked:**
- Packages published less than 24 hours ago (supply chain poisoning protection)
- Packages with CVE severity ≥ configured threshold (`HIGH` by default)
- Packages whose artifact matches a malware signature detected by any configured scanner
- Packages on the explicit `denylist`

**What gets cached:** Approved artifacts are stored locally; repeat requests are served
from cache without contacting the upstream registry.

## Quick Start

**Prerequisites:** Docker and Docker Compose (no Go installation required for this path).

**1. Start the proxy**

```bash
git clone <repo-url> && cd sca-proxy
docker-compose up -d
```

The proxy starts on `http://localhost:8080`. ClamAV runs as a sidecar in the compose file;
malware scanning is active when the selected policy profile sets `malware_block: true`.

**2. Point your package manager at the proxy**

pip:
```bash
pip install requests \
  --index-url http://localhost:8080/pypi/simple/ \
  --trusted-host localhost
```

Or persist it in `~/.pip/pip.conf`:
```ini
[global]
index-url = http://localhost:8080/pypi/simple/
trusted-host = localhost
```

npm:
```bash
npm install lodash --registry http://localhost:8080/npm/
```

Or persist it:
```bash
npm config set registry http://localhost:8080/npm/
```

**yarn** (uses the npm registry protocol via the `/yarn/` alias):
```bash
# Yarn Berry (v2+)
yarn config set npmRegistryServer http://localhost:8080/yarn/
# Yarn Classic (v1)
yarn config set registry http://localhost:8080/yarn/
```

**RubyGems / Bundler:**
```bash
# bundler
bundle config mirror.https://rubygems.org http://localhost:8080/rubygems
# or set the source in a Gemfile:
#   source "http://localhost:8080/rubygems"
```

**3. Smoke test**

```bash
# Health check
curl -s http://localhost:8080/health
# Expected: {"status":"ok"}

# Install a well-known package (should pass)
pip install requests==2.31.0 --index-url http://localhost:8080/pypi/simple/ --trusted-host localhost
```

## How it Works

Every package download goes through this pipeline:

1. **Cache lookup** — if the artifact was previously approved and cached, it is served
   immediately with `X-SCA-Proxy-Cache: HIT`. No upstream contact.

2. **Supply Chain Filter** — fetches version metadata from the upstream registry and checks
   `upload_time`. Packages published less than `supply_chain.min_age_hours` ago are rejected
   with HTTP **423 Locked**.

3. **CVE Scan** — queries [osv.dev](https://osv.dev) with the package name and version.
   If any finding meets or exceeds `cve.block_on` severity, the package is rejected with
   HTTP **403 Forbidden**. Results are cached in memory for `cve.cache_ttl_minutes`.

4. **Malware Scan** — the artifact is downloaded to a temp file and scanned by
   every configured engine in `malware.scanners[]` (native ClamAV `INSTREAM`, or
   any ICAP server such as Kaspersky / Dr.Web). If any engine reports a signature,
   the package is rejected with HTTP **403 Forbidden** (`reason: malware_found`)
   and the artifact is not cached.

5. **Cache + Serve** — a clean artifact is stored in the local cache and served to
   the client.

If any scanner is unreachable, the request is rejected (fail-closed). The proxy never serves
an artifact that has not been approved.

Index and metadata requests (e.g. `/simple/requests/` for pip) are proxied transparently
to the upstream registry without scanning or caching.

### Multiple upstreams per provider

Each provider accepts an ordered list of `upstreams`. For every request the proxy tries
them in order and uses the first that serves the artifact (Nexus-style sequential
fallback). Any failure — 404/410, 5xx, timeout, or connection refused — advances to the
next upstream. If every upstream returns 404/410 the client gets a 404; any other failure
mix yields a 502.

```yaml
registries:
  maven:
    enabled: true
    upstreams:
      - "https://repo1.maven.org/maven2"
      - "https://repo.spring.io/release"
  rubygems:
    enabled: true
    upstreams:
      - "https://rubygems.org"
```

## Configuration

The proxy reads `config.yaml` (default path, overridable with `--config`).
All values can be overridden with environment variables using the prefix `SCAPROXY_`
and `_` as separator (e.g. `SCAPROXY_SUPPLY_CHAIN_MODE=dry_run`).

| Key | Default | Description |
|-----|---------|-------------|
| `server.listen` | `:8080` | TCP address to listen on |
| `supply_chain.min_age_hours` | `24` | Minimum package age in hours before serving |
| `supply_chain.mode` | `enforce` | `enforce` blocks; `dry_run` logs only; `off` disables the filter |
| `cve.enabled` | `true` | Enable CVE scanning via osv.dev |
| `cve.block_on` | `HIGH` | Minimum severity to block: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `cve.cache_ttl_minutes` | `1440` | How long CVE scan results are cached in memory (minutes) |
| `policy.active_profile` | `production` | Name of the active policy profile |
| `policy.profiles.<name>.allowlist` | `[]` | Packages that bypass CVE and age checks. Format: `pypi/requests` (all versions) or `pypi/requests@2.31.0` (exact version) |
| `policy.profiles.<name>.denylist` | `[]` | Packages always blocked regardless of scan results. Same format as `allowlist` |
| `cache.local.path` | `/var/cache/sca-proxy` | Directory for cached artifacts |
| `cache.local.max_size_gb` | `100` | Maximum cache size; oldest entries evicted when exceeded (LRU) |

The full default configuration is in [`config.yaml`](./config.yaml).

## Understanding Block Responses

When the proxy rejects a request, it returns a structured JSON body. The `reason` field
tells you exactly why.

### 423 Locked — Supply Chain Filter

The package was published too recently.

```json
{
  "error": "package_blocked",
  "reason": "package_version_newer_than_24h",
  "package": "requests",
  "version": "2.32.0",
  "published_at": "2026-05-31T10:00:00Z",
  "block_until": "2026-06-01T10:00:00Z",
  "blocked_by": ["supply_chain_filter"],
  "request_id": "req_abc123"
}
```

**What to do:**
- Wait until `block_until` and retry.
- Or add the package to `policy.profiles.<name>.allowlist` to bypass the age check for
  trusted packages (e.g. internal packages, approved hotfixes).

### 403 Forbidden — CVE found

A known vulnerability meets or exceeds the configured severity threshold.

```json
{
  "error": "package_blocked",
  "reason": "cve_found",
  "package": "requests",
  "version": "2.28.0",
  "cves": [
    {
      "id": "CVE-2024-35195",
      "severity": "HIGH",
      "summary": "Requests Session object does not verify requests after making first request with verify=False"
    }
  ],
  "blocked_by": ["cve_scanner"],
  "request_id": "req_def456"
}
```

**What to do:**
- Upgrade to a version with no CVEs at or above the threshold.
- Or add the package+version to `allowlist` if the CVE has been reviewed and accepted
  as a known risk.

### 403 Forbidden — Denylist

```json
{
  "error": "package_blocked",
  "reason": "denylisted",
  "package": "evil-pkg",
  "version": "1.0.0",
  "blocked_by": ["policy_engine"],
  "request_id": "req_ghi789"
}
```

**What to do:** Remove the package from `policy.profiles.<name>.denylist` if it was added
in error, or use a different package.

### 403 Forbidden — Malware detected

The downloaded artifact matched a malware signature.

```json
{
  "error": "package_blocked",
  "reason": "malware_found",
  "package": "evil-pkg",
  "version": "1.0.0",
  "engine": "clamav",
  "signature": "Win.Trojan.Agent-123456",
  "blocked_by": ["malware_scanner"],
  "request_id": "req_jkl012"
}
```

**What to do:** Do not install this artifact. If you believe it is a false
positive, verify the package out-of-band and report the signature to your
security team before adding an `allowlist` entry.

## Building from Source

**Prerequisites:** Go 1.25+ (see [go.dev/dl](https://go.dev/dl/) for downloads)

```bash
# Download the latest stable Go from https://go.dev/dl/ and follow the install instructions.
# On Linux amd64 (adjust version as needed):
#   curl -fsSL https://go.dev/dl/go1.25.10.linux-amd64.tar.gz -o /tmp/go.tar.gz
#   mkdir -p ~/go-sdk && tar -C ~/go-sdk -xzf /tmp/go.tar.gz
#   export PATH="$HOME/go-sdk/go/bin:$PATH"

# Build
go build -o bin/sca-proxy ./cmd/sca-proxy

# Run
./bin/sca-proxy --config config.yaml

# Unit tests
go test ./...

# Integration tests (use in-process mocks; no external services required)
go test ./integration/... -tags integration
```
