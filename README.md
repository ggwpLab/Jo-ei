# sca-proxy

A transparent supply chain security proxy for package registries (PyPI, npm, Maven, Go).
Point your package manager at sca-proxy instead of the upstream registry — it intercepts
every download and enforces three layers of protection before serving the artifact.

```
Developer (pip/npm/mvn)
        │
        ▼
  ┌─────────────────────────────────────┐
  │           SCA Proxy :8080           │
  │  1. Supply Chain Filter (24h rule)  │
  │  2. CVE Scanner (osv.dev)           │
  │  3. Local artifact cache            │
  └─────────────────────────────────────┘
        │
        ▼
   Upstream registry (PyPI / npm / …)
```

**What gets blocked:**
- Packages published less than 24 hours ago (supply chain poisoning protection)
- Packages with CVE severity ≥ configured threshold (`HIGH` by default)
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

The proxy starts on `http://localhost:8080`. ClamAV initialises its signature database on
first run — this takes ~60 seconds.

**2. Point your package manager at the proxy**

pip:
```bash
pip install requests \
  --index-url http://localhost:8080/simple/ \
  --trusted-host localhost
```

Or persist it in `~/.pip/pip.conf`:
```ini
[global]
index-url = http://localhost:8080/simple/
trusted-host = localhost
```

npm:
```bash
npm install lodash --registry http://localhost:8080/
```

Or persist it:
```bash
npm config set registry http://localhost:8080/
```

**3. Smoke test**

```bash
# Health check
curl -s http://localhost:8080/health
# Expected: {"status":"ok"}

# Install a well-known package (should pass)
pip install requests==2.31.0 --index-url http://localhost:8080/simple/ --trusted-host localhost
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

4. **Download + Cache** — the artifact is downloaded from the upstream registry, stored in
   the local cache, and served to the client.

If any scanner is unreachable, the request is rejected (fail-closed). The proxy never serves
an artifact that has not been approved.
