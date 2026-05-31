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
