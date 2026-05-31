# README Documentation Design

**Date:** 2026-05-31  
**Repo:** `sca-proxy/`  
**Output:** `sca-proxy/README.md`  
**Audience:** DevOps/Platform engineers (deploy & configure) + developers (understand block responses)  
**Language:** English  
**Style:** Practical — focus on doing, not exhaustive reference

---

## Goals

Single `README.md` at the root of `sca-proxy/`. A reader should be able to:

1. Understand what sca-proxy does in under 60 seconds.
2. Run it locally with `docker-compose up -d` and point `pip`/`npm` at it.
3. Know which config knobs matter and what they do.
4. Decode a 423 or 403 response and understand why a package was blocked.
5. Build and test from source.

---

## Structure (Story-driven, top-to-bottom)

### 1. Header + What it does

- One-line badge-free description.
- ASCII flow diagram (from spec): `Developer → SCA Proxy → Registry`.
- Three-bullet summary of what gets blocked and what gets cached.

### 2. Quick Start

For DevOps. Three numbered steps:

1. `git clone` + `docker-compose up -d` (pre-req: Docker only — no Go needed for this path)
2. Point pip / npm at the proxy (one-liner per ecosystem)
3. Smoke test: `pip install requests` should succeed; `curl localhost:8080/health` → `{"status":"ok"}`

No optional flags, no advanced config — just the path to working.

### 3. How it Works

Numbered pipeline showing what happens for every download request:

1. Cache lookup — served immediately on HIT
2. Supply Chain Filter — blocks packages published < 24 h ago (HTTP 423)
3. CVE Scan — queries osv.dev; blocks findings ≥ configured severity (HTTP 403)
4. Download + Cache — artifact saved for subsequent requests

One or two sentences per step. No subheadings needed.

### 4. Configuration Reference

Single table with columns `Key | Default | Description` covering the fields a new operator must understand:

| Key | Default | Description |
|-----|---------|-------------|
| `server.listen` | `:8080` | TCP address to listen on |
| `supply_chain.min_age_hours` | `24` | Minimum package age before serving |
| `supply_chain.mode` | `enforce` | `enforce` / `dry_run` / `off` |
| `cve.enabled` | `true` | Enable CVE scanning via osv.dev |
| `cve.block_on` | `HIGH` | Minimum severity to block (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`) |
| `policy.active_profile` | `production` | Active policy profile name |
| `policy.profiles.<name>.allowlist` | `[]` | Packages that bypass CVE + age checks (`pypi/requests` or `pypi/requests@2.31.0`) |
| `policy.profiles.<name>.denylist` | `[]` | Packages always blocked regardless of scan results |
| `cache.local.path` | `/var/cache/sca-proxy` | Directory for cached artifacts |
| `cache.local.max_size_gb` | `100` | Maximum cache size (LRU eviction) |

Note: all values overridable via `SCAPROXY_<KEY>` env vars (e.g. `SCAPROXY_SUPPLY_CHAIN_MODE=dry_run`).

### 5. Understanding Block Responses

Two annotated JSON examples:

**423 Locked — Supply Chain Filter:**
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

**403 Forbidden — CVE found:**
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
      "summary": "Requests Session object does not verify..."
    }
  ],
  "blocked_by": ["cve_scanner"],
  "request_id": "req_def456"
}
```

Brief explanation of each `reason` value and what to do (add to `allowlist`, wait until `block_until`, upgrade the package).

### 6. Building from Source

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"  # or however Go is installed
go build -o bin/sca-proxy ./cmd/sca-proxy
go test ./...
go test ./integration/... -tags integration
```

---

## What is NOT in this README

- Full admin API docs (`/admin/cache/stats`, allowlist management) — Phase 4
- Kubernetes deployment manifests — Phase 4
- Prometheus metrics reference — Phase 4
- ClamAV integration — Phase 3
- Multi-registry setup (npm, Maven, Go) — Phase 3

These are explicitly out of scope for this README because the features don't exist yet.

---

## Constraints

- No emojis.
- No badges (CI status, coverage) — the repo has neither configured yet.
- Keep the whole file under ~200 lines; configuration table is the densest part.
- Code blocks for every command — nothing prose-only for runnable instructions.
