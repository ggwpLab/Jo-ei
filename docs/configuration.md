# Configuration Reference

Jōei is configured by a single YAML file passed via `--config` (default in the
Docker image: `/etc/jo-ei/config.yaml`). The repository's
[`config.yaml`](../config.yaml) is a fully commented working example.

## Loading & environment overrides

Any config key can be overridden by an environment variable: take the key
path, replace dots with underscores, uppercase it, and prefix `JOEI_`.

| Config key | Environment variable |
|---|---|
| `logging.level` | `JOEI_LOGGING_LEVEL` |
| `cve.block_on` | `JOEI_CVE_BLOCK_ON` |
| `supply_chain.min_age_hours` | `JOEI_SUPPLY_CHAIN_MIN_AGE_HOURS` |

Only keys that appear in the YAML file can be overridden (the override
replaces the file's value; it cannot introduce a key the file omits).

Two special cases are read directly from the environment, not through this
mechanism:

- **`JOEI_CONSOLE_AUTH_USERS`** — console credentials as
  `username:bcrypt-hash`, multiple users separated by `;`. Merged with (and
  taking precedence over) `console.auth.users` from the file. Preferred over
  the file so password hashes stay out of version control.

Validation runs at startup; an invalid config prints the offending key and the
process exits non-zero.

## `server`

| Key | Default | Description |
|---|---|---|
| `listen` | — | Listen address, e.g. `":8080"`. |
| `upstream_max_concurrent` | `6` | Max concurrent in-flight requests **per upstream host** (metadata + transparent proxy + downloads combined). Keeps parallel dependency resolution under registry limits. |
| `upstream_rate_per_second` | `10` | Max request **rate** per upstream host (token bucket, burst = 2×). The primary defense against upstream HTTP 429. Set high to effectively disable. |

Upstream responses of 429/503 additionally trip a per-host circuit breaker
with exponential cooldown (1s–20s, honoring `Retry-After`).

## `registries`

Five fixed ecosystems: `pypi`, `npm`, `maven`, `rubygems`, `docker`. Each:

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Serve this ecosystem. An enabled registry **must** list at least one upstream. |
| `upstreams` | — | Upstream base URLs, tried in order (first success wins; failover on error). |

Client-facing paths: `/pypi/simple/…`, `/npm/…` (alias `/yarn/`),
`/maven/…`, `/rubygems/…`, and the Docker Registry v2 API (`/v2/…`) for use
as a `registry-mirrors` entry. Yarn uses the npm protocol; the `/yarn/` alias
exists so both package managers can be pointed at the proxy independently.

Docker caveats: multiple `upstreams` are supported as ordered failover
*mirrors of one registry* (e.g. Docker Hub plus a corporate pull-through
mirror of it) — do not mix different registries in one list, since the image
reference passed to Trivy is always built from the first upstream's host.
Also note the Docker daemon applies `registry-mirrors` only to Docker Hub
images; images from another upstream registry must be pulled explicitly as
`docker pull <proxy-host>/<repo>:<tag>`.

## `supply_chain`

The min-age gate: packages published less than `min_age_hours` ago are blocked
with HTTP 423 (Locked) until they age past the threshold.

| Key | Default | Description |
|---|---|---|
| `min_age_hours` | — | Minimum package age. `24` blocks day-old poisoning attacks. |
| `mode` | — | `enforce` (block), `dry_run` (log what would block, allow), `off`. |
| `allowlist_path` | — | Optional file of packages exempt from this gate (format below). |

Allowlist file format — one entry per line, `#` comments and blank lines
ignored:

```
# ecosystem/name         → all versions
pypi/requests
# ecosystem/name@version → one version
npm/lodash@4.17.21
```

The file seeds the **supply-chain** allowlist at first boot; after that the
per-gate allowlists (supply-chain and CVE) are edited in the console and
persist in the database.

## `cve`

Known-vulnerability gate backed by [osv.dev](https://osv.dev). Runs before the
artifact download; fails closed on scanner errors (HTTP 503).

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Query osv.dev for each package version. |
| `base_url` | `https://api.osv.dev` | OSV-compatible API endpoint. |
| `block_on` | — | Minimum severity that blocks: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. The active policy profile's `cve_min_severity` overrides this when set. |
| `cache_ttl_minutes` | `1440` | How long CVE scan results are cached in memory before re-querying osv.dev. Keep it at or below `cache.revalidation.cve_ttl_minutes` so lazy CVE re-checks see fresh data. |

## `image_scan`

Trivy is the engine behind the **CVE gate for Docker images** — the same gate
that osv.dev implements for package ecosystems, applied to a different
artifact type. The verdict is returned on the **manifest** request, so a
rejected image never reaches the client. Severity threshold and denylist come
from the same active policy profile as package CVE decisions.

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Scan images pulled through the Docker proxy. Requires `trivy_server`. |
| `trivy_server` | — | Trivy server URL, e.g. `http://trivy:4954`. |
| `timeout_seconds` | `120` | Per-scan timeout. |
| `scanners` | `vuln,secret` | Passed to Trivy `--scanners`. |
| `max_layer_bytes` | `0` (no limit) | Layers larger than this fail closed (block the image). The example config uses 2 GiB. |

## `malware`

Post-download antivirus gate. Zero scanners is valid — the gate is skipped.

| Key | Default | Description |
|---|---|---|
| `max_concurrent_scans` | `8` | Cap on simultaneous scans across all engines (backpressure; roughly clamd's default worker pool). |
| `scanners` | `[]` | List of engines, each: |

Per scanner:

| Key | Default | Description |
|---|---|---|
| `type` | — | `clamav` (clamd protocol) or `icap` (RFC 3507 — Kaspersky, Dr.Web, …). |
| `address` | — | `tcp:host:port` or `unix:///path/to/socket`. |
| `timeout_seconds` | `30` | Per-scan timeout. |
| `service` | — | ICAP service name (required for `icap`). |

All configured engines scan every artifact; any single detection blocks.
Malware verdicts cannot be allowlisted.

## `health`

Background liveness probes for socket scanners (clamd/ICAP), surfaced in the
console overview.

| Key | Default | Description |
|---|---|---|
| `probe_interval_seconds` | `30` | Probe frequency. |
| `slow_threshold_ms` | `2000` | Latency above this shows the scanner as "warn". |

## `cache`

| Key | Default | Description |
|---|---|---|
| `backend` | — | `local`. (`s3` is reserved and currently fails fast at startup.) |
| `local.path` | — | Directory for cached artifacts. |
| `local.max_size_gb` | — | Size cap; least-recently-used entries are evicted. |
| `local.stale_after_days` | `30` | Entries idle this long are stale: shown as reclaimable in the console and deleted by its Clean up button (`POST /api/cache/cleanup`). |

### `cache.revalidation`

Lazy per-gate re-validation. A cache hit whose CVE or malware check is older
than its TTL re-runs **only that gate** before serving — CVE against current
osv.dev data, malware by re-scanning the cached bytes; Docker re-runs the full
image gate when its verdict is older than the smaller enabled TTL. An entry
that now fails is blocked and evicted (index entry and binary). A temporarily
unreachable scanner (or scan infrastructure — Trivy, ClamAV, the verdict
store) serves the previously clean entry and retries on the next hit. For Docker, scan-infrastructure outages (Trivy, ClamAV) serve the stale
verdict. An unreachable upstream registry fails **by-tag** pulls (tag
resolution needs the upstream), but **by-digest** repeat pulls are served
from the cache: a fresh cached verdict is served without contacting the
upstream at all, and an expired one degrades to the stale verdict. Load is proportional to traffic,
not cache size.

| Key | Default | Description |
|---|---|---|
| `cve_ttl_minutes` | `1440` | Re-run the CVE gate on hits older than this. `0` disables. |
| `malware_ttl_minutes` | `1440` | Re-scan cached bytes on hits older than this. `0` disables. |

Note: the CVE scanner keeps its own in-memory result cache
(`cve.cache_ttl_minutes`). A newly published CVE becomes visible only after
both TTLs lapse, so keep `cve.cache_ttl_minutes` ≤ `cve_ttl_minutes`.

## `database`

Embedded SQLite (pure Go, no cgo). **Required** — telemetry, runtime policy
edits, and registry toggles persist here and survive restarts.

| Key | Default | Description |
|---|---|---|
| `path` | — (required) | Database file path. The parent directory is created if missing. |
| `event_retention_days` | `30` | Prune request events older than this. |
| `daily_retention_days` | `365` | Prune per-day metric rows older than this. |

## `policy`

Named profiles; `active_profile` selects one at boot.

| Key (per profile) | Description |
|---|---|
| `cve_block` | Enforce the CVE gate. |
| `cve_min_severity` | Blocking threshold; overrides `cve.block_on` when non-empty. |
| `supply_chain_block` | Enforce the min-age gate. |
| `malware_block` | Enforce the malware gate. |
| `allowlist` | Entries (`eco/name` or `eco/name@version`) that seed **both** per-gate allowlists (supply-chain and CVE). |
| `denylist` | Always-blocked packages, same entry format. |

The profile seeds the runtime policy on **first boot only**; after that the
console's policy editor is the source of truth (persisted in the database,
applied atomically without restart).

## `logging`

| Key | Default | Description |
|---|---|---|
| `level` | `info` (unknown values warn and fall back) | zerolog level: `trace`…`error`. |
| `format` | `json` | `json` or `text` (human-readable console writer). |
| `output` | `stderr` | `stdout`, `stderr`, or a file path (opened append). |

## `console`

| Key | Description |
|---|---|
| `auth.users` | List of `{username, password_hash}` (bcrypt). Prefer `JOEI_CONSOLE_AUTH_USERS`. |

Generate a hash: `printf '%s' 'your-password' | jo-ei hashpw`

**Fail-closed:** with zero users configured, `/console/` and `/api/` return
HTTP 503; the proxy data path and `/health` stay open.
