# Lazy TTL Re-validation — Design

**Date:** 2026-07-18
**Status:** Approved
**Stage:** OSS release preparation

## Problem

The background re-validation sweep (`internal/revalidate`, spec
`2026-06-28-cache-revalidation-design.md`) re-runs the gates over the whole
cache on a timer. Its load is proportional to **cache size**, not to traffic:
at ~5 000 entries a sweep pass is fine; at ~100 000 entries each pass burns
scanner capacity (clamd, Trivy, osv.dev) re-checking artifacts nobody is
pulling, and the batch/interval tuning becomes a moving target.

## Goal

Replace the timer sweep with **lazy per-gate TTL re-validation on the serve
path**: a cache hit whose CVE or malware check has expired re-runs *only the
expired gate* against the already-cached bytes/metadata before serving. A
now-failing entry is blocked and evicted (index row + binary on disk). Load is
proportional to traffic; an artifact nobody requests is never re-scanned.

Decisions fixed during brainstorming:

1. **Lazy re-check on access** — no re-download from upstream; CVE re-check is
   metadata-only, malware re-check scans the cached file.
2. **Scanner outage → serve stale**: the previously-clean cached artifact is
   served, the check timestamp is not bumped, the next hit retries. Mirrors
   the old sweep's `Retry`.
3. **Config:** `cache.revalidation.cve_ttl_minutes` and
   `cache.revalidation.malware_ttl_minutes`, default 1440 each, explicit `0`
   disables that gate's re-check. Old sweep keys are removed.
4. **Docker:** the image verdict expires by `min` of the enabled TTLs and is
   re-evaluated by the full manifest gate (existing `skipVerdictCache` path).
5. **Blocking re-check**: the request waits for the re-check; past its TTL no
   artifact is served without a fresh verdict (except the scanner-outage
   stale case above).

Non-goals: changing the miss/first-fetch pipeline; per-layer Docker blob
re-checks (the manifest is the gate); reworking idle-entry cleanup
(`stale_after_days` is orthogonal and stays).

## Architecture

No new packages. The re-check logic lives where the serve decisions already
are: `internal/proxy/handler.go` for package ecosystems and
`internal/proxy/dockerproxy/gate.go` for images. `internal/revalidate` is
deleted.

### Storage (`internal/cache`)

- **Schema:** replace `last_validated` with two columns:
  `last_cve_check INTEGER NOT NULL DEFAULT 0` and
  `last_malware_check INTEGER NOT NULL DEFAULT 0`.
  Migration (same pattern as `migrateLastValidated`): add both columns,
  backfill from `last_validated` (falling back to `stored_at` where 0), then
  drop `last_validated` (SQLite ≥3.35 `ALTER TABLE … DROP COLUMN`,
  supported by modernc.org/sqlite).
- **`Insert`/`Put`:** both check columns start at `stored_at` — a freshly
  cached entry was just fully checked.
- **New methods:** `MarkCVEChecked(ref, ts)` and
  `MarkMalwareChecked(ref, ts)` (UPDATE one column).
- **Removed:** `DueForRevalidation`, `MarkValidated`, `RevalEntry`,
  `internal/cache/reval.go`.
- **`gate.ArtifactEntry`** gains `LastCVECheck time.Time` and
  `LastMalwareCheck time.Time`; `Get` populates them. The `ArtifactCache`
  interface gains the two `Mark*` methods (implemented by `LocalCache`;
  the handler treats them as best-effort — a failed bump is logged, never
  fails the request).

### Package serve path (`internal/proxy/handler.go`)

Current cache-hit branch (`handler.go:96`) serves immediately. New order on a
hit:

1. `!entry.ScanClean` → 403 `scan_failed` (unchanged).
2. **CVE re-check** — if `cveTTL > 0 && now-entry.LastCVECheck > cveTTL` and
   `CVEScanner`+`Policy` are non-nil:
   - `Scan` error → `log.Warn`, serve stale, timestamp untouched.
   - `Evaluate` not allowed → `Cache.Invalidate(ref)` (index row + file),
     record `BLOCK`/`GateCVE` with the live request's `request_id`,
     `BlockedBy` `cve`|`denylist`, findings attached;
     `writeCVEBlockedResponse`; return.
   - clean → `MarkCVEChecked(now)`.
3. **Malware re-check** — if `malwareTTL > 0 && now-entry.LastMalwareCheck >
   malwareTTL` and `AVScanner` non-nil: `Scan(entry.ArtifactPath)`.
   - error (clamd down, file unreadable) → serve stale.
   - infected → `Invalidate`, record `BLOCK`/`GateMalware` (engine,
     signature), 403 `malware_found`; return.
   - clean → `MarkMalwareChecked(now)`.
4. Serve from cache + `CACHE` event (unchanged).

CVE before malware: cheap metadata check short-circuits before the byte scan.
The supply-chain time rule is not re-run (a cached entry has matured; denylist
changes are caught by the policy step). TTLs reach the handler via two new
`HandlerConfig` fields (`CVERecheckTTL`, `MalwareRecheckTTL time.Duration`).

### Docker (`internal/proxy/dockerproxy`)

- `verdictStore.GetImageVerdict` additionally returns the verdict's last-check
  time (`min` of the entry's two check columns — they move together for
  Docker).
- `gateDeps` gains `recheckTTL time.Duration` = `min` of the enabled TTLs
  (0 when both disabled → cached verdicts never expire).
- In `evaluate` (`gate.go:110`): the cached-verdict short-circuit now also
  requires `recheckTTL == 0 || age <= recheckTTL`. An expired verdict falls
  through to the full pipeline (supply chain + Trivy + ClamAV) — the same
  path `skipVerdictCache` forces today.
- Fresh re-eval of a previously cached image:
  - **clean** → `PutImageVerdict` overwrites the entry (check columns reset
    via `Put`), serve.
  - **blocked** → before overwriting, cascade-invalidate the old manifest's
    config/layer blobs (`manifestBlobDigests` moves from `revalidate.go` into
    `gate.go`), store the blocked verdict, 403. The binary blobs are gone.
  - **infra error** (Trivy, clamd, verdict store) → serve the stale cached
    verdict, timestamps untouched — mirrors the package path's serve-stale
    rule. This is a new fallback branch: on `evaluate` error with a cached
    clean verdict present, return that verdict instead of failing closed.
    Exception: `FetchManifest` (the upstream registry) runs before the cached
    verdict is even consulted, so an unreachable upstream still fails the
    pull closed.
    (Superseded for digest refs by
    `2026-07-19-recheck-coalescing-offline-digest-design.md`: a by-digest
    pull consults the cached verdict before the fetch and survives an
    unreachable upstream.)
- Blobs have no independent TTL: a blob is owned by its image and is
  re-validated transitively when the manifest verdict expires. Direct blob
  hits serve as today.
- `dockerproxy/revalidate.go` + `revalidate_test.go` are deleted.
- `FromCache` semantics unchanged: `true` only when the verdict was served
  from a still-fresh cached decision (repeat pulls log `CACHE`); a lazy
  re-eval that passes logs `PASS`.

### Sweep removal

- Delete `internal/revalidate/` entirely (sweeper, package revalidator,
  tests).
- Delete the sweeper wiring block in `cmd/jo-ei/main.go`; instead pass the
  two TTLs into the package handler config and docker gate deps.
- `integration/revalidate_test.go` is rewritten against the lazy model (see
  Testing).

## Configuration

```yaml
cache:
  revalidation:
    cve_ttl_minutes: 1440      # 0 disables CVE re-checks on cache hits
    malware_ttl_minutes: 1440  # 0 disables malware re-scans on cache hits
```

- `RevalidationConfig` becomes `{CVETTLMinutes, MalwareTTLMinutes int}`.
- Defaults via `viper.SetDefault` (key absent → 1440; explicit `0` →
  disabled). Negative values rejected by `Validate`.
- Removed keys: `enabled`, `interval_minutes`, `revalidate_after_hours`,
  `batch_size`. Old configs still start (viper ignores unknown keys);
  CHANGELOG documents the behavioral change.

**Interplay:** the CVE scanner keeps its own in-memory result cache
(`cve.cache_ttl_minutes`, default 1440). A re-check that hits a cached osv.dev
result learns nothing new — a fresh CVE becomes visible only after **both**
TTLs lapse (worst case ≈ their sum). Documented recommendation:
`cve.cache_ttl_minutes` ≤ `cache.revalidation.cve_ttl_minutes`.

## Telemetry

Lazy-re-check blocks record a normal `BLOCK` event with the live request's
`request_id` (not the sweep's synthetic `"revalidation"`), `Gate`
`cve`/`malware` (packages) or `image_scan`/`malware` (Docker, via
`gateForBlockedBy`), findings/engine/signature attached. The console feed and
quarantine view work unchanged.

## Error handling

| Situation | Outcome |
|-----------|---------|
| CVE re-check: finding above threshold / denylisted | 403 + evict (row + file) |
| Malware re-check: infected | 403 + evict (row + file) |
| Docker re-eval blocks | 403 + blocked verdict + cascade blob invalidation |
| Scanner unreachable / infra error | serve stale, timestamp untouched, retry next hit |
| Docker: upstream registry unreachable (`FetchManifest`) | fails the pull closed — runs before the cached verdict is consulted, not covered by stale-serve |
| Cached file missing at malware re-scan | scan errors → serve-stale path → `serveFromCache` misses → existing `cache_read_error` handling |
| TTL = 0 (disabled) | that gate is never re-checked on hits |
| `Mark*Checked` update fails | log warn, serve anyway (best-effort bump) |

## Documentation changes

- `docs/configuration.md`:
  - `cache.revalidation` table → the two TTL keys, defaults, `0` semantics,
    the osv-result-cache interplay note.
  - `image_scan` section reworded: Trivy is the **engine of the CVE gate for
    Docker images** — same gate as osv.dev for packages, different engine —
    not a separate kind of check.
  - `cve.cache_ttl_minutes` note updated (the artifact cache now *does*
    re-check by TTL).
- `docs/architecture.md`: sweep references → lazy TTL re-validation; Docker
  verdict caching paragraph gains "until TTL".
- `README.md`: replace sweep mentions with lazy TTL re-validation.
- `CHANGELOG.md`: breaking-ish entry (sweep removed, new keys, old keys
  ignored).

## Testing

- **Index (unit, real SQLite):** migration adds both columns, backfills from
  `last_validated`/`stored_at`, drops `last_validated`; `Mark*Checked` update
  one column; `Get` returns the timestamps; fresh `Insert` sets both to
  `stored_at`.
- **Handler (unit, fake cache/scanners):** expired CVE → re-scan, block,
  entry+file gone, `BLOCK/cve` event; expired malware → block, file gone,
  `BLOCK/malware` event; both fresh → no scanner calls, `CACHE` event; clean
  re-check → timestamp bumped, served; scanner error → served stale, no bump;
  TTL 0 → no re-check; nil scanner → skipped.
- **Docker gate (unit, stub scanner/store):** fresh verdict → `FromCache`
  short-circuit, no scan; expired verdict → full re-eval; re-eval block →
  cascade blob invalidation + 403; re-eval infra error → stale verdict
  served; both TTLs 0 → never expires.
- **Integration (`-tags=integration`):**
  - *Package:* cache a clean artifact, rewind `last_malware_check` (and
    separately `last_cve_check`), swap in an infected-stub AV / CVE-finding
    stub, GET again → 403, binary gone from disk, BLOCK event recorded.
  - *Docker:* cache a clean image verdict, rewind its check columns, swap the
    image scanner for a blocking stub, pull manifest again → 403, manifest +
    layer blob cache entries gone.

## Files touched

- `internal/cache/index.go` — schema, migration, `Mark*Checked`, drop reval queries
- `internal/cache/local.go`, `internal/cache/reval.go` (deleted), `internal/cache/cache.go`
- `internal/gate/cache.go` — `ArtifactEntry` timestamps, `ArtifactCache.Mark*`
- `internal/proxy/handler.go` — lazy re-check on cache hit
- `internal/proxy/dockerproxy/gate.go` — verdict TTL, cascade on block, stale-on-error
- `internal/proxy/dockerproxy/blobcache.go` — `GetImageVerdict` age
- `internal/proxy/dockerproxy/revalidate.go` — deleted
- `internal/revalidate/` — deleted
- `internal/config/config.go` — new `RevalidationConfig`, viper defaults, validation
- `cmd/jo-ei/main.go` — wire TTLs, remove sweeper
- `config.yaml`, `docs/configuration.md`, `docs/architecture.md`, `README.md`, `CHANGELOG.md`
- `integration/revalidate_test.go` — rewritten
- tests alongside each
