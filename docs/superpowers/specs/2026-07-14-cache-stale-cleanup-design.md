# Cache: Drop TTL, Idle-Based Staleness, Manual Cleanup — Design

**Date:** 2026-07-14
**Status:** Approved

## Problem

1. Cache entries carry a hardcoded 24 h TTL (`internal/cache/factory.go`),
   not configurable. Its original purpose — scan-verdict freshness — is now
   fully covered by the re-validation sweep (gates re-run every
   `revalidate_after_hours`, failures evicted). Artifacts are immutable
   (versioned packages, digest-addressed blobs), so re-downloading on TTL
   expiry buys nothing.
2. Expired entries are never actually deleted. `Index.Get` returns a miss for
   an expired row but leaves the row and the artifact file on disk — the
   "dropped on access" comment is wrong. They linger until size-pressure
   eviction.
3. The console shows `reclaimable · expired N GB` but offers no way to
   reclaim it: no background purge, no endpoint, no button.

Note: eviction order was *not* a problem — `LRUCandidates` already orders by
`last_hit ASC` (true LRU); `last_hit` updates on every hit.

## Decisions (made during brainstorming)

- **Drop TTL entirely.** Verdict freshness is revalidation's job. When
  `cache.revalidation.enabled: false`, log a startup warning that cached
  artifacts are never rescanned.
- **"Old" = idle**: an entry is *stale* when `last_hit` is older than the new
  `cache.local.stale_after_days` (default 30; 0/absent → default at wiring,
  negative rejected by validation; no explicit "off" — the threshold only
  drives the metric and the manual purge).
- **Background behavior unchanged**: automatic deletion happens only under
  size pressure (existing LRU eviction). Stale entries are removed on demand
  via a console button.
- The `expired_bytes` metric (added earlier on this same unmerged branch)
  becomes `stale_bytes` — renamed in place, no compat shim needed.

## Design

### A. Remove TTL — `internal/cache/`

- `LocalCacheConfig`: delete `TTL`, add `StaleAfter time.Duration`.
- `CacheEntry`: delete `ExpiresAt` and `IsExpired()`.
- `Index.Get`: stop discarding expired rows.
- `Index.Insert`: keep the `expires_at` column (NOT NULL, no migration),
  write 0; nothing reads it anymore.
- `Index.DueForRevalidation`: drop the `expires_at > now` filter so
  previously-expired entries re-enter the revalidation pool (load stays
  bounded by `batch_size`).
- `factory.New`: build `StaleAfter` from config (default 30 days).
- `cmd/jo-ei/main.go`: when revalidation is disabled, warn:
  cached artifacts are never rescanned.

### B. Config — `internal/config/config.go`

```yaml
cache:
  local:
    stale_after_days: 30
```

- `LocalCache.StaleAfterDays int` (`mapstructure:"stale_after_days"`).
- Validation: negative → error. Zero → default 30 applied at wiring
  (same pattern as `RevalidationConfig`).
- Document in `config.yaml` comments and `docs/configuration.md`.

### C. Staleness metric — replaces expired metric

- `Index.StaleSizeBytes(cutoff int64)`: `SUM(size_bytes) WHERE last_hit <
  cutoff`. Replaces `ExpiredSizeBytes`.
- `CacheStats.StaleBytes` replaces `ExpiredBytes`; `LocalCache.Stats()`
  computes `cutoff = now − StaleAfter`.
- `/api/overview` cache envelope: `stale_bytes` and `stale_after_days`
  replace `expired_bytes`. The console is the only consumer and the old field
  never shipped to `main` — rename in place.

### D. Manual cleanup

- `Index.StaleCandidates(cutoff int64, n int)`: stale entries as
  `{Ref gate.PackageRef, SizeBytes int64}` pairs, oldest `last_hit` first —
  the size rides along so the purge can report freed bytes without a second
  lookup.
- `LocalCache.PurgeStale() (removed int64, freedBytes int64, err error)`:
  loop batches of candidates, reuse `Invalidate` (removes file + row), sum
  freed bytes from entry sizes; per-entry failures are skipped (same policy
  as `evictToSize`), only a failed candidate query aborts. SQLite's
  single-writer connection serializes purge with the eviction worker.
- Console (`internal/console/server.go`):
  - New optional `CachePurger` interface in server config
    (`PurgeStale() (removed, freedBytes int64, err error)`); `LocalCache`
    satisfies it.
  - `POST /api/cache/cleanup` → `200 {"removed": N, "freed_bytes": M}`;
    404 when no purger configured; 500 when the purge query fails. Auth via
    the existing middleware in `cmd/jo-ei`.
- The `evictions` counter is untouched — manual purge is not an LRU
  eviction; its result is reported via the toast.

### E. Console UI — LOCAL CACHE card

- Meter hatch = stale slice of used space (was: expired slice).
- Legend: `reclaimable · unused {stale_after_days}d+ · {n} GB`.
- `Clean up` button next to the legend, rendered only when stale bytes > 0;
  click → `POST /api/cache/cleanup` → toast `freed N GB, M objects` →
  refresh data.
- `web/console/src/api.js`: map `stale_gb`, `stale_after_days`; add
  `JOEI.cleanupCache()` POST helper.
- Rebuild committed bundle via `go generate ./...`.

### F. Workflow

- Continue on branch `feat/console-cache-cleanup` (the expired-bytes metric
  was built here and is not yet in `main`; reworking it to stale in the same
  branch avoids an add-then-rename PR sequence). PR into `main`.
- Run `golangci-lint run` before pushing.

### G. Changelog — `CHANGELOG.md` under `[Unreleased]`

- **Changed**: cache entries no longer expire on a fixed 24 h TTL — verdict
  freshness is handled by the re-validation sweep; entries idle longer than
  `cache.local.stale_after_days` (default 30) are reported as reclaimable.
- **Added**: `POST /api/cache/cleanup` and a console button to purge stale
  cache entries on demand.
- Amend/replace the earlier Unreleased wording about the expired-bytes
  meter treatment (same branch).

## Testing

- `internal/cache/index_test.go`: `StaleSizeBytes` sums only entries with
  old `last_hit`; `StaleCandidates` orders oldest-first and respects the
  limit; `Get` returns rows whose (legacy) `expires_at` is in the past;
  `DueForRevalidation` includes such rows.
- `internal/cache/local_internal_test.go`: `PurgeStale` deletes stale rows
  and artifact files, returns correct counts/bytes, leaves fresh entries;
  replace the `StatsReportsExpiredBytes` test with a `StaleBytes` one.
- `internal/config`: validation rejects negative `stale_after_days`.
- `internal/console/server_test.go`: cleanup endpoint happy path + no-purger
  404; overview envelope carries `stale_bytes` / `stale_after_days`.
- UI: manual verification (hatch, legend, button, toast, refresh).

## Files touched

- `internal/cache/cache.go` — CacheEntry/CacheStats changes
- `internal/cache/local.go` — TTL removal, StaleAfter, PurgeStale, Stats
- `internal/cache/index.go` — Get/Insert/DueForRevalidation, StaleSizeBytes,
  StaleCandidates
- `internal/cache/factory.go` — config wiring
- `internal/config/config.go` — `stale_after_days` + validation
- `cmd/jo-ei/main.go` — wiring, revalidation-off warning
- `internal/console/server.go` — CachePurger, cleanup endpoint, envelope
- `web/console/src/registries.jsx`, `web/console/src/api.js`,
  `web/console/screens.css` (if needed), `web/console/app.bundle.js`
- `config.yaml`, `docs/configuration.md`, `README.md` (if TTL mentioned),
  `CHANGELOG.md`
- Tests as listed above

API shape: `cache.expired_bytes` → `cache.stale_bytes` + `stale_after_days`
(pre-merge rename), one new endpoint `POST /api/cache/cleanup`. Schema:
unchanged (legacy `expires_at` column retained, written as 0).
