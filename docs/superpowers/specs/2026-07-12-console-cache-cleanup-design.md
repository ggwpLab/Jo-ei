# Console Cleanup: "total" Labels, Cache Card Charts, Eviction Counter — Design

**Date:** 2026-07-12
**Status:** Approved

## Problem

1. The console still labels lifetime counters "since start". That wording dates
   from the in-memory telemetry era; counters now live in the SQLite `counters`
   table and survive restarts, so the label is wrong.
2. The LOCAL CACHE card on the Registries screen is number-only. The desired
   look (see `cache.bmp` mock) adds a hit-rate sparkline and an
   eviction-headroom treatment on the usage meter.
3. Bug: `LocalCache.Stats()` never fills `Evictions` — the API and console
   always show 0 LRU evictions. Nothing in the codebase counts evictions.

## Scope decisions (made during brainstorming)

- Sparkline uses the existing per-UTC-day metrics (`/api/metrics/daily`),
  window fixed at 30 days. No hourly telemetry, no per-day eviction column, no
  new endpoints — the mock's "24h" captions become honest "30d" / lifetime
  captions instead.
- Replacement wording for lifetime counters: **"total"**.
- The new eviction counter is in-memory (process-lifetime). Its caption is
  **"since restart"**, which is accurate for this one stat. Persisting it is
  out of scope.

## Design

### A. Label fixes — "since start" → "total"

`web/console/src/overview.jsx`:

- Section eyebrow: `Since start · uptime {uptime}` → `Totals · uptime {uptime}`.
- KPI card labels: `Requests · since start` → `Requests · total`;
  `Blocked · since start` → `Blocked · total`.
- "Served from cache" delta: `{n} hits since start` → `{n} hits total`.

`web/console/src/registries.jsx`:

- `Hit rate · since start` → `Hit rate · total`.
- `LRU evictions · since start` → `LRU evictions · since restart` (see B —
  this counter really is process-lifetime).

### B. Eviction counter — `internal/cache/local.go`

- Add `evictions atomic.Int64` to `LocalCache`.
- `evictToSize` increments it once per successfully deleted entry (index
  delete succeeded — count what actually left the cache).
- `Stats()` fills `CacheStats.Evictions` from the counter. `HitRatio` stays
  untouched (unused by the console; request-level hit rate comes from
  telemetry).
- The counter is in-memory and resets on restart — matching the
  "since restart" caption in A.

### C. Cache card charts — `web/console/src/registries.jsx` + `web/console/screens.css`

- **Sparkline** (top-right of the LOCAL CACHE card, as in the mock): reuse the
  global `Spark` component with the same per-day hit-rate series the Overview
  uses — `JOEI.daily.map(r => r.requests ? r.cache_hits / r.requests : 0)` —
  jade color, caption `hit rate · 30d`.
  - `JOEI.daily` is already fetched globally in `api.js` (oldest-first);
    no data-layer change.
  - Guard: render the sparkline only when the series has ≥ 2 points (`Spark`
    breaks on fewer — same guard the Overview uses). With < 2 points the card
    header renders as it does today.
- **Reclaimable (expired) segment** *(amended 2026-07-12 after review of the
  first iteration — the original "headroom = all free space" hatch was
  misleading, and the bare `⟍` glyph read as a stray backslash)*: the hatched
  segment shows the **expired slice of used space** — entries past their TTL,
  which are dropped on access, i.e. the bytes that would actually be
  reclaimed. Meter: solid jade = live bytes, hatch = expired bytes, dark =
  free. The caption becomes a legend entry: a small `.legend-chip` square
  filled with the same hatch pattern, followed by
  `reclaimable · expired {n} GB`. Segment and caption render only when
  expired bytes > 0.
  - Backend: `Index.ExpiredSizeBytes()` (`SUM(size_bytes) WHERE expires_at <
    now`), `CacheStats.ExpiredBytes`, and an `expired_bytes` field in the
    `/api/overview` cache envelope (additive only). `api.js` maps it to
    `JOEI.cache.expired_gb`.

### D. Build & workflow

- Rebuild the committed bundle: `go generate ./...` regenerates
  `web/console/app.bundle.js`; CI fails if it is stale.
- Feature branch, PR into `main`. Run `golangci-lint` locally before pushing.

### E. Changelog — `CHANGELOG.md` under `[Unreleased]`

- **Fixed**: cache LRU eviction counter always reported 0; evictions are now
  counted and shown in the console (since restart).
- **Changed**: console lifetime counters are labeled "total" (they persist in
  SQLite and survive restarts); the cache card gained a 30-day hit-rate
  sparkline and an eviction-headroom meter treatment.

## Testing

- `internal/cache/local_internal_test.go`: extend the existing
  `evictToSize` test (or add one) asserting the eviction counter equals the
  number of evicted entries and that `Stats()` reports it.
- `internal/console/server_test.go` already asserts `evictions` in the cache
  envelope via `fakeStats`; no change expected.
- JS has no unit harness: verify by running the console — labels, sparkline
  with ≥ 2 days of history, sparkline absence with < 2 days, hatched meter.

## Files touched

- `internal/cache/local.go` — eviction counter
- `internal/cache/local_internal_test.go` — counter test
- `web/console/src/overview.jsx` — labels
- `web/console/src/registries.jsx` — labels, sparkline, headroom caption
- `web/console/screens.css` — hatched meter, caption style
- `web/console/app.bundle.js` — regenerated
- `CHANGELOG.md` — Unreleased entries

Backend API shape: one additive field (`cache.expired_bytes` in
`/api/overview`); the `evictions` field finally carries a real value. No
schema migrations, no new endpoints.
