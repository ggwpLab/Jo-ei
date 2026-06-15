# Overview Daily Telemetry — Design

**Date:** 2026-06-15
**Status:** Approved

## Problem

Persistent telemetry already ships: the proxy stores per-UTC-day metrics in SQLite
and exposes them at `GET /api/metrics/daily?days=N` (newest-first). Nothing in the
console consumes this endpoint. The Overview is entirely "since start" (in-memory
counters that reset on restart), so operators cannot see day-over-day trends.

## Goal

Surface the daily metrics on the existing Overview screen as sparklines on the KPI
cards, with a 7-day / 30-day window toggle. No new screen.

Non-goals (YAGNI): a dedicated Trends screen, per-gate charts, arbitrary date
ranges, CSV export.

## Data shape

`GET /api/metrics/daily?days=30` returns:

```json
{
  "daily": [
    {
      "day": "2026-06-15",
      "requests": 1234,
      "cache_hits": 900,
      "blocked": 12,
      "errors": 3,
      "supply_blocked": 5,
      "cve_blocked": 4,
      "malware_blocked": 2,
      "denylisted": 1,
      "gates": { "cache": {"pass":0,"block":0}, ... }
    }
  ]
}
```

Rows are **newest-first**. When persistence is disabled (`database.path` empty),
the array is `[]`.

## Design

### Data layer — `web/console/api.js`

- Extend `load()`'s `Promise.all` with a sixth fetch:
  `getJSON("/api/metrics/daily?days=30")`.
  - `30` = the maximum the window toggle needs; the toggle slices this array
    client-side (last 7 or last 30), so flipping the window never refetches.
- Store on `window.JOEI.daily` as a **chronological (oldest-first)** array — the
  endpoint is newest-first, so reverse it. Sparklines render left→right in time
  order.
- Keep each row's raw counters (`day`, `requests`, `cache_hits`, `blocked`); the
  component derives series from them.
- Guard with `(resp.daily || [])`, matching the existing per-panel `|| []` pattern:
  a null/empty response degrades only the sparklines, never the whole `load()`.
- Initialize `J.daily = []` in the `window.JOEI` object literal so consumers can
  read it before the first load settles.

### Presentation — `web/console/overview.jsx`

- Local state `window` (`7 | 30`, default `30`).
- A small segmented toggle `[7d] [30d]` in the "Gate throughput" `section-head`.
- `const rows = JOEI.daily.slice(-win)` then build three series:
  - **Requests** card → `rows.map(r => r.requests)`
  - **Served from cache** card → per-day hit rate
    `rows.map(r => r.requests ? r.cache_hits / r.requests : 0)`, `sparkColor` jade.
  - **Blocked** card → `rows.map(r => r.blocked)`, `sparkColor` vermilion.
- "In quarantine" card is a live snapshot with no daily series → no sparkline
  (unchanged).
- Reuse the existing `KpiCard` `spark` / `sparkColor` props and the `Spark`
  component. No new chart component.

### Empty / no-history handling

- `Spark` breaks on an empty array (`Math.max(...[])` → `-Infinity`,
  division by `length - 1` → `-1`). So a sparkline is passed to a card **only when
  the series has ≥2 points**. With fewer, the card renders exactly as it does today
  (no `spark` prop).
- When `JOEI.daily` is empty (persistence off, or a brand-new DB), show a quiet
  one-line hint under the toggle:
  `no history yet · set database.path to persist daily metrics`. This explains the
  absence rather than leaving a silent gap.

### CSS — `web/console/screens.css`

- Minimal styles for the segmented `[7d][30d]` toggle, following existing `pill`
  / section-head conventions. No new color tokens.

## Testing

- The JS has no unit-test harness in this repo; logic is verified by running the
  console and exercising both window states and the empty-history case.
- `internal/console/server_test.go` already covers `/api/metrics/daily`; confirm
  it asserts the `{ "daily": [...] }` envelope shape the client now depends on,
  and extend it only if that assertion is missing.
- `web/web_test.go` confirms assets are served; no change needed for new JS unless
  a new file is added (it is not — edits to existing files only).

## Files touched

- `web/console/api.js` — fetch + store `JOEI.daily`
- `web/console/overview.jsx` — window toggle, sparkline series, empty hint
- `web/console/screens.css` — toggle styles
- `README.md` — note that the Overview shows daily-metric sparklines when
  persistence is enabled
- (test) `internal/console/server_test.go` — only if envelope assertion missing

Backend is untouched.
