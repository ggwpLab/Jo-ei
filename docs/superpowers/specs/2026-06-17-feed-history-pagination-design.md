# Feed History Pagination — Design

**Date:** 2026-06-17
**Status:** Approved

## Problem

The console Request feed only ever holds a recent window of traffic. `load()`
fetches `GET /api/requests?limit=500`, the client keeps at most 500 events in
`JOEI.requests`, and the feed component renders only `slice(0, 120)`. The
verdict filter chips (`All` / `Blocked` / `Passed` / `Cache`) filter that small
client-side window — they do **not** query history.

Consequently an operator cannot review all blocked or errored requests: a
`BLOCK` or `ERROR` that scrolled past the 500-event window is unreachable from
the UI. There is also no `Error` filter chip at all, even though `ERROR` is a
first-class verdict (`internal/proxy/recorder.go`).

## Goal

Let operators page through the **entire history** of blocked and errored
requests, backed by SQLite, while keeping the live stream behavior for normal
traffic.

Non-goals (YAGNI):
- Server-side history paging for `Passed` / `Cache` (those stay live-only).
- Server-side full-text search; search stays client-side over loaded rows.
- Numbered pages / jump-to-page; only "Show more" forward paging.
- Date-range pickers, CSV export, a separate "Incidents" screen.

## Verdicts

Four verdicts exist (`internal/proxy/recorder.go`): `PASS`, `CACHE`, `BLOCK`,
`ERROR`. Only `BLOCK` and `ERROR` get history-browse mode.

## UI behavior (`web/console/feed.jsx`)

- Add an **`Error`** filter chip. New chip set:
  `All` / `Blocked` / `Passed` / `Cache` / `Error`.
- **Live-window filters** (`All`, `Passed`, `Cache`): unchanged. Source is
  `JOEI.requests` (`slice(0, 120)`), SSE prepends live events, client-side
  filter + search as today.
- **History filters** (`Blocked`, `Error`): the feed switches to **history
  mode**:
  - Live prepending is paused automatically while one of these filters is
    active (independent of the manual Pause button).
  - First page is fetched from the server:
    `GET /api/requests?verdict=BLOCK&limit=50`.
  - Rows render newest-first; a **"Show more"** button below the table loads the
    next page via the returned cursor and appends rows to the bottom.
  - When the server returns an empty `next_cursor`, the button is hidden
    ("no more").
  - Switching back to `All` (or `Passed`/`Cache`) restores live mode and
    re-syncs from `JOEI.requests`.
- Search box `q` in history mode filters only already-loaded rows (documented
  limitation; not sent to the server).
- The empty state is reused when the first page is empty.

## Backend API (`internal/console/server.go`)

`GET /api/requests` is extended, backward-compatibly:

| Param    | Meaning                                                            |
|----------|-------------------------------------------------------------------|
| `limit`  | Page size (existing; default 100).                                |
| `verdict`| Optional. One of `PASS` / `CACHE` / `BLOCK` / `ERROR`. Empty = no filter (current behavior). |
| `cursor` | Optional opaque keyset cursor `"<unixMillis>:<id>"` from the previous page's `next_cursor`. |

Response gains `next_cursor`:

```json
{
  "requests": [ /* eventJSON, newest-first */ ],
  "next_cursor": "1718600000000:4213"
}
```

`next_cursor` is `""` when the last row of the result is the end of the data
(i.e. fewer than `limit` rows returned).

Backward compatibility: the existing `load()` call `?limit=500` (no `verdict`,
no `cursor`) returns the same `requests` array as today. The added
`next_cursor` field is ignored by the current client path.

Validation (consistent with existing `invalid_limit`):
- unknown `verdict` → `400 {"error":"invalid_verdict"}`
- malformed `cursor` → `400 {"error":"invalid_cursor"}`

## Storage layer (`internal/telemetry`)

- Add a repo method alongside `Recent`, e.g.:

  ```go
  // Page returns up to limit events matching verdict (empty = any),
  // newest-first, starting strictly before cursor (zero cursor = newest).
  // The returned cursor points at the last row (zero when the page is the
  // last one).
  Page(verdict string, before Cursor, limit int) ([]proxy.Event, Cursor, error)
  ```

  where `Cursor` carries `(Ts time.Time, ID int64)`. `Recent` is left unchanged
  (still used by `load()`'s live window and unrelated callers).

- `Store` gains a thin pass-through `Page(...)` mirroring `Recent`, logging and
  degrading on read error.

- SQLite query (keyset on `(ts, id)`):

  ```sql
  SELECT id, ts, detail_json FROM events
  WHERE (?verdict = '' OR verdict = ?)
    AND (?cursorZero OR (ts < ?cursorTs OR (ts = ?cursorTs AND id < ?cursorId)))
  ORDER BY ts DESC, id DESC
  LIMIT ?
  ```

  (Built with conditional clauses/args rather than literal placeholders above.)
  Uses `idx_events_verdict_gate` for the verdict filter and `idx_events_ts` for
  ordering. The `(ts, id)` keyset is stable when multiple events share a
  millisecond and when new rows are inserted between pages.

- Cursor string encoding (`"<unixMillis>:<id>"`) lives in the console handler;
  the repo deals only in the typed `Cursor`.

## Testing

Go:
- Repo `Page`:
  - newest-first ordering;
  - keyset paging yields every row exactly once with no gaps/dupes, including
    rows that share a `ts`;
  - `verdict` filter restricts to the requested verdict;
  - empty/zero cursor returns the newest page; last page returns a zero cursor.
- Console handler:
  - `verdict` and `cursor` parsing;
  - `next_cursor` shape (non-empty mid-history, empty at the end);
  - `400` on `invalid_verdict` / `invalid_cursor`;
  - backward compatibility: `?limit=500` with no `verdict`/`cursor` behaves as
    before.

Frontend behavior (manual / existing harness): mode switch on filter change,
"Show more" appends, button hides at end, return-to-`All` resyncs live.
