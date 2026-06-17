# Feed History Pagination Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let console operators page through the entire SQLite history of blocked and errored requests via a keyset "Show more", while normal traffic keeps its live-stream behavior.

**Architecture:** A new `Page` method on the telemetry repo/store does keyset pagination on `(ts, id)` with an optional verdict filter. The `GET /api/requests` handler gains optional `verdict` and `cursor` params and returns a `next_cursor`. The feed UI adds an `Error` filter chip; selecting `Blocked` or `Error` switches the feed into a server-paged history mode.

**Tech Stack:** Go 1.x + `database/sql` (SQLite via `internal/storage`), testify; vanilla React (in-browser Babel) for `web/console/*.jsx`.

---

## File Structure

- `internal/telemetry/repo.go` — add `Cursor` type + `Page` to the `Repo` interface.
- `internal/telemetry/sqlite.go` — implement `Page` on `sqliteRepo`.
- `internal/telemetry/store.go` — add `Store.Page` pass-through.
- `internal/telemetry/sqlite_test.go` — repo `Page` tests.
- `internal/telemetry/store_test.go` — store `Page` test.
- `internal/console/cursor.go` (new) — verdict validation + cursor encode/parse helpers.
- `internal/console/server.go` — route `requests` through `Page`, parse `verdict`/`cursor`, return `next_cursor`.
- `internal/console/server_test.go` — handler tests for the new params.
- `web/console/api.js` — expose `JOEI.pageRequests(...)`.
- `web/console/feed.jsx` — `Error` chip + history mode + "Show more".

Key existing facts the implementer must respect:
- The `events.ts` column stores **unix nanoseconds** (`unixNanoOrZero(ev.Time)`, `internal/telemetry/sqlite.go:96`). Cursors encode nanoseconds.
- `events.id` is `INTEGER PRIMARY KEY AUTOINCREMENT` starting at 1, so `id == 0` is a safe "no cursor" sentinel.
- Existing ordering is `ORDER BY ts DESC, id DESC` (`Recent`, `internal/telemetry/sqlite.go:253`). Keep it identical so paging is gap/dupe-free.
- `idx_events_verdict_gate (verdict, gate)` and `idx_events_ts (ts)` already exist.
- Only `sqliteRepo` implements `Repo`; there is no mock to update.

---

## Task 1: Repo `Cursor` type + `Page` interface method

**Files:**
- Modify: `internal/telemetry/repo.go`

- [ ] **Step 1: Add the `Cursor` type and `Page` to the `Repo` interface**

In `internal/telemetry/repo.go`, add the `Cursor` type above the `Repo` interface and a `Page` method inside the interface. The file already imports `time` and `proxy`.

```go
// Cursor is a keyset position in the event log — the (ts, id) of a row under
// the canonical ORDER BY ts DESC, id DESC. The zero Cursor means "start from
// the newest event". id is the SQLite rowid (>= 1), so ID == 0 is the sentinel.
type Cursor struct {
	TS time.Time
	ID int64
}

// Zero reports whether c is the start-from-newest sentinel.
func (c Cursor) Zero() bool { return c.ID == 0 }
```

Then add to the `Repo` interface (after `Recent`):

```go
	// Page returns up to limit events with the given verdict (empty = any),
	// newest-first, strictly older than cursor. A zero cursor starts at the
	// newest matching event. The second return is the cursor of the last row
	// returned; it is the zero Cursor when there are no more pages.
	Page(verdict string, cursor Cursor, limit int) ([]proxy.Event, Cursor, error)
```

- [ ] **Step 2: Verify it compiles-fails because `sqliteRepo` lacks `Page`**

Run: `go build ./internal/telemetry/`
Expected: FAIL — `*sqliteRepo does not implement Repo (missing method Page)`.

- [ ] **Step 3: Commit**

```bash
git add internal/telemetry/repo.go
git commit -m "telemetry: add Cursor type and Page to Repo interface"
```

---

## Task 2: Implement `sqliteRepo.Page`

**Files:**
- Modify: `internal/telemetry/sqlite.go`
- Test: `internal/telemetry/sqlite_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/telemetry/sqlite_test.go`. These use the existing `newRepo(t)` helper. Note `Page` is on the `Repo` interface already.

```go
func TestSQLiteRepo_PagePagesAllWithoutGapsOrDupes(t *testing.T) {
	repo := newRepo(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// 5 events sharing the SAME ts to exercise the (ts, id) tiebreak.
	for i := 1; i <= 5; i++ {
		require.NoError(t, repo.RecordEvent(proxy.Event{
			RequestID: fmt.Sprintf("r%d", i), Time: base,
			Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply,
			Ecosystem: "npm", Package: "p", Version: "1",
		}))
	}

	var ids []string
	cursor := telemetry.Cursor{}
	for {
		evs, next, err := repo.Page(proxy.VerdictBlock, cursor, 2)
		require.NoError(t, err)
		for _, ev := range evs {
			ids = append(ids, ev.RequestID)
		}
		if next.Zero() {
			break
		}
		cursor = next
	}
	// Newest-first, every row exactly once.
	assert.Equal(t, []string{"r5", "r4", "r3", "r2", "r1"}, ids)
}

func TestSQLiteRepo_PageFiltersByVerdict(t *testing.T) {
	repo := newRepo(t)
	now := time.Now()
	require.NoError(t, repo.RecordEvent(proxy.Event{RequestID: "pass1", Time: now, Verdict: proxy.VerdictPass, Gate: proxy.GateSupply}))
	require.NoError(t, repo.RecordEvent(proxy.Event{RequestID: "err1", Time: now.Add(time.Second), Verdict: proxy.VerdictError, Gate: proxy.GateCache}))
	require.NoError(t, repo.RecordEvent(proxy.Event{RequestID: "block1", Time: now.Add(2 * time.Second), Verdict: proxy.VerdictBlock, Gate: proxy.GateCVE}))

	evs, next, err := repo.Page(proxy.VerdictError, telemetry.Cursor{}, 10)
	require.NoError(t, err)
	require.Len(t, evs, 1)
	assert.Equal(t, "err1", evs[0].RequestID)
	assert.True(t, next.Zero(), "single matching row is the last page")
}

func TestSQLiteRepo_PageEmptyVerdictReturnsAllNewestFirst(t *testing.T) {
	repo := newRepo(t)
	now := time.Now()
	require.NoError(t, repo.RecordEvent(proxy.Event{RequestID: "a", Time: now, Verdict: proxy.VerdictPass, Gate: proxy.GateSupply}))
	require.NoError(t, repo.RecordEvent(proxy.Event{RequestID: "b", Time: now.Add(time.Second), Verdict: proxy.VerdictBlock, Gate: proxy.GateCVE}))

	evs, next, err := repo.Page("", telemetry.Cursor{}, 10)
	require.NoError(t, err)
	require.Len(t, evs, 2)
	assert.Equal(t, "b", evs[0].RequestID, "newest first")
	assert.True(t, next.Zero())
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/telemetry/ -run TestSQLiteRepo_Page -v`
Expected: FAIL (does not compile — `Page` not implemented yet).

- [ ] **Step 3: Implement `Page`**

Add `"strings"` to the import block in `internal/telemetry/sqlite.go`, then add this method directly after `Recent` (which ends at `internal/telemetry/sqlite.go:278`):

```go
func (r *sqliteRepo) Page(verdict string, cursor Cursor, limit int) ([]proxy.Event, Cursor, error) {
	var (
		conds []string
		args  []any
	)
	if verdict != "" {
		conds = append(conds, "verdict = ?")
		args = append(args, verdict)
	}
	if !cursor.Zero() {
		// Keyset: rows strictly older than the cursor under (ts DESC, id DESC).
		conds = append(conds, "(ts < ? OR (ts = ? AND id < ?))")
		args = append(args, cursor.TS.UnixNano(), cursor.TS.UnixNano(), cursor.ID)
	}
	query := "SELECT id, ts, detail_json FROM events"
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += " ORDER BY ts DESC, id DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, Cursor{}, err
	}
	defer rows.Close()

	var (
		out     []proxy.Event
		next    Cursor
		scanned int
	)
	for rows.Next() {
		var (
			id     int64
			tsNano int64
			blob   string
		)
		if err := rows.Scan(&id, &tsNano, &blob); err != nil {
			return nil, Cursor{}, err
		}
		scanned++
		// Advance the cursor for every scanned row (even one that fails to
		// unmarshal) so paging never stalls on a single bad blob.
		next = Cursor{TS: time.Unix(0, tsNano), ID: id}
		var ev proxy.Event
		if err := json.Unmarshal([]byte(blob), &ev); err != nil {
			continue
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, Cursor{}, err
	}
	// A short page (fewer rows than asked) means we reached the end: no cursor.
	if limit > 0 && scanned < limit {
		next = Cursor{}
	}
	return out, next, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/telemetry/ -run TestSQLiteRepo_Page -v`
Expected: PASS (all three).

- [ ] **Step 5: Run the full telemetry package to catch regressions**

Run: `go test ./internal/telemetry/`
Expected: PASS (ok).

- [ ] **Step 6: Commit**

```bash
git add internal/telemetry/sqlite.go internal/telemetry/sqlite_test.go
git commit -m "telemetry: implement keyset Page on sqliteRepo"
```

---

## Task 3: `Store.Page` pass-through

**Files:**
- Modify: `internal/telemetry/store.go`
- Test: `internal/telemetry/store_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/telemetry/store_test.go` (uses existing `newStore(t)` and `evt(...)` helpers):

```go
func TestStorePageFiltersAndPages(t *testing.T) {
	s := newStore(t)
	s.Record(evt("pass1", proxy.VerdictPass, proxy.GateSupply, "ok"))
	s.Record(evt("block1", proxy.VerdictBlock, proxy.GateCVE, "cve_found"))
	s.Record(evt("block2", proxy.VerdictBlock, proxy.GateSupply, "young"))

	evs, next := s.Page(proxy.VerdictBlock, telemetry.Cursor{}, 1)
	require.Len(t, evs, 1)
	assert.Equal(t, "block2", evs[0].RequestID, "newest first")
	require.False(t, next.Zero(), "more pages remain")

	evs2, next2 := s.Page(proxy.VerdictBlock, next, 1)
	require.Len(t, evs2, 1)
	assert.Equal(t, "block1", evs2[0].RequestID)
	assert.True(t, next2.Zero(), "last page")
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/telemetry/ -run TestStorePageFiltersAndPages -v`
Expected: FAIL (does not compile — `s.Page` undefined).

- [ ] **Step 3: Implement `Store.Page`**

Add to `internal/telemetry/store.go` directly after the `Recent` method (ends at line 119):

```go
// Page returns up to limit events matching verdict (empty = any), newest-first,
// older than cursor (zero cursor = newest), plus the cursor for the next call
// (zero when there are no more pages). A read error logs and yields nil with a
// zero cursor, so the console degrades to an empty page rather than failing.
func (s *Store) Page(verdict string, cursor Cursor, limit int) ([]proxy.Event, Cursor) {
	evs, next, err := s.repo.Page(verdict, cursor, limit)
	if err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: paging events")
		return nil, Cursor{}
	}
	return evs, next
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/telemetry/ -run TestStorePageFiltersAndPages -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/telemetry/store.go internal/telemetry/store_test.go
git commit -m "telemetry: add Store.Page pass-through"
```

---

## Task 4: Console cursor + verdict helpers

**Files:**
- Create: `internal/console/cursor.go`
- Test: `internal/console/cursor_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/console/cursor_test.go`. Note: the cursor helpers are unexported, so this test is in `package console` (white-box), unlike `server_test.go` which is `package console_test`.

```go
package console

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func TestEncodeCursorRoundTrips(t *testing.T) {
	c := telemetry.Cursor{TS: time.Unix(0, 1718600000000000123), ID: 4213}
	s := encodeCursor(c)
	assert.Equal(t, "1718600000000000123:4213", s)

	got, ok := parseCursor(s)
	assert.True(t, ok)
	assert.Equal(t, int64(1718600000000000123), got.TS.UnixNano())
	assert.Equal(t, int64(4213), got.ID)
}

func TestEncodeCursorZeroIsEmpty(t *testing.T) {
	assert.Equal(t, "", encodeCursor(telemetry.Cursor{}))
}

func TestParseCursorRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "abc", "123", "1:2:3", "x:2", "1:y", "1:0", "1:-3"} {
		_, ok := parseCursor(bad)
		assert.False(t, ok, "cursor %q must be rejected", bad)
	}
}

func TestValidVerdict(t *testing.T) {
	for _, v := range []string{"PASS", "CACHE", "BLOCK", "ERROR"} {
		assert.True(t, validVerdict(v), v)
	}
	for _, v := range []string{"pass", "BOGUS", "", "BLOCKED"} {
		assert.False(t, validVerdict(v), v)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/console/ -run 'TestEncodeCursor|TestParseCursor|TestValidVerdict' -v`
Expected: FAIL (does not compile — helpers undefined).

- [ ] **Step 3: Implement the helpers**

Create `internal/console/cursor.go`:

```go
package console

import (
	"strconv"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// validVerdicts is the set accepted by GET /api/requests?verdict=.
var validVerdicts = map[string]bool{
	proxy.VerdictPass:  true,
	proxy.VerdictCache: true,
	proxy.VerdictBlock: true,
	proxy.VerdictError: true,
}

func validVerdict(v string) bool { return validVerdicts[v] }

// encodeCursor renders a keyset cursor as "<unixNanos>:<id>". The zero cursor
// (no more pages / start-from-newest) renders as the empty string.
func encodeCursor(c telemetry.Cursor) string {
	if c.Zero() {
		return ""
	}
	return strconv.FormatInt(c.TS.UnixNano(), 10) + ":" + strconv.FormatInt(c.ID, 10)
}

// parseCursor inverts encodeCursor. It rejects malformed input and any id < 1
// (ids are SQLite rowids starting at 1; id 0 is the zero-cursor sentinel).
func parseCursor(s string) (telemetry.Cursor, bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return telemetry.Cursor{}, false
	}
	tsNano, err1 := strconv.ParseInt(parts[0], 10, 64)
	id, err2 := strconv.ParseInt(parts[1], 10, 64)
	if err1 != nil || err2 != nil || id < 1 {
		return telemetry.Cursor{}, false
	}
	return telemetry.Cursor{TS: time.Unix(0, tsNano), ID: id}, true
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/console/ -run 'TestEncodeCursor|TestParseCursor|TestValidVerdict' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/console/cursor.go internal/console/cursor_test.go
git commit -m "console: add cursor and verdict helpers for request paging"
```

---

## Task 5: Route `requests` through `Page` with `verdict`/`cursor`

**Files:**
- Modify: `internal/console/server.go:181-197` (the `requests` handler) and its import block (`internal/console/server.go:7-23`)
- Test: `internal/console/server_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/console/server_test.go` (package `console_test`; uses existing `newFixture`, `getJSON`). The fixture's `f.store` is a `*telemetry.Store`.

```go
func TestRequestsFilterByVerdictAndPage(t *testing.T) {
	f := newFixture(t)
	f.store.Record(proxy.Event{RequestID: "pass1", Verdict: proxy.VerdictPass, Gate: proxy.GateSupply, Time: time.Now(), Ecosystem: "pypi", Package: "p", Version: "1"})
	f.store.Record(proxy.Event{RequestID: "block1", Verdict: proxy.VerdictBlock, Gate: proxy.GateCVE, Time: time.Now().Add(time.Second), Ecosystem: "pypi", Package: "p", Version: "1"})
	f.store.Record(proxy.Event{RequestID: "block2", Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply, Time: time.Now().Add(2 * time.Second), Ecosystem: "pypi", Package: "p", Version: "1"})

	var page1 struct {
		Requests []struct {
			RequestID string `json:"request_id"`
		} `json:"requests"`
		NextCursor string `json:"next_cursor"`
	}
	code := getJSON(t, f.srv.URL+"/api/requests?verdict=BLOCK&limit=1", &page1)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, page1.Requests, 1)
	assert.Equal(t, "block2", page1.Requests[0].RequestID, "newest blocked first")
	require.NotEmpty(t, page1.NextCursor, "more blocked rows remain")

	var page2 struct {
		Requests []struct {
			RequestID string `json:"request_id"`
		} `json:"requests"`
		NextCursor string `json:"next_cursor"`
	}
	code = getJSON(t, f.srv.URL+"/api/requests?verdict=BLOCK&limit=1&cursor="+url.QueryEscape(page1.NextCursor), &page2)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, page2.Requests, 1)
	assert.Equal(t, "block1", page2.Requests[0].RequestID)
	assert.Empty(t, page2.NextCursor, "no more pages")
}

func TestRequestsRejectsBadVerdictAndCursor(t *testing.T) {
	f := newFixture(t)

	resp, err := http.Get(f.srv.URL + "/api/requests?verdict=BOGUS")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	resp, err = http.Get(f.srv.URL + "/api/requests?cursor=not-a-cursor")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
```

Add `"net/url"` to the `server_test.go` import block.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/console/ -run TestRequests -v`
Expected: FAIL — `TestRequestsFilterByVerdictAndPage` fails (no `next_cursor` / no filtering), `TestRequestsRejectsBadVerdictAndCursor` fails (200 instead of 400). The existing `TestRequests` still passes.

- [ ] **Step 3: Update the `requests` handler**

In `internal/console/server.go`, add `"github.com/ggwpLab/Jo-ei/internal/proxy"` to the import block (it is not currently imported). `strconv` and `telemetry` are already imported. Then replace the whole `requests` method (`internal/console/server.go:181-197`):

```go
func (s *server) requests(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 {
			s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_limit"})
			return
		}
		limit = n
	}

	verdict := r.URL.Query().Get("verdict")
	if verdict != "" && !validVerdict(verdict) {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_verdict"})
		return
	}

	var cursor telemetry.Cursor
	if q := r.URL.Query().Get("cursor"); q != "" {
		c, ok := parseCursor(q)
		if !ok {
			s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_cursor"})
			return
		}
		cursor = c
	}

	events, next := s.cfg.Store.Page(verdict, cursor, limit)
	out := make([]eventJSON, 0, len(events))
	for _, ev := range events {
		out = append(out, toEventJSON(ev))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"requests":    out,
		"next_cursor": encodeCursor(next),
	})
}
```

Note: the no-`verdict`/no-`cursor` path now calls `Page("", zero, limit)`, which returns the newest `limit` events exactly as the old `Recent(limit)` did — so `load()`'s `?limit=500` and the existing `TestRequests` are unchanged. `proxy` is referenced indirectly via `validVerdict`/`Page`, but make sure the import is added so the file compiles. (If `goimports`/`go build` reports `proxy` imported but unused, it means the handler does not reference it directly — in that case remove the `proxy` import again; `validVerdict` already lives in `cursor.go`. Prefer letting `go build` decide.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/console/ -run TestRequests -v`
Expected: PASS (old `TestRequests` + both new tests).

- [ ] **Step 5: Run the full console + telemetry packages**

Run: `go test ./internal/console/ ./internal/telemetry/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/console/server.go internal/console/server_test.go
git commit -m "console: filter and keyset-page GET /api/requests by verdict"
```

---

## Task 6: Expose `JOEI.pageRequests` in the API client

**Files:**
- Modify: `web/console/api.js`

- [ ] **Step 1: Add the `pageRequests` function**

In `web/console/api.js`, add this function after `load()` (which ends at line 138, before `savePolicy`). It reuses the file-private `getJSON` and `reviveEvent` so revival logic stays in one place.

```js
  // Fetch one page of history filtered by verdict (server-paged). cursor ""
  // starts from the newest matching event. Returns revived rows (ts as Date,
  // cves/supply expanded) plus nextCursor ("" when there are no more pages).
  async function pageRequests({ verdict, cursor, limit }) {
    const params = new URLSearchParams();
    if (verdict) params.set("verdict", verdict);
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));
    const data = await getJSON("/api/requests?" + params.toString());
    return {
      rows: (data.requests || []).map(reviveEvent),
      nextCursor: data.next_cursor || "",
    };
  }
```

- [ ] **Step 2: Export it on `JOEI`**

In `web/console/api.js`, find the export lines (currently `J.load = load;` / `J.savePolicy = savePolicy;` at lines 184-185) and add:

```js
  J.pageRequests = pageRequests;
```

- [ ] **Step 3: Verify the file parses**

Run: `node --check web/console/api.js`
Expected: no output, exit 0. (If `node` is unavailable, skip — this is plain ES2017 and is verified in the click-through in Task 7.)

- [ ] **Step 4: Commit**

```bash
git add web/console/api.js
git commit -m "console(web): expose JOEI.pageRequests for history paging"
```

---

## Task 7: Feed UI — `Error` chip, history mode, "Show more"

**Files:**
- Modify: `web/console/feed.jsx`

- [ ] **Step 1: Replace `feed.jsx` with the history-aware version**

The component keeps the live window for `All`/`Passed`/`Cache` and switches to server-paged history for `Blocked`/`Error`. Replace the entire contents of `web/console/feed.jsx` with:

```jsx
/* 浄衛 Jōei :: LIVE REQUEST FEED */

function FeedRow({ r, onOpen, isNew }) {
  const blocked = r.verdict === "BLOCK";
  const gateName = blocked ? GATE_LABEL[r.blocked_by[0]] : GATE_LABEL[r.gate] || "—";
  return (
    <div
      className={`feed-row ${blocked ? "clickable" : ""} ${isNew ? "new-row" : ""}`}
      onClick={blocked ? () => onOpen(r) : undefined}
    >
      <span className="ts mono">{fmtClock(r.ts)}</span>
      <Eco id={r.eco} />
      <span className="pkg" title={`${r.pkg}@${r.ver}`}>
        {r.pkg}<span className="ver">@{r.ver}</span>
      </span>
      <span><Verdict v={r.verdict} /></span>
      <span className="gate-cell">
        {(blocked || r.verdict === "ERROR") && r.http ? (
          <span style={{ color: "var(--vermilion-l)", fontFamily: "var(--mono)", fontSize: 11, marginRight: 6 }}>{r.http}</span>
        ) : null}
        {gateName}
      </span>
      <span className="lat mono" style={{ color: r.lat > 400 ? "var(--gold-l)" : undefined }}>{r.lat}ms</span>
      <span className="rid mono">{r.request_id}</span>
      <span className="chev">{blocked ? <Icons.chevron /> : null}</span>
    </div>
  );
}

const FILTERS = [
  ["all", "All"], ["BLOCK", "Blocked"], ["PASS", "Passed"],
  ["CACHE", "Cache"], ["ERROR", "Error"],
];

// Verdict filters that browse the full SQLite history (server-paged) rather
// than the live in-memory window. The chip value is sent verbatim as ?verdict=.
const HISTORY_FILTERS = { BLOCK: true, ERROR: true };

const PAGE_SIZE = 50;

function LiveFeed({ openThreat }) {
  const [rows, setRows] = useState(() => JOEI.requests.slice(0, 120));
  const [filter, setFilter] = useState("all");
  const [q, setQ] = useState("");
  const [paused, setPaused] = useState(false);
  const [newId, setNewId] = useState(null);

  // History-mode state, active only while filter is in HISTORY_FILTERS.
  const [histRows, setHistRows] = useState([]);
  const [cursor, setCursor] = useState("");
  const [loading, setLoading] = useState(false);
  const [histErr, setHistErr] = useState(false);

  const history = !!HISTORY_FILTERS[filter];

  // Live window: prepend SSE events and resync on full refresh. Kept warm even
  // in history mode so switching back to a live filter is instant.
  useEffect(() => {
    const onEvent = (e) => {
      if (paused) return;
      setNewId(e.detail.request_id);
      setRows((rs) => [e.detail, ...rs].slice(0, 120));
    };
    const onData = () => { if (!paused) setRows(JOEI.requests.slice(0, 120)); };
    window.addEventListener("joei:event", onEvent);
    window.addEventListener("joei:data", onData);
    return () => {
      window.removeEventListener("joei:event", onEvent);
      window.removeEventListener("joei:data", onData);
    };
  }, [paused]);

  // Entering a history filter loads its first page; leaving one clears the
  // history state so a live filter shows the live window again.
  useEffect(() => {
    if (!history) {
      setHistRows([]); setCursor(""); setHistErr(false); setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true); setHistErr(false); setHistRows([]); setCursor("");
    JOEI.pageRequests({ verdict: filter, cursor: "", limit: PAGE_SIZE })
      .then(({ rows: got, nextCursor }) => {
        if (cancelled) return;
        setHistRows(got); setCursor(nextCursor);
      })
      .catch(() => { if (!cancelled) setHistErr(true); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [history, filter]);

  const loadMore = () => {
    if (loading || !cursor) return;
    setLoading(true);
    JOEI.pageRequests({ verdict: filter, cursor, limit: PAGE_SIZE })
      .then(({ rows: got, nextCursor }) => {
        setHistRows((rs) => rs.concat(got));
        setCursor(nextCursor);
      })
      .catch(() => setHistErr(true))
      .finally(() => setLoading(false));
  };

  const source = history ? histRows : rows;
  const shown = source.filter((r) => {
    // Live filters narrow the in-memory window client-side; history rows are
    // already verdict-filtered by the server.
    if (!history && filter !== "all" && r.verdict !== filter) return false;
    if (q && !(`${r.pkg}@${r.ver}`.toLowerCase().includes(q.toLowerCase()) || r.request_id.includes(q))) return false;
    return true;
  });

  return (
    <div className="content-inner">
      <div className="section-head">
        <span className="head-kanji kanji">流</span>
        <div>
          <div className="eyebrow">Live · request_id stream</div>
          <h2>Request feed</h2>
        </div>
        <div className="spacer"></div>
        {history ? (
          <span className="pill">
            <span className="dot" style={{ color: "var(--washi-mut)" }}></span>
            history · {filter.toLowerCase()}
          </span>
        ) : (
          <>
            <button className="btn sm ghost" onClick={() => setPaused((p) => !p)}>
              {paused ? "Resume" : "Pause"} stream
            </button>
            <span className="pill">
              <span className="dot live" style={{ color: paused ? "var(--washi-faint)" : "var(--jade)" }}></span>
              {paused ? "paused" : "live"}
            </span>
          </>
        )}
      </div>

      <div className="card" style={{ overflow: "hidden" }}>
        <div className="feed-toolbar">
          <div className="seg">
            {FILTERS.map(([k, l]) => (
              <button key={k} className={filter === k ? "active" : ""} onClick={() => setFilter(k)}>{l}</button>
            ))}
          </div>
          <div className="search">
            <Icons.search />
            <input placeholder="filter by package or request_id…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <span className="right muted mono" style={{ fontSize: 12 }}>{shown.length} shown</span>
        </div>

        <div className="feed-row head">
          <span>TIME</span><span></span><span>PACKAGE</span><span>VERDICT</span>
          <span>GATE</span><span style={{ textAlign: "right" }}>LATENCY</span><span>REQUEST ID</span><span></span>
        </div>

        {histErr ? (
          <div className="empty">
            <span className="e-kanji">録</span>
            <div className="e-title">Could not load history</div>
            <div className="e-sub">The request history could not be fetched. Check the connection and try the filter again.</div>
          </div>
        ) : shown.length === 0 ? (
          loading ? (
            <div className="empty"><div className="e-sub">Loading…</div></div>
          ) : (
            <div className="empty">
              <span className="e-kanji">無</span>
              <div className="e-title">No matching requests</div>
              <div className="e-sub">{q || filter !== "all"
                ? <>Nothing matches “{q || filter}”. Clear the filter to see all traffic.</>
                : <>No requests have passed through the gate yet. Point a package manager at the proxy and traffic will appear here live.</>}</div>
            </div>
          )
        ) : (
          shown.map((r) => (
            <FeedRow key={r.request_id} r={r} onOpen={openThreat} isNew={r.request_id === newId} />
          ))
        )}

        {history && !histErr && (cursor || loading) && (
          <div style={{ padding: "12px", textAlign: "center", borderTop: "1px solid var(--washi-faint)" }}>
            <button className="btn sm ghost" onClick={loadMore} disabled={loading || !cursor}>
              {loading ? "Loading…" : "Show more"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

Object.assign(window, { FeedRow, LiveFeed });
```

- [ ] **Step 2: Verify the file parses**

Run: `npx --yes @babel/cli --presets @babel/preset-react web/console/feed.jsx -o /dev/null`
Expected: exits 0 with no parse error. (If Babel CLI is unavailable, skip and rely on the click-through below — the in-browser Babel will surface any syntax error in the console.)

- [ ] **Step 3: Build the binary so embedded assets refresh, then run a manual click-through**

The console assets are served by the Go binary (`web/web.go`). Rebuild and run:

Run: `go build ./...`
Expected: PASS (no compile errors anywhere).

Then start the app per the repo's run instructions (e.g. `go run ./cmd/jo-ei` with a config that enables the console, or the existing docker-compose), generate a few `BLOCK` and `ERROR` events (point a package manager at the proxy, or use an existing integration/seed path), open the console, and verify:
- A new **Error** chip appears next to Cache.
- Selecting **Blocked** swaps the live pill for a `history · blocked` pill, hides the Pause button, and lists blocked rows.
- A **Show more** button appears when more than 50 blocked rows exist; clicking it appends the next page; it disappears at the end.
- Selecting **Error** lists errored rows with their HTTP status shown.
- Selecting **All** returns to the live stream (pill back to `live`, rows update in real time).

- [ ] **Step 4: Commit**

```bash
git add web/console/feed.jsx
git commit -m "console(web): Error filter and paged history mode in the request feed"
```

---

## Task 8: Full verification

- [ ] **Step 1: Run the whole Go test suite**

Run: `go test ./...`
Expected: PASS (ok across all packages).

- [ ] **Step 2: Vet**

Run: `go vet ./...`
Expected: no findings.

- [ ] **Step 3: Confirm backward compatibility of the original load path**

Run: `go test ./internal/console/ -run 'TestRequests$' -v`
Expected: PASS — the original `?limit=2` newest-first behavior is intact.

---

## Self-Review Notes

- **Spec coverage:** Error chip (Task 7) · history-mode switch for BLOCK/ERROR (Task 7) · keyset Show-more (Tasks 2/6/7) · backward-compatible `verdict`/`cursor`/`next_cursor` API (Tasks 4/5) · `invalid_verdict`/`invalid_cursor` 400s (Tasks 4/5) · keyset storage on `(ts,id)` with verdict filter (Task 2) · client-side search retained in history mode (Task 7, `shown` filter) · Go tests for repo/store/handler (Tasks 2/3/4/5). All spec sections map to a task.
- **Type consistency:** `Cursor{TS time.Time, ID int64}` and `Cursor.Zero()` are used identically in repo, store, and console. `Page(verdict string, cursor Cursor, limit int)` signature matches across `Repo`, `sqliteRepo`, and `Store` (the `Store` variant drops the `error` return, returning `([]proxy.Event, Cursor)`). `encodeCursor`/`parseCursor`/`validVerdict` names match between `cursor.go`, `cursor_test.go`, and `server.go`. JS `pageRequests({verdict,cursor,limit}) → {rows,nextCursor}` matches its consumer in `feed.jsx`.
- **Cursor encoding:** unix **nanoseconds**, matching the `events.ts` column; verified against `unixNanoOrZero` at write time.
