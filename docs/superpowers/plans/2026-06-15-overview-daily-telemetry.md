# Overview Daily Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the persistent per-day telemetry on the console Overview as sparklines on the Requests / Cache-hit / Blocked KPI cards, with a 7d/30d window toggle.

**Architecture:** `api.js` gains a sixth fetch in `load()` (`GET /api/metrics/daily?days=30`) and stores the rows oldest-first on `window.JOEI.daily`. `overview.jsx` keeps a local window state (7|30), slices `JOEI.daily` client-side (no refetch on toggle), derives three numeric series, and passes them to the existing `KpiCard` `spark`/`sparkColor` props. Backend is untouched.

**Tech Stack:** In-browser React + Babel (no build step, no JS test harness), Go stdlib HTTP for the API, embedded assets via `web/web.go`.

> **Note on testing:** the console JS has no unit-test harness in this repo (JSX is compiled in-browser from CDN Babel). JS changes are verified by (a) grepping the edited source for the expected content, (b) `go build` + `go test ./...` to confirm the embed still compiles and the API envelope is unchanged, and (c) a manual browser checklist in the final task. There is no failing-test-first step for the JS edits — this is a deliberate, documented exception, not an oversight.

---

### Task 1: Fetch and store daily metrics in `api.js`

**Files:**
- Modify: `web/console/api.js` (the `window.JOEI` object literal ~line 30-49, and `load()` ~line 112-132)

- [ ] **Step 1: Add `daily` to the JOEI state object**

In `web/console/api.js`, inside the `const J = (window.JOEI = { ... })` literal, add a `daily` array. Place it immediately after the `quarantine: [],` line:

```js
    requests: [],
    quarantine: [],
    daily: [], // per-UTC-day metric rows, oldest-first (for left→right sparklines)
```

- [ ] **Step 2: Fetch the daily endpoint in `load()`**

In `load()`, extend the `Promise.all` destructuring and array with a sixth fetch. Replace:

```js
    const [overview, requests, quarantine, pol, registries] = await Promise.all([
      getJSON("/api/overview"),
      getJSON("/api/requests?limit=500"),
      getJSON("/api/quarantine"),
      getJSON("/api/policy"),
      getJSON("/api/registries"),
    ]);
```

with:

```js
    const [overview, requests, quarantine, pol, registries, daily] = await Promise.all([
      getJSON("/api/overview"),
      getJSON("/api/requests?limit=500"),
      getJSON("/api/quarantine"),
      getJSON("/api/policy"),
      getJSON("/api/registries"),
      getJSON("/api/metrics/daily?days=30"),
    ]);
```

- [ ] **Step 3: Store the rows oldest-first**

Still in `load()`, after the existing `J.registries = ...` assignment and before `J.ready = true;`, add:

```js
    // The endpoint returns newest-first; reverse to oldest-first so sparklines
    // read left→right in time order. "|| []" degrades only the sparklines (e.g.
    // when persistence is off and the array is empty), never the whole load().
    J.daily = (daily.daily || []).slice().reverse();
```

- [ ] **Step 4: Verify the edits are present**

Run: `grep -n "metrics/daily\|J.daily\|daily: \[\]" web/console/api.js`
Expected: three matches — the `daily: []` initializer, the `getJSON("/api/metrics/daily?days=30")` fetch, and the `J.daily = ...` assignment.

- [ ] **Step 5: Verify the embed still builds**

Run: `go build ./...`
Expected: no output, exit 0 (the edited asset is embedded by `web/web.go`).

- [ ] **Step 6: Commit**

```bash
git add web/console/api.js
git commit -m "feat(console): fetch daily metrics into JOEI.daily"
```

---

### Task 2: Render the window toggle and sparklines in `overview.jsx`

**Files:**
- Modify: `web/console/overview.jsx` (the `Overview` component, ~line 15-95)

Reuses the existing `.seg` segmented-control CSS (defined in `web/console/screens.css`) and the `.spacer` / `.faint` helpers — **no CSS changes**. Reuses `KpiCard`'s existing `spark`/`sparkColor` props and the `Spark` component from `shared.jsx`.

- [ ] **Step 1: Add window state and derive the series**

In `web/console/overview.jsx`, inside `Overview(...)`, after the existing `const uptime = ...` line, add the window state and series builders:

```js
  const [win, setWin] = useState(30);
  // Toggling the window only re-slices the already-loaded array — no refetch.
  const rows = JOEI.daily.slice(-win);
  // Spark breaks on <2 points (Math.max(...[]) === -Infinity, divide by len-1).
  // With fewer points pass `undefined` so the card renders exactly as before.
  const haveTrend = rows.length >= 2;
  const reqSpark = haveTrend ? rows.map((r) => r.requests) : undefined;
  const hitSpark = haveTrend ? rows.map((r) => (r.requests ? r.cache_hits / r.requests : 0)) : undefined;
  const blkSpark = haveTrend ? rows.map((r) => r.blocked) : undefined;
```

- [ ] **Step 2: Add the toggle (or empty hint) to the "Gate throughput" section head**

Replace the existing section head:

```jsx
      <div className="section-head" style={{ marginTop: 28 }}>
        <span className="head-kanji kanji">衛</span>
        <div>
          <div className="eyebrow">Since start · uptime {uptime}</div>
          <h2>Gate throughput</h2>
        </div>
      </div>
```

with (adds a `.spacer` then either the toggle or, when there is no history, a quiet hint in its place):

```jsx
      <div className="section-head" style={{ marginTop: 28 }}>
        <span className="head-kanji kanji">衛</span>
        <div>
          <div className="eyebrow">Since start · uptime {uptime}</div>
          <h2>Gate throughput</h2>
        </div>
        <div className="spacer"></div>
        {JOEI.daily.length > 0 ? (
          <div className="seg" role="group" aria-label="Sparkline window">
            {[7, 30].map((n) => (
              <button key={n} className={win === n ? "active" : ""} onClick={() => setWin(n)}>{n}d</button>
            ))}
          </div>
        ) : (
          <span className="faint" style={{ fontSize: 11 }}>no history yet · set database.path to persist daily metrics</span>
        )}
      </div>
```

- [ ] **Step 3: Pass the series to the KPI cards**

Replace the existing `kpi-grid` block:

```jsx
      <div className="kpi-grid">
        <KpiCard label="Requests · since start" value={fmtCompact(k.requests_total)}
          delta={<><b>{fmtNum(k.requests_total)}</b> total · {fmtNum(k.errors)} errors</>} watermark="求" />
        <KpiCard label="Served from cache" value={(k.hit_rate * 100).toFixed(1) + "%"} accent="jade"
          delta={<><b>{fmtCompact(k.cache_hits)}</b> hits since start</>} watermark="蔵" />
        <KpiCard label="Blocked · since start" value={fmtNum(k.blocked_total)} accent="verm"
          delta={<>423 Locked + 403 Forbidden</>} watermark="封" />
        <KpiCard label="In quarantine" value={fmtNum(k.quarantined)} accent="gold"
          delta={<>held until min-age maturity</>} watermark="守" />
      </div>
```

with (adds `spark`/`sparkColor` to the first three cards; "In quarantine" is a live snapshot with no daily series and stays unchanged):

```jsx
      <div className="kpi-grid">
        <KpiCard label="Requests · since start" value={fmtCompact(k.requests_total)}
          delta={<><b>{fmtNum(k.requests_total)}</b> total · {fmtNum(k.errors)} errors</>} watermark="求"
          spark={reqSpark} sparkColor="var(--washi-mut)" />
        <KpiCard label="Served from cache" value={(k.hit_rate * 100).toFixed(1) + "%"} accent="jade"
          delta={<><b>{fmtCompact(k.cache_hits)}</b> hits since start</>} watermark="蔵"
          spark={hitSpark} sparkColor="var(--jade)" />
        <KpiCard label="Blocked · since start" value={fmtNum(k.blocked_total)} accent="verm"
          delta={<>423 Locked + 403 Forbidden</>} watermark="封"
          spark={blkSpark} sparkColor="var(--vermilion)" />
        <KpiCard label="In quarantine" value={fmtNum(k.quarantined)} accent="gold"
          delta={<>held until min-age maturity</>} watermark="守" />
      </div>
```

- [ ] **Step 4: Verify the edits are present**

Run: `grep -n "setWin\|reqSpark\|hitSpark\|blkSpark\|no history yet" web/console/overview.jsx`
Expected: matches for the window state, all three spark series, and the empty hint.

- [ ] **Step 5: Verify the embed still builds**

Run: `go build ./...`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add web/console/overview.jsx
git commit -m "feat(console): daily sparklines + 7d/30d toggle on Overview"
```

---

### Task 3: Document the feature in the README

**Files:**
- Modify: `README.md` (the "Persistent telemetry" section, ~line 196-209)

- [ ] **Step 1: Add a sentence about the Overview sparklines**

In `README.md`, in the "### Persistent telemetry" section, after the paragraph that ends `... newest first).`, add:

```markdown

When persistence is enabled, the console **Overview** renders these daily metrics
as sparklines on the Requests, Cache-hit and Blocked KPI cards, with a 7-day /
30-day window toggle. Without a `database.path`, the cards show current counters
only and the Overview notes that no history is available.
```

- [ ] **Step 2: Verify the edit**

Run: `grep -n "sparklines on the Requests" README.md`
Expected: one match.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: note Overview daily-metric sparklines"
```

---

### Task 4: Full build, test, and manual verification

**Files:** none (verification only)

- [ ] **Step 1: Build and run the unit tests**

Run: `go build ./... && go test ./...`
Expected: all packages pass. `internal/console` includes `TestDailyMetrics`, which already asserts the `{ "daily": [...] }` envelope the client now depends on — confirm it passes.

- [ ] **Step 2: Run the proxy with persistence and a console user**

```bash
# generate a console hash (any password)
HASH=$(printf '%s' 'verify-pass' | go run ./cmd/jo-ei hashpw)
export JOEI_CONSOLE_AUTH_USERS="admin:$HASH"
# enable persistence so daily rows exist
export JOEI_DATABASE_PATH="$(mktemp -d)/jo-ei.db"
go run ./cmd/jo-ei --config config.yaml
```

Expected: starts on `:8080`, logs no database warning.

- [ ] **Step 2.5: Confirm the served asset contains the new code**

In a second shell:

Run: `curl -s -u "admin:verify-pass" http://localhost:8080/console/api.js | grep -c "metrics/daily"`
Expected: `1` (the edited, embedded asset is what the browser will load).

- [ ] **Step 3: Manual browser checklist**

Open `http://localhost:8080/console/` (log in as `admin` / `verify-pass`) and confirm:
  - Overview "Gate throughput" section shows a `[7d] [30d]` toggle (30 active by default) on a **fresh** DB only after ≥2 distinct UTC days exist; on a same-day-only or empty DB the cards show no sparkline and the header shows the `no history yet …` hint instead of the toggle.
  - With ≥2 days of data: Requests, Served-from-cache, and Blocked cards each render a sparkline; "In quarantine" does not.
  - Flipping `7d`/`30d` re-slices the line without a network request (check the Network tab — no new `/api/metrics/daily` call on toggle).
  - No console errors.

> Tip for generating ≥2 days quickly: with persistence on, the daily series fills in as the proxy runs across UTC-day boundaries; for an immediate visual check you can seed two days via the same mechanism `TestDailyMetrics` uses (two `store.Record` events on different `time.Date` days) in a throwaway test, or simply trust the unit test for shape and verify the empty/single-day states live.

- [ ] **Step 4: Stop the proxy**

Stop the `go run` process (Ctrl-C) and remove the temp DB dir if desired.

---

## Notes for the integrator

- Branch is `feature/overview-daily-telemetry` (already created). After Task 4 passes, open a PR into `main` per the repo workflow.
- No backend, config, or CSS files change — only `web/console/api.js`, `web/console/overview.jsx`, and `README.md`.
