# Console Bugfixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three console defects — the Overview 7d/30d toggle that moves only the sparklines, the Live Feed's 50-row/unpaged listing, and the hardcoded "gate healthy" badge.

**Architecture:** All three are client-side only. The data each fix needs is already on the wire: `/api/metrics/daily?days=30` returns per-day tallies for every KPI, and `/api/overview` returns per-scanner `status`. No Go handler, no API shape, and no database change. The console is plain JSX compiled by esbuild through `internal/uibuild`; the built bundle is committed.

**Tech Stack:** React 18 (vendored, no JSX modules — all files share one global scope), esbuild via `go generate ./web`, Go 1.25 toolchain.

**Spec:** None — these are bounded fixes agreed in chat, not an architectural change. The JWT work is separate: `docs/superpowers/specs/2026-09-05-jwt-console-auth-design.md`.

## Global Constraints

- **No npm, no CDN, no new dependency.** The console is vendored on purpose; `web/console/vendor/` and `internal/uibuild` are the whole toolchain.
- **Console sources are not ES modules.** `web/console/src/*.jsx` share one global lexical scope and are concatenated in the order listed in `internal/uibuild/main.go`. Never add `import`/`export`; publish new globals with `Object.assign(window, {...})` as the existing files do.
- **`web/console/app.bundle.js` is generated and committed.** After every source edit run `go generate ./web` and commit the regenerated bundle with the sources.
- **There is no JavaScript test runner in this repository, by design.** Verification for these tasks is: `go generate ./web` succeeds, `go build ./...` and `go test ./...` stay green, and the documented manual browser checks pass. Do not claim test coverage that does not exist, and do not add an npm toolchain to create some.
- **Branch:** `fix/console-bugfixes`, cut from `main`. One PR into `main`. Never commit these directly to `main`.
- **Lint gate is golangci-lint**, not just `go vet` — run `golangci-lint run` before pushing if any Go file is touched (none is expected in this plan).

---

### Task 0: Branch

**Files:** none

- [ ] **Step 1: Cut the branch from an up-to-date main**

```bash
git checkout main
git pull --ff-only
git checkout -b fix/console-bugfixes
```

- [ ] **Step 2: Confirm the tree is clean and the bundle builds before you change anything**

Run:

```bash
go generate ./web
git status --short web/console/app.bundle.js
```

Expected: no output from `git status` — the committed bundle already matches the sources. If it differs, stop and report; something was committed without regenerating, and you need to know that before your own changes land in the same file.

---

### Task 1: Overview 7d/30d moves the KPI values

**Files:**
- Modify: `web/console/src/overview.jsx:14-128` (the whole `Overview` component)
- Regenerate: `web/console/app.bundle.js`

**Interfaces:**
- Consumes: `JOEI.daily` — array of daily rows, oldest-first (reversed in `api.js`), each `{day, requests, cache_hits, blocked, errors, supply_blocked, cve_blocked, malware_blocked, denylisted, gates}` (see `internal/telemetry/store.go:38-49`); `JOEI.kpis` — lifetime counters.
- Produces: nothing consumed by other tasks.

**Background.** `overview.jsx:33` already slices the window (`const rows = JOEI.daily.slice(-win)`), but every KPI card and the block-breakdown strip read `k = JOEI.kpis`, which holds lifetime counters. That is why the toggle moves the pictures and not the numbers. The `/api/metrics/daily?days=30` call in `api.js` already loads 30 days, so 7d and 30d are both satisfied client-side with no refetch.

Two rules to respect:

- **Quarantine is a gauge, not a flow.** `k.quarantined` is "how many are held right now" (`api.js` sets it from `JOEI.quarantine.length`). It has no daily counter and must not gain a window suffix.
- **Fewer than two daily rows hides the toggle** (`overview.jsx:57`, unchanged). In that state the cards must keep showing the lifetime counters with their current `· total` wording, so a fresh install looks exactly as it does today.

- [ ] **Step 1: Add the windowed tallies next to the existing slice**

In `web/console/src/overview.jsx`, immediately after the `qSpark` line (currently `overview.jsx:44`), add:

```jsx
  // The toggle moves the values, not only the sparklines: each card sums the
  // daily rows inside the window. Below two rows the toggle is not rendered
  // (see the section head), so the cards fall back to the lifetime counters
  // and keep their "· total" wording — a fresh install looks unchanged.
  const sum = (field) => rows.reduce((acc, r) => acc + (r[field] || 0), 0);
  const w = haveTrend
    ? {
        windowed: true,
        suffix: ` · ${win}d`,
        requests: sum("requests"),
        cacheHits: sum("cache_hits"),
        blocked: sum("blocked"),
        errors: sum("errors"),
        supplyBlocked: sum("supply_blocked"),
        cveBlocked: sum("cve_blocked"),
        malwareBlocked: sum("malware_blocked"),
        denylisted: sum("denylisted"),
      }
    : {
        windowed: false,
        suffix: " · total",
        requests: k.requests_total,
        cacheHits: k.cache_hits,
        blocked: k.blocked_total,
        errors: k.errors,
        supplyBlocked: k.supply_blocked,
        cveBlocked: k.cve_blocked,
        malwareBlocked: k.malware_blocked,
        denylisted: k.denylisted,
      };
  // Windowed hit rate is recomputed from the window's own totals; the lifetime
  // rate is a server-side counter ratio and cannot be re-derived from it.
  const hitRate = w.windowed ? (w.requests ? w.cacheHits / w.requests : 0) : k.hit_rate;
```

- [ ] **Step 2: Point the section eyebrow at the window**

Replace (currently `overview.jsx:51`):

```jsx
          <div className="eyebrow">Totals · uptime {uptime}</div>
```

with:

```jsx
          <div className="eyebrow">{w.windowed ? `Last ${win} days` : "Totals"} · uptime {uptime}</div>
```

- [ ] **Step 3: Feed the KPI cards from the window**

Replace the whole `<div className="kpi-grid">…</div>` block (currently `overview.jsx:70-82`) with:

```jsx
      <div className="kpi-grid">
        <KpiCard label={`Requests${w.suffix}`} value={fmtCompact(w.requests)}
          delta={<><b>{fmtNum(k.requests_total)}</b> lifetime · {fmtNum(w.errors)} errors</>} watermark="求"
          spark={reqSpark} sparkColor="var(--washi-mut)" />
        <KpiCard label={`Served from cache${w.suffix}`} value={(hitRate * 100).toFixed(1) + "%"} accent="jade"
          delta={<><b>{fmtCompact(w.cacheHits)}</b> hits{w.windowed ? ` in ${win}d` : " total"}</>} watermark="蔵"
          spark={hitSpark} sparkColor="var(--jade)" />
        <KpiCard label={`Blocked${w.suffix}`} value={fmtNum(w.blocked)} accent="verm"
          delta={<>423 Locked + 403 Forbidden</>} watermark="封"
          spark={blkSpark} sparkColor="var(--vermilion)" />
        {/* Quarantine is a current-state gauge, not a daily flow: no window. */}
        <KpiCard label="In quarantine" value={fmtNum(k.quarantined)} accent="gold"
          delta={<>held until min-age maturity</>} watermark="守"
          spark={qSpark} sparkColor="var(--gold)" />
      </div>
```

- [ ] **Step 4: Feed the block breakdown from the window**

In the `<div className="card breakdown">` block (currently `overview.jsx:85-103`) replace the four values only, leaving the labels and colours as they are:

- `{fmtNum(k.supply_blocked)}` → `{fmtNum(w.supplyBlocked)}`
- `{fmtNum(k.cve_blocked)}` → `{fmtNum(w.cveBlocked)}`
- `{fmtNum(k.malware_blocked)}` → `{fmtNum(w.malwareBlocked)}`
- `{fmtNum(k.denylisted)}` → `{fmtNum(w.denylisted)}`

- [ ] **Step 5: Rebuild the bundle and the binary**

Run:

```bash
go generate ./web
go build ./...
```

Expected: both silent. `git status --short` now shows `web/console/src/overview.jsx` and `web/console/app.bundle.js` modified.

- [ ] **Step 6: Verify in a browser**

Run the binary against your dev config and open `/console/`. There is no JS test runner here, so this manual pass *is* the verification — do it, don't assume it:

1. With ≥2 days of history, click **7d** and **30d**. Every KPI value except "In quarantine" changes, and the labels read `Requests · 7d` / `Requests · 30d`.
2. The block-breakdown numbers change with the toggle too.
3. The 30d numbers are ≤ the lifetime counters shown in the "lifetime" delta line (retention is 365 days for daily rows, so 30d is a subset).
4. Point a package manager at the proxy so a request lands: the sparklines and the windowed values both move on the next 15-second poll.
5. Against a database with <2 daily rows (or `database.path` unset), the toggle is absent, labels read `· total`, and values match the lifetime counters — identical to `main`.

- [ ] **Step 7: Commit**

```bash
git add web/console/src/overview.jsx web/console/app.bundle.js
git commit -m "fix(console): make the 7d/30d toggle move the KPI values

The window slice fed only the sparklines; every card and the block
breakdown read the lifetime counters, so the pictures moved and the
numbers did not. Sum the daily rows inside the window instead, and keep
the lifetime fallback for installs with fewer than two days of history.
Quarantine stays unwindowed: it is a current-state gauge with no daily
counter."
```

---

### Task 2: Live Feed pages 20 rows at a time

**Files:**
- Modify: `web/console/src/feed.jsx:41` (`PAGE_SIZE`), `:44-211` (`LiveFeed`)
- Regenerate: `web/console/app.bundle.js`

**Interfaces:**
- Consumes: `JOEI.pageRequests({verdict, cursor, limit})` from `api.js` — returns `{rows, nextCursor}`; the server honours `limit`.
- Produces: nothing consumed by other tasks.

**Background.** Two listing modes share this screen. History filters (`BLOCK`, `ERROR` — `HISTORY_FILTERS`) are server-paged with `PAGE_SIZE = 50`. Live filters (`all`, `PASS`, `CACHE`) render the entire in-memory window — up to 120 rows — with no paging at all. Both become 20 per page, and the live side gets the same **Show more** affordance the history side already has.

The live buffer stays at 120 rows: it is what SSE prepends into and what a "Show more" reveals from. Only the *rendered* slice is capped.

- [ ] **Step 1: Set the page size**

In `web/console/src/feed.jsx`, replace:

```jsx
const PAGE_SIZE = 50;
```

with:

```jsx
// One page, for both listing modes: the live window reveals rows from the
// in-memory buffer, the history filters fetch this many per server page.
const PAGE_SIZE = 20;
```

- [ ] **Step 2: Add the live-mode page state**

After the `const [newId, setNewId] = useState(null);` line (currently `feed.jsx:50`), add:

```jsx
  // How many live rows are rendered. History mode ignores it — the server
  // already pages there — so this only ever grows via "Show more" below.
  const [visible, setVisible] = useState(PAGE_SIZE);
```

- [ ] **Step 3: Reset paging when the filter or the search term changes**

Immediately after the existing `const history = !!HISTORY_FILTERS[filter];` line (currently `feed.jsx:60`), add:

```jsx
  // A new filter or query restarts at the first page; without this, narrowing
  // a search would keep an inflated row count from the previous filter.
  useEffect(() => { setVisible(PAGE_SIZE); }, [filter, q]);
```

- [ ] **Step 4: Render one page**

Replace:

```jsx
  const source = history ? histRows : rows;
  const shown = source.filter((r) => {
```

…leaving the filter body untouched, and add a `page` line after the closing `});` of that filter (currently `feed.jsx:120`):

```jsx
  // History rows arrive one server page at a time and accumulate on "Show
  // more", so they are rendered whole; the live window is sliced client-side.
  const page = history ? shown : shown.slice(0, visible);
```

- [ ] **Step 5: Render `page` instead of `shown`, and report both counts**

Replace the count in the toolbar (currently `feed.jsx:158`):

```jsx
          <span className="right muted mono" style={{ fontSize: 12 }}>{shown.length} shown</span>
```

with:

```jsx
          <span className="right muted mono" style={{ fontSize: 12 }}>
            {page.length < shown.length ? `${page.length} of ${shown.length} shown` : `${shown.length} shown`}
          </span>
```

and replace the row map (currently `feed.jsx:181-183`):

```jsx
          shown.map((r) => (
            <FeedRow key={r.request_id} r={r} onOpen={openThreat} isNew={r.request_id === newId} />
          ))
```

with:

```jsx
          page.map((r) => (
            <FeedRow key={r.request_id} r={r} onOpen={openThreat} isNew={r.request_id === newId} />
          ))
```

Leave the empty-state condition on `shown.length === 0` as it is: an empty page with a non-empty result set cannot happen, since `visible` never drops below `PAGE_SIZE`.

- [ ] **Step 6: Give live mode its own Show more**

Extend the footer chain at the end of the card (currently `feed.jsx:186-200`) with a third branch. The final `: null}` becomes:

```jsx
        ) : !history && page.length < shown.length ? (
          <div style={{ padding: "12px", textAlign: "center", borderTop: "1px solid var(--washi-faint)" }}>
            <button className="btn sm ghost" onClick={() => setVisible((n) => n + PAGE_SIZE)}>Show more</button>
          </div>
        ) : null}
```

- [ ] **Step 7: Rebuild and verify in a browser**

Run:

```bash
go generate ./web
go build ./...
```

Then, with traffic flowing through the proxy (a `pip download` loop is enough to fill the buffer):

1. **All** tab shows 20 rows, footer reads **Show more**, counter reads `20 of N shown`.
2. Clicking **Show more** adds 20; the counter follows; the button disappears once every buffered row is rendered.
3. New requests still appear at the top live, and the page does not collapse back to 20 when they do.
4. Switching to **Passed** or **Cache** resets to 20; typing in the search box resets to 20.
5. **Blocked** and **Error** (server-paged) load 20 rows per page — verify in the browser's network tab that the request carries `limit=20` — and **Show more** appends the next 20.
6. **Pause stream**, then **Show more**: paging still works while paused.

- [ ] **Step 8: Commit**

```bash
git add web/console/src/feed.jsx web/console/app.bundle.js
git commit -m "fix(console): page the request feed 20 rows at a time

History filters paged at 50 and the live filters did not page at all,
rendering the whole 120-row buffer. Both now show 20 per page behind the
same Show more button; the live buffer is unchanged, only the rendered
slice is capped, so SSE rows keep landing at the top."
```

---

### Task 3: The gate badge reports real scanner health

**Files:**
- Modify: `web/console/src/app.jsx:59-100` (`App` state and subscriptions), `:175` (the badge)
- Modify: `web/console/screens.css:212-216` (dot colours for the two unstyled statuses)
- Regenerate: `web/console/app.bundle.js`

**Interfaces:**
- Consumes: `JOEI.scanners` — `[{name, detail, status, latency}]` where `status` is one of `ok | warn | down | unknown | off` (mapped in `api.js:applyOverview`, produced by `internal/health.Snapshot`); `JOEI.connected`.
- Produces: nothing consumed by other tasks.

**Background.** `app.jsx:175` is a literal: `<span className="health ok">…gate healthy</span>`. It has always been green because nothing computes it. The per-engine statuses are already loaded for the hero's `ScannerStrip`, so this is a derivation, not a data problem.

Semantics agreed for the badge: `off` (configured but not attached by the active profile) and `unknown` (never probed yet) are **not** failures and stay green — otherwise every boot spends its first 30 seconds looking broken.

- [ ] **Step 1: Track scanners in the App component's state**

In `web/console/src/app.jsx`, after `const [connected, setConnected] = useState(JOEI.connected);` (currently `app.jsx:68`), add:

```jsx
  const [scanners, setScanners] = useState(JOEI.scanners);
```

and in the `onData` callback inside the existing subscription effect (currently `app.jsx:84`), extend it:

```jsx
    const onData = () => { setLoading(false); setPolicyState(JOEI.policy); setScanners(JOEI.scanners); };
```

- [ ] **Step 2: Derive the badge**

After the `const meta = PAGE_META[page];` line (currently `app.jsx:144`), add:

```jsx
  // The sidebar badge reports the worst scan-engine status. "off" (configured
  // but not attached by the active profile) and "unknown" (not probed yet) are
  // not failures, so they stay green — otherwise every boot looks broken for
  // its first probe interval. A dead API outranks everything.
  const down = scanners.filter((s) => s.status === "down");
  const warn = scanners.filter((s) => s.status === "warn");
  const gate = !connected
    ? { cls: "off", label: "no connection", title: "The console cannot reach the API" }
    : down.length
    ? { cls: "down", label: "gate degraded", title: `Not responding: ${down.map((s) => s.name).join(", ")}` }
    : warn.length
    ? { cls: "warn", label: "gate slow", title: `Slow to respond: ${warn.map((s) => s.name).join(", ")}` }
    : { cls: "ok", label: "gate healthy", title: "All attached scan engines are responding" };
```

- [ ] **Step 3: Render it**

Replace (currently `app.jsx:175`):

```jsx
            <span className="health ok" style={{ fontSize: 11 }}><i className="hdot"></i>gate healthy</span>
```

with:

```jsx
            <span className={`health ${gate.cls}`} style={{ fontSize: 11 }} title={gate.title}><i className="hdot"></i>{gate.label}</span>
```

- [ ] **Step 4: Give `off` and `unknown` a visible dot**

`screens.css` styles `.health.ok`, `.health.warn` and `.health.down` only, so an `off`/`unknown` engine currently renders a zero-colour dot — visible in the hero's scanner strip too. After the `.health.down .hdot` rule (currently `screens.css:216`) add:

```css
.health.off .hdot, .health.unknown .hdot { background: var(--washi-faint); }
```

- [ ] **Step 5: Rebuild and verify in a browser**

Run:

```bash
go generate ./web
go build ./...
```

Then:

1. With every configured scanner up: badge is green, reads **gate healthy**, tooltip names no engine.
2. Stop one scanner (`docker compose stop clamav`, or point `malware.scanners[].address` at a dead port) and wait one probe interval (30s default): the badge turns vermilion, reads **gate degraded**, and the tooltip names the stopped engine. The hero's scanner strip shows the same engine red — the two must agree.
3. Restart the scanner: within a probe interval the badge returns to green.
4. Stop the proxy while the console tab is open: the badge goes grey, reads **no connection**, and the existing connection banner appears.
5. With `malware.scanners` empty (no engines configured at all): badge is green — nothing is failing.

- [ ] **Step 6: Commit**

```bash
git add web/console/src/app.jsx web/console/screens.css web/console/app.bundle.js
git commit -m "fix(console): derive the gate badge from scanner health

The sidebar badge was a hardcoded green literal, so a dead scan engine
never surfaced there. Report the worst status instead: down -> degraded,
warn -> slow, API unreachable -> no connection. 'off' and 'unknown' are
not failures and stay green. Also colours the previously unstyled off and
unknown dots, which the hero scanner strip renders too."
```

---

### Task 4: Ship it

**Files:**
- Modify: `CHANGELOG.md` (Unreleased section)

- [ ] **Step 1: Add the changelog entries**

Under `## [Unreleased]` → `### Fixed` (create the heading if the section has none), add:

```markdown
- **Console overview:** the 7d/30d toggle now moves the KPI values and the
  block breakdown, not only the sparklines.
- **Console feed:** both the live and the history listings page 20 rows at a
  time behind a "Show more" button (history previously fetched 50; the live
  window rendered all 120 buffered rows).
- **Console sidebar:** the gate badge reports the worst scan-engine status
  instead of a hardcoded "gate healthy".
```

- [ ] **Step 2: Full check before pushing**

Run:

```bash
go generate ./web
go build ./...
go test ./...
git status --short
```

Expected: build and tests green; `git status` shows only `CHANGELOG.md` (every other change is already committed, and the regenerated bundle is byte-identical to the committed one — if it is not, you skipped a `go generate` in an earlier task; commit the difference and say so in the PR).

- [ ] **Step 3: Commit and push**

```bash
git add CHANGELOG.md
git commit -m "docs: changelog for the console bugfixes"
git push -u origin fix/console-bugfixes
```

- [ ] **Step 4: Open the PR into main**

```bash
gh pr create --base main --title "fix(console): 7d/30d values, 20-row feed paging, real gate badge" --body "$(cat <<'EOF'
Three console defects reported from production use.

**Overview 7d/30d** — the window slice fed only the sparklines; every KPI card
and the block breakdown read lifetime counters. They now sum the daily rows
inside the window. "In quarantine" stays unwindowed — it is a current-state
gauge with no daily counter. Installs with fewer than two days of history keep
the lifetime numbers and the "· total" wording, exactly as before.

**Live Request Feed** — history filters paged at 50, live filters did not page
at all and rendered the whole 120-row buffer. Both now show 20 per page behind
the same "Show more" button. The live buffer is unchanged; only the rendered
slice is capped, so SSE rows keep landing at the top.

**Gate badge** — was a hardcoded green literal. It now reports the worst
scan-engine status (down → degraded, warn → slow, API unreachable → no
connection); "off" and "unknown" are not failures and stay green. The
previously unstyled off/unknown dots get a colour, which the hero's scanner
strip renders too.

Client-side only: no API, handler, or schema change. This repository has no
JavaScript test runner by design, so verification was `go generate ./web` +
`go build ./...` + `go test ./...` green, plus a manual pass over each of the
three flows (both windows with and without history, both paging modes with a
scanner stopped and restarted, and the disconnected state).
EOF
)"
```

---

## Self-Review

**Coverage.** Bug 1 → Task 1 (KPI cards, breakdown, eyebrow, sub-2-row fallback, quarantine exemption). Bug 2 → Task 2 (`PAGE_SIZE` 20 for the server pages, `visible` slice plus Show more for the live window, reset on filter/search). Bug 3 → Task 3 (derived badge, worst-status precedence, disconnected state, `off`/`unknown` dot colour). Bundle regeneration and the changelog are folded into the tasks that need them; Task 4 carries the release note and the PR.

**Placeholders.** None: every step names the file, quotes the line it replaces, and gives the replacement verbatim.

**Consistency.** `w`/`sum`/`hitRate` are introduced in Task 1 Step 1 and used in Steps 2-4 under exactly those names. `visible`/`page`/`PAGE_SIZE` are introduced in Task 2 Steps 1-4 and used in Steps 5-6. `scanners`/`down`/`warn`/`gate` are introduced in Task 3 Steps 1-2 and used in Step 3. The status vocabulary (`ok|warn|down|unknown|off`) matches `internal/health/health.go:17-23` and the `.health.*` CSS classes.
