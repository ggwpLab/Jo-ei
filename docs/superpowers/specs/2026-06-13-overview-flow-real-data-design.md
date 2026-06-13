# Overview hero: real data in the gate procession animation

**Date:** 2026-06-13
**Status:** Approved design, pending implementation plan
**Scope:** `web/console/hero.jsx` only (frontend, no backend changes)

## Problem

The Overview tab's hero block animates packages travelling left→right through the
four gates (Cache → Supply Chain → CVE → Malware). The procession is driven by a
hardcoded `FLOW` array in `hero.jsx`:

```js
const FLOW = [
  { pkg: "requests", eco: "pypi", block: null },
  { pkg: "log4j-core", eco: "maven", block: 2 },
  ...
];
```

These are invented packages and verdicts. The user wants the animation to reflect
**real traffic** — the actual request history the console already loads.

## What we already have

`web/console/api.js` populates `window.JOEI.requests` with up to 500 real request
rows (`GET /api/requests?limit=500`), refreshed every 15s by polling and prepended
live from the SSE stream (`/api/events`). Each row carries everything we need:

- `pkg`, `ver`, `eco`
- `verdict` (`"PASS"` / `"CACHE"` / `"BLOCK"`)
- `blocked_by` — array of gate keys for blocked requests (`"supply"`,
  `"supply_chain"`, `"denylist"`, `"cve"`, `"malware"`, `"cache"`)
- `gate` — the gate a passed request was served from

The procession token shape `{ pkg, eco, block }` (where `block` is an index into
`GATE_ORDER = ["cache", "supply", "cve", "malware"]`, or `null` for "passed all
gates") maps cleanly onto this data.

## Decisions

| Question | Decision |
|----------|----------|
| Which records feed the procession | Last N requests from history (live mix of passed + blocked, as-is) |
| Empty history (fresh start, zero requests) | Idle gate state — token does not move, gates rest, "awaiting traffic" label |
| New requests arriving over SSE mid-animation | Picked up on the next cycle (snapshot refreshed at procession loop boundary) |

## Design

### 1. `buildFlow()` helper (new, in `hero.jsx`)

Converts the live history into the procession's token list:

```js
const GATE_BLOCK_INDEX = {
  cache: 0, supply: 1, supply_chain: 1, denylist: 1, cve: 2, malware: 3,
};
const FLOW_LEN = 12;

function buildFlow() {
  const reqs = (window.JOEI.requests || []).slice(0, FLOW_LEN);
  return reqs.map((r) => {
    const eco = window.JOEI.ECO[r.eco] ? r.eco : "pypi"; // guard unknown ecosystem
    let block = null;
    if (r.verdict === "BLOCK") {
      const key = (r.blocked_by && r.blocked_by[0]) || "supply";
      block = GATE_BLOCK_INDEX[key] != null ? GATE_BLOCK_INDEX[key] : 1;
    }
    return { pkg: r.pkg, eco, block };
  });
}
```

Notes:
- Unknown ecosystem falls back to `pypi` (same defensive pattern already used in the
  quarantine card). The token label comes from `JOEI.ECO[eco].label`, so an unguarded
  unknown eco would throw.
- A `BLOCK` with a missing/unknown `blocked_by[0]` falls back to the Supply Chain
  gate (index 1) rather than rendering as "passed", so a block never reads as purified.
- `CACHE`/`PASS` verdicts → `block: null` → token travels the full pipeline and exits
  "purified", which matches today's visual semantics.
- Newest-first order (as `JOEI.requests` already is) is acceptable; ordering is cosmetic
  for a looping demo.

### 2. `useGateFlow(enabled)` — drive from a live snapshot

Replace the global `FLOW` constant with a stateful snapshot:

- Hold `flowList` in state, initialized from `buildFlow()`.
- `idle = flowList.length === 0`. While idle: the interval tick does not run, the token
  stays hidden, and all gate glows are `"idle"`.
- Subscribe to `joei:data` and `joei:event`. When idle and new data appears, rebuild
  `flowList` from `buildFlow()` so the animation comes to life on first traffic.
- When the procession advances past the end of `flowList` (a full loop completes),
  re-snapshot from `buildFlow()` and restart at run 0 — this is the "picked up on the
  next cycle" behavior. The existing 15s poll and SSE prepend keep `JOEI.requests`
  fresh; we simply re-read it at the loop boundary.
- The existing per-step timing, block-and-hold behaviour, `leftPct`, `atGate`,
  `tokenState`, and `glow` logic are preserved unchanged — only the data source moves
  from a constant to state.

The hook returns the same shape as today plus an `idle` flag, and `cur` is `null` when
idle.

### 3. Rendering changes

- `Procession` / `Lanterns` / `InkScroll` receive the same `flow` object. The travelling
  token (only present in `Procession`) is hidden when `flow.idle` is true. Gate glow is
  already `"idle"` for every gate in that case, so the static layout needs no change.
- `GateHero`'s `stateLabel` must guard `flow.cur === null`: show
  "Awaiting traffic — no requests yet" (neutral/gold) instead of dereferencing
  `flow.cur.pkg`.

### Boundaries

- Files touched: `web/console/hero.jsx` only. Possibly one small CSS class in
  `screens.css` if the idle token needs a muted style — but the plan is to hide the
  token entirely when idle, so CSS may be untouched.
- No backend, API, or `api.js` changes — the data already exists.
- The three treatment views and the treatment switcher keep working identically.
- The exported globals (`GateHero`, `useGateFlow`, `GATE_ORDER`) stay; the `FLOW`
  export is removed (it was only consumed internally).

## Testing

`hero.jsx` is browser-served JSX compiled by Babel at runtime; the project has no
frontend unit-test harness. Verification is by:

1. Reasoning through `buildFlow()` against representative history rows (a passed PyPI
   package, a CVE-blocked Maven package, a malware-blocked npm package, an unknown
   ecosystem, a `BLOCK` with empty `blocked_by`).
2. Running the console and observing:
   - **Empty history** → gates idle, no moving token, "awaiting traffic" label.
   - **With real traffic** → tokens carry real package names from the feed, and blocked
     packages stop at the correct gate matching their feed row.
   - New requests appearing in the live feed show up in the procession after the current
     loop completes.

## Out of scope

- Reordering or de-duplicating history for the animation.
- Changing the KPI cards, breakdown, or recent-activity table on the Overview tab.
- Any change to how history is fetched or retained.
