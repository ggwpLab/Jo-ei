# Overview Gate Procession — Real Data Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drive the Overview hero's gate-procession animation from real request history (`window.JOEI.requests`) instead of a hardcoded `FLOW` array.

**Architecture:** A new pure helper `buildFlow()` maps the live history rows already loaded by `api.js` into the procession's `{ pkg, eco, block }` token shape. `useGateFlow` holds that list as a state snapshot: it shows an idle pipeline when history is empty, comes alive when the first traffic arrives, and re-snapshots the live history each time the procession completes a full loop. All changes are confined to `web/console/hero.jsx`.

**Tech Stack:** React 18 + Babel-standalone (in-browser, no build step), served as a Go `go:embed` static bundle at `/console/`. No JS test harness exists; logic is verified with a throwaway Node script and the full page is verified by running the console.

---

## Background for the implementer

- `web/console/hero.jsx` is browser-served JSX compiled at runtime by Babel-standalone (see `web/console/index.html`). There is **no** bundler, npm install, or JS unit-test runner in this repo. Do not add one.
- `web/console/api.js` already populates `window.JOEI.requests` — up to 500 real request rows from `GET /api/requests?limit=500`, refreshed every 15s by polling and prepended live from the `/api/events` SSE stream. Each row has: `pkg`, `ver`, `eco`, `verdict` (`"PASS"` / `"CACHE"` / `"BLOCK"`), `blocked_by` (array of gate keys for blocked rows), `gate`.
- `window.JOEI.ECO` is a map of ecosystem id → `{ id, label, name }`. The procession token renders `JOEI.ECO[eco].label`, so an unknown `eco` must be guarded or it throws.
- `GATE_ORDER = ["cache", "supply", "cve", "malware"]` is the gate index order. A token's `block` field is the index of the gate it is rejected at, or `null` if it passes all gates.
- The console is served at `http://localhost:8080/console/`. Run it with `make run` (which runs `go run ./cmd/jo-ei --config config.yaml`). Because the console is `go:embed`-ed, **edited `.jsx` files require restarting `make run`** to be re-embedded and served.
- `FLOW` and `useGateFlow` are referenced only inside `hero.jsx` (verified by grep). Removing/renaming them affects no other file.

The current `hero.jsx` lines 3-56 are the area being changed:

```js
const GATE_ORDER = ["cache", "supply", "cve", "malware"];

// scripted procession of packages through the gates
const FLOW = [
  { pkg: "requests", eco: "pypi", block: null },
  { pkg: "log4j-core", eco: "maven", block: 2 },   // blocked at CVE
  { pkg: "lodash", eco: "npm", block: null },
  { pkg: "event-stream", eco: "npm", block: 3 },    // blocked at Malware
  { pkg: "numpy", eco: "pypi", block: null },
  { pkg: "freshtelemetry", eco: "npm", block: 1 },  // blocked at Supply Chain (423)
  { pkg: "cryptography", eco: "pypi", block: 2 },    // CVE
  { pkg: "axios", eco: "npm", block: null },
];

// drives the left→right token + per-gate glow
function useGateFlow(enabled) {
  const [run, setRun] = useState(0);
  const [step, setStep] = useState(0); // 0 entering, 1..4 at gate, 5 exited
  const cur = FLOW[run % FLOW.length];

  useEffect(() => {
    if (!enabled) return;
    let blocked = false;
    const tick = () => {
      setStep((s) => {
        const f = FLOW[run % FLOW.length];
        // if just arrived at a block gate, hold then advance run
        if (f.block !== null && s === f.block + 1) {
          blocked = true;
          setTimeout(() => { setRun((r) => r + 1); setStep(0); blocked = false; }, 1700);
          return s;
        }
        if (s >= 5) { setRun((r) => r + 1); return 0; }
        return s + 1;
      });
    };
    const id = setInterval(() => { if (!blocked) tick(); }, 1150);
    return () => clearInterval(id);
  }, [run, enabled]);

  // token horizontal position (%)
  const leftPct = [2, 12.5, 37.5, 62.5, 87.5, 102][Math.min(step, 5)];
  const atGate = step >= 1 && step <= 4 ? step - 1 : -1;
  const blockedHere = cur.block !== null && atGate === cur.block;
  const tokenState = blockedHere ? "rejected" : step >= 5 ? "purified" : "";

  // per-gate glow: pass while token currently sits at it (not blocked), block if stuck
  const glow = GATE_ORDER.map((_, i) => {
    if (atGate === i) return blockedHere ? "block" : "pass";
    return "idle";
  });

  return { cur, step, leftPct, atGate, tokenState, glow };
}
```

---

## Task 1: Add `buildFlow()` helper and gate-index map

Add the pure mapping helper alongside `FLOW`. `FLOW` and `useGateFlow` stay untouched in this task, so the page keeps working exactly as before — this task is purely additive and independently verifiable.

**Files:**
- Modify: `web/console/hero.jsx` (insert after the `GATE_ORDER` declaration on line 3, before the `FLOW` comment on line 5)

- [ ] **Step 1: Insert the helper and mapping table**

Insert these lines immediately **after** line 3 (`const GATE_ORDER = ["cache", "supply", "cve", "malware"];`) and **before** the existing `// scripted procession of packages through the gates` comment:

```js

// Maps a blocked request's gate key to its index in GATE_ORDER. Several keys
// collapse onto the Supply Chain gate: min-age holds, denylist, and the
// alternate "supply_chain" spelling all surface there.
const GATE_BLOCK_INDEX = {
  cache: 0, supply: 1, supply_chain: 1, denylist: 1, cve: 2, malware: 3,
};

// How many recent requests the procession cycles through before re-snapshotting.
const FLOW_LEN = 12;

// Builds the procession token list { pkg, eco, block } from the live request
// history. block === null means "passed every gate"; a number is the gate index
// the package was rejected at. Returns [] when there is no history yet.
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

- [ ] **Step 2: Write a throwaway Node check for the mapping logic**

There is no JS test runner, so verify the pure logic with a temporary Node script. Create `web/console/_buildflow_check.cjs` whose `buildFlow` body is **copied verbatim** from Step 1 (same lines, only the `window` reference satisfied by a stub):

```js
// TEMPORARY verification scratch — delete after running. Not committed.
const GATE_BLOCK_INDEX = {
  cache: 0, supply: 1, supply_chain: 1, denylist: 1, cve: 2, malware: 3,
};
const FLOW_LEN = 12;
function buildFlow() {
  const reqs = (window.JOEI.requests || []).slice(0, FLOW_LEN);
  return reqs.map((r) => {
    const eco = window.JOEI.ECO[r.eco] ? r.eco : "pypi";
    let block = null;
    if (r.verdict === "BLOCK") {
      const key = (r.blocked_by && r.blocked_by[0]) || "supply";
      block = GATE_BLOCK_INDEX[key] != null ? GATE_BLOCK_INDEX[key] : 1;
    }
    return { pkg: r.pkg, eco, block };
  });
}

global.window = {
  JOEI: {
    ECO: { pypi: { label: "py" }, npm: { label: "npm" }, maven: { label: "mvn" } },
    requests: [
      { pkg: "numpy",        eco: "pypi",    verdict: "PASS",  blocked_by: [] },
      { pkg: "log4j-core",   eco: "maven",   verdict: "BLOCK", blocked_by: ["cve"] },
      { pkg: "event-stream", eco: "npm",     verdict: "BLOCK", blocked_by: ["malware"] },
      { pkg: "telemetry",    eco: "npm",     verdict: "BLOCK", blocked_by: ["supply_chain"] },
      { pkg: "shady",        eco: "npm",     verdict: "BLOCK", blocked_by: ["denylist"] },
      { pkg: "weird",        eco: "unknown", verdict: "PASS",  blocked_by: [] },
      { pkg: "mystery",      eco: "npm",     verdict: "BLOCK", blocked_by: [] },
      { pkg: "lodash",       eco: "npm",     verdict: "CACHE", blocked_by: [] },
    ],
  },
};

const out = buildFlow();
const expected = [
  { pkg: "numpy",        eco: "pypi", block: null },
  { pkg: "log4j-core",   eco: "maven", block: 2 },
  { pkg: "event-stream", eco: "npm",  block: 3 },
  { pkg: "telemetry",    eco: "npm",  block: 1 },
  { pkg: "shady",        eco: "npm",  block: 1 },
  { pkg: "weird",        eco: "pypi", block: null }, // unknown eco -> pypi fallback
  { pkg: "mystery",      eco: "npm",  block: 1 },    // BLOCK w/ empty blocked_by -> supply
  { pkg: "lodash",       eco: "npm",  block: null }, // CACHE -> passes
];
const ok = JSON.stringify(out) === JSON.stringify(expected);
console.log(ok ? "PASS" : "FAIL");
if (!ok) { console.log("got:     ", JSON.stringify(out)); console.log("expected:", JSON.stringify(expected)); }
process.exit(ok ? 0 : 1);
```

- [ ] **Step 3: Run the check and confirm it passes**

Run: `node web/console/_buildflow_check.cjs`
Expected output: `PASS`

- [ ] **Step 4: Delete the throwaway script**

Run: `rm web/console/_buildflow_check.cjs`

- [ ] **Step 5: Commit**

```bash
git add web/console/hero.jsx
git commit -m "feat(web): add buildFlow() to derive procession from real history"
```

---

## Task 2: Drive `useGateFlow` from the live snapshot + idle state, and guard the rendering

This is the atomic "use real data" change. The hook now returns `cur === null` and `idle === true` when there is no history, so the token render in `Procession` and the `stateLabel` in `GateHero` MUST be guarded in the same commit — otherwise an empty history dereferences `null` and breaks the hero. All three edits land together.

**Files:**
- Modify: `web/console/hero.jsx` — replace `useGateFlow` (currently lines 18-56); guard the token in `Procession` (currently lines 85-88); guard `stateLabel` in `GateHero` (currently lines 182-186)

- [ ] **Step 1: Replace the `useGateFlow` function**

Replace the entire existing `useGateFlow` function (from `// drives the left→right token + per-gate glow` through its closing `}`) with:

```js
// drives the left→right token + per-gate glow, fed by real request history
function useGateFlow(enabled) {
  const [flowList, setFlowList] = useState(buildFlow);
  const [run, setRun] = useState(0);
  const [step, setStep] = useState(0); // 0 entering, 1..4 at gate, 5 exited

  const idle = flowList.length === 0;

  // While idle (no history yet) the loop never runs, so it can't re-snapshot on
  // its own. Listen for fresh data and rebuild once traffic appears so the
  // animation comes to life. When already running, the loop boundary refreshes.
  useEffect(() => {
    const onData = () => setFlowList((prev) => (prev.length === 0 ? buildFlow() : prev));
    window.addEventListener("joei:data", onData);
    window.addEventListener("joei:event", onData);
    return () => {
      window.removeEventListener("joei:data", onData);
      window.removeEventListener("joei:event", onData);
    };
  }, []);

  useEffect(() => {
    if (!enabled || idle) return;
    let blocked = false;
    // Advance to the next package; at the end of the list re-snapshot the live
    // history and restart the loop ("new requests picked up on the next cycle").
    const advanceRun = () => setRun((r) => {
      const next = r + 1;
      if (next >= flowList.length) { setFlowList(buildFlow()); return 0; }
      return next;
    });
    const tick = () => {
      setStep((s) => {
        const f = flowList[run % flowList.length];
        // if just arrived at a block gate, hold then advance run
        if (f.block !== null && s === f.block + 1) {
          blocked = true;
          setTimeout(() => { advanceRun(); setStep(0); blocked = false; }, 1700);
          return s;
        }
        if (s >= 5) { advanceRun(); return 0; }
        return s + 1;
      });
    };
    const id = setInterval(() => { if (!blocked) tick(); }, 1150);
    return () => clearInterval(id);
  }, [run, enabled, idle, flowList]);

  const cur = idle ? null : flowList[run % flowList.length];

  // token horizontal position (%)
  const leftPct = [2, 12.5, 37.5, 62.5, 87.5, 102][Math.min(step, 5)];
  const atGate = step >= 1 && step <= 4 ? step - 1 : -1;
  const blockedHere = !idle && cur.block !== null && atGate === cur.block;
  const tokenState = blockedHere ? "rejected" : step >= 5 ? "purified" : "";

  // per-gate glow: pass while token currently sits at it (not blocked), block if
  // stuck. All gates rest while idle.
  const glow = GATE_ORDER.map((_, i) => {
    if (idle) return "idle";
    if (atGate === i) return blockedHere ? "block" : "pass";
    return "idle";
  });

  return { cur, idle, step, leftPct, atGate, tokenState, glow };
}
```

- [ ] **Step 2: Guard the travelling token in `Procession`**

In the `Procession` function, find the travelling token block (currently lines 85-88):

```jsx
      {/* traveling package token */}
      <div className={`token ${flow.tokenState}`} style={{ left: flow.leftPct + "%", top: "78px" }}>
        {JOEI.ECO[flow.cur.eco].label}
      </div>
```

Replace it with a version that renders nothing while idle (so `flow.cur` is never dereferenced when null):

```jsx
      {/* traveling package token — hidden until there is real traffic */}
      {!flow.idle && (
        <div className={`token ${flow.tokenState}`} style={{ left: flow.leftPct + "%", top: "78px" }}>
          {JOEI.ECO[flow.cur.eco].label}
        </div>
      )}
```

- [ ] **Step 3: Guard `stateLabel` in `GateHero`**

In `GateHero`, find the `stateLabel` declaration (currently lines 182-186):

```js
  const stateLabel = flow.tokenState === "rejected"
    ? `✕ ${flow.cur.pkg} rejected at ${stats[GATE_ORDER[flow.cur.block]].label}`
    : flow.tokenState === "purified"
    ? `✓ ${flow.cur.pkg} purified — served`
    : `Purifying ${flow.cur.pkg}…`;
```

Replace it with an idle-first version:

```js
  const stateLabel = flow.idle
    ? "Awaiting traffic — no requests yet"
    : flow.tokenState === "rejected"
    ? `✕ ${flow.cur.pkg} rejected at ${stats[GATE_ORDER[flow.cur.block]].label}`
    : flow.tokenState === "purified"
    ? `✓ ${flow.cur.pkg} purified — served`
    : `Purifying ${flow.cur.pkg}…`;
```

(The state-label color span already falls back to gold when `flow.tokenState` is `""`, which is the idle case — no change needed there.)

- [ ] **Step 4: Run the console and verify behavior**

Run: `make run` (serves on `:8080`; the console is re-embedded on each start, so restart it after editing). Open `http://localhost:8080/console/`.

Verify, on the Overview tab:
- With **no traffic yet** (fresh start, before pointing any package manager at the proxy): the four gates render at rest, no token moves, and the hero state line reads "Awaiting traffic — no requests yet".
- After generating traffic (e.g. `pip install --index-url http://localhost:8080/pypi/simple <pkg>` or any request that appears in the Live feed): tokens carry **real package names** matching the feed, passed packages travel the full pipeline and exit "purified", and blocked packages stop at the gate matching their feed row (CVE-blocked at CVE, malware at Malware, supply/denylist at Supply Chain).
- All three treatment buttons (Procession / Lanterns / Ink Scroll) still switch and animate.
- Browser devtools console shows no errors (no "Cannot read properties of null").

- [ ] **Step 5: Commit**

```bash
git add web/console/hero.jsx
git commit -m "feat(web): drive gate procession from live request history"
```

---

## Task 3: Remove the dead static `FLOW` constant and its export

With `useGateFlow` no longer referencing `FLOW`, the hardcoded array is dead code. Remove it and drop it from the window export.

**Files:**
- Modify: `web/console/hero.jsx` — delete the `FLOW` constant (the `// scripted procession…` comment plus the array) and remove `FLOW` from the final `Object.assign`

- [ ] **Step 1: Delete the static `FLOW` array**

Remove this block (the comment + constant that currently sits just above `useGateFlow`):

```js
// scripted procession of packages through the gates
const FLOW = [
  { pkg: "requests", eco: "pypi", block: null },
  { pkg: "log4j-core", eco: "maven", block: 2 },   // blocked at CVE
  { pkg: "lodash", eco: "npm", block: null },
  { pkg: "event-stream", eco: "npm", block: 3 },    // blocked at Malware
  { pkg: "numpy", eco: "pypi", block: null },
  { pkg: "freshtelemetry", eco: "npm", block: 1 },  // blocked at Supply Chain (423)
  { pkg: "cryptography", eco: "pypi", block: 2 },    // CVE
  { pkg: "axios", eco: "npm", block: null },
];
```

- [ ] **Step 2: Drop `FLOW` from the window export**

Find the export line at the bottom of `hero.jsx`:

```js
Object.assign(window, { GateHero, useGateFlow, GATE_ORDER, FLOW });
```

Replace it with:

```js
Object.assign(window, { GateHero, useGateFlow, GATE_ORDER });
```

- [ ] **Step 3: Confirm no remaining references to `FLOW`**

Run: `grep -rn "\bFLOW\b" web/console/`
Expected: only `FLOW_LEN` matches (from `buildFlow`); **no** bare `FLOW` references remain.

- [ ] **Step 4: Restart the console and confirm it still renders**

Run: `make run`, open `http://localhost:8080/console/`, Overview tab.
Expected: hero renders identically to Task 2's verified behavior (idle when empty, real packages when there is traffic); no devtools console errors.

- [ ] **Step 5: Commit**

```bash
git add web/console/hero.jsx
git commit -m "refactor(web): drop dead static FLOW array from hero"
```

---

## Self-review notes

- **Spec coverage:** `buildFlow()` + gate map (Task 1) ✓; last-N-from-history source (`FLOW_LEN = 12` slice) ✓; idle empty state with "awaiting traffic" label (Task 2 hook + render guards) ✓; loop-boundary re-snapshot for live pickup (`advanceRun` boundary) ✓; first-traffic wake-up via `joei:data`/`joei:event` (Task 2 listener) ✓; unknown-ecosystem and empty-`blocked_by` guards (Task 1) ✓; export cleanup / `FLOW` removal (Task 3) ✓; "files touched: hero.jsx only" ✓.
- **No backend / api.js / CSS changes** — token is hidden when idle, so no idle-token CSS class is needed (the spec flagged CSS as only a possibility).
- **Type consistency:** the hook's return object gains `idle`; both consumers (`Procession` token guard, `GateHero.stateLabel`) read `flow.idle` and `flow.cur` with the null-guard in place. `buildFlow`, `GATE_BLOCK_INDEX`, `FLOW_LEN` names are used identically across tasks.
- **No automated frontend tests exist** in the repo by design; Task 1 uses a throwaway Node check for the pure mapping, Tasks 2-3 use the running console. This matches the spec's stated verification approach.
