/* 浄衛 Jōei :: GATE PIPELINE HERO — 3 treatments + traveling-token flow */

const GATE_ORDER = ["cache", "supply", "cve", "malware"];

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
    let timeoutId = null;
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
          timeoutId = setTimeout(() => { advanceRun(); setStep(0); blocked = false; }, 1700);
          return s;
        }
        if (s >= 5) { advanceRun(); return 0; }
        return s + 1;
      });
    };
    const id = setInterval(() => { if (!blocked) tick(); }, 1150);
    return () => { clearInterval(id); if (timeoutId !== null) clearTimeout(timeoutId); };
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

/* ---------- Treatment 1: PROCESSION ---------- */
function Procession({ flow, stats }) {
  return (
    <div className="pipeline">
      <div className="procession">
        <div className="proc-rail"></div>
        {GATE_ORDER.map((g, i) => {
          const s = stats[g];
          const st = flow.glow[i];
          return (
            <div className={`gate ${st === "idle" ? "" : st}`} key={g}>
              <div style={{ position: "relative" }}>
                <Torii state={st} />
                {s.kanji && <span className="gate-kanji kanji">{s.kanji}</span>}
              </div>
              <div className="gate-meta">
                <div className="gate-name">{s.label}</div>
                <div className="gate-sub">{s.sub}</div>
                <div className="gate-count">
                  <span className="pc">✓ {fmtCompact(s.pass)}</span>
                  {s.block > 0 && <><span className="sep">·</span><span className="bc">✕ {fmtCompact(s.block)}</span></>}
                </div>
              </div>
            </div>
          );
        })}
      </div>
      {/* traveling package token — hidden until there is real traffic */}
      {!flow.idle && (
        <div className={`token ${flow.tokenState}`} style={{ left: flow.leftPct + "%", top: "78px" }}>
          {JOEI.ECO[flow.cur.eco].label}
        </div>
      )}
    </div>
  );
}

/* ---------- Treatment 2: LANTERNS ---------- */
function Lanterns({ flow, stats }) {
  return (
    <div className="pipeline">
      <div className="lanterns">
        {GATE_ORDER.map((g, i) => {
          const s = stats[g];
          const st = flow.glow[i];
          return (
            <div className={`lantern ${st === "idle" ? "" : st}`} key={g}>
              <span className="l-idx mono">{String(i + 1).padStart(2, "0")}</span>
              {s.kanji && <span className="lantern-kanji">{s.kanji}</span>}
              <div className="l-name">{s.label}</div>
              <div className="l-sub">{s.sub}</div>
              <div className="l-stat">
                <div className="row"><span className="muted">Passed</span><span className="jade-l" style={{ color: "var(--jade-l)" }}>{fmtCompact(s.pass)}</span></div>
                <div className="row"><span className="muted">Blocked</span><span style={{ color: s.block ? "var(--vermilion-l)" : "var(--washi-faint)" }}>{s.block ? fmtCompact(s.block) : "—"}</span></div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- Treatment 3: INK SCROLL ---------- */
function InkScroll({ flow, stats }) {
  return (
    <div className="pipeline">
      <div className="inkscroll">
        <span className="inkscroll-bg kanji">浄</span>
        <div className="ink-track">
          <svg className="ink-svg" viewBox="0 0 1000 60" preserveAspectRatio="none">
            <path d="M125 30 Q250 6 375 30 T625 30 T875 30" fill="none" stroke="var(--line-strong)" strokeWidth="1.5" strokeDasharray="2 5"/>
          </svg>
          {GATE_ORDER.map((g, i) => {
            const s = stats[g];
            const st = flow.glow[i];
            return (
              <div className={`ink-node ${st === "idle" ? "" : st}`} key={g}>
                <div className="ink-orb">{s.kanji || "◈"}</div>
                <div className="n-name">{s.label}</div>
                <div className="n-sub">{s.sub}</div>
                <div className="n-count">
                  <span style={{ color: "var(--jade-l)" }}>✓{fmtCompact(s.pass)}</span>
                  {s.block > 0 && <span style={{ color: "var(--vermilion-l)" }}>✕{fmtCompact(s.block)}</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ---------- scanner fail-closed strip ---------- */
function ScannerStrip() {
  useJoeiData();
  return (
    <div className="scanner-strip">
      <span className="fc-label">
        <span style={{ color: "var(--jade-l)" }}>● </span>
        Fail-closed
      </span>
      <span className="muted" style={{ fontSize: 12 }}>
        Scanner errors hold requests rather than serving unscanned artifacts.
      </span>
      <div className="right row" style={{ gap: 20 }}>
        {JOEI.scanners.length === 0
          ? <span className="muted" style={{ fontSize: 12 }}>no scanners configured</span>
          : JOEI.scanners.map((s) => (
              <span className={`health ${s.status}`} key={s.name + s.detail} title={s.detail}>
                <i className="hdot"></i>{s.name}
              </span>
            ))}
      </div>
    </div>
  );
}

/* ---------- the hero card ---------- */
function GateHero({ treatment, setTreatment }) {
  useJoeiData();
  const enabled = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const flow = useGateFlow(enabled);
  const stats = JOEI.gateStats;

  const stateLabel = flow.idle
    ? "Awaiting traffic — no requests yet"
    : flow.tokenState === "rejected"
    ? `✕ ${flow.cur.pkg} rejected at ${stats[GATE_ORDER[flow.cur.block]].label}`
    : flow.tokenState === "purified"
    ? `✓ ${flow.cur.pkg} purified — served`
    : `Purifying ${flow.cur.pkg}…`;

  return (
    <div className="card hero">
      <div className="hero-head">
        <div>
          <div className="eyebrow">浄衛 Gate Pipeline · production</div>
          <h2>Every package passes through four sacred gates</h2>
        </div>
        <div className="grow"></div>
        <div className="hero-flow-state">
          <span style={{ color: flow.tokenState === "rejected" ? "var(--vermilion-l)" : flow.tokenState === "purified" ? "var(--jade-l)" : "var(--gold-l)" }}>
            {stateLabel}
          </span>
        </div>
        <div className="treat-switch">
          {[["procession", "Procession"], ["lanterns", "Lanterns"], ["inkscroll", "Ink Scroll"]].map(([k, label]) => (
            <button key={k} className={treatment === k ? "active" : ""} onClick={() => setTreatment(k)}>{label}</button>
          ))}
        </div>
      </div>

      {treatment === "procession" && <Procession flow={flow} stats={stats} />}
      {treatment === "lanterns" && <Lanterns flow={flow} stats={stats} />}
      {treatment === "inkscroll" && <InkScroll flow={flow} stats={stats} />}

      <ScannerStrip />
    </div>
  );
}

Object.assign(window, { GateHero, useGateFlow, GATE_ORDER });
