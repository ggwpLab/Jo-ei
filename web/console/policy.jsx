/* 浄衛 Jōei :: POLICY EDITOR */

function ListEditor({ kind, items, onAdd, onRemove }) {
  const [val, setVal] = useState("");
  const submit = () => { const v = val.trim(); if (v) { onAdd(v); setVal(""); } };
  return (
    <div className="list-editor">
      {items.map((it) => {
        const eco = it.split("/")[0];
        return (
          <div className={`list-chip ${kind}`} key={it}>
            <Eco id={JOEI.ECO[eco] ? eco : "pypi"} size={20} />
            <span className="lc-val">{it}</span>
            <button className="lc-del" onClick={() => onRemove(it)}><Icons.trash /></button>
          </div>
        );
      })}
      <div className="list-chip" style={{ borderStyle: "dashed" }}>
        <Icons.plus />
        <input
          className="lc-val" style={{ background: "none", border: "none", outline: "none", color: "var(--washi)" }}
          placeholder={kind === "allow" ? "pypi/requests or npm/@scope/pkg@1.2.3" : "pypi/colourama"}
          value={val} onChange={(e) => setVal(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />
        <button className="btn sm ghost" onClick={submit}>Add</button>
      </div>
    </div>
  );
}

function buildYaml(p) {
  return [
    ["c", "# 浄衛 policy profile"],
    ["k", "profile", "v", p.profile],
    ["k", "mode", "v", p.mode],
    ["c", ""],
    ["k", "cve:"],
    ["i", "block_on", "v", p.cve_block_on],
    ["c", ""],
    ["k", "supply_chain:"],
    ["i", "min_age_hours", "d", p.supply_chain.min_age_hours],
    ["i", "mode", "v", p.supply_chain.mode],
    ["c", ""],
    ["k", "allowlist:"],
    ...p.allowlist.map((x) => ["li", x]),
    ["c", ""],
    ["k", "denylist:"],
    ...p.denylist.map((x) => ["li", x]),
  ];
}

function YamlView({ p }) {
  const lines = buildYaml(p);
  return (
    <div className="yaml-view">
      {lines.map((ln, i) => {
        if (ln[0] === "c") return <div key={i}><span className="yc">{ln[1]}</span></div>;
        if (ln[0] === "li") return <div key={i}>{"  - "}<span className="yv">{ln[1]}</span></div>;
        if (ln[0] === "k" && ln.length === 2) return <div key={i}><span className="yk">{ln[1]}</span></div>;
        const indent = ln[0] === "i" ? "  " : "";
        const valClass = ln[2] === "d" ? "yd" : "yv";
        return <div key={i}>{indent}<span className="yk">{ln[1]}</span>: <span className={valClass}>{String(ln[3])}</span></div>;
      })}
    </div>
  );
}

function Policy({ policy, setPolicy, notify }) {
  const [yaml, setYaml] = useState(false);
  const [dirty, setDirty] = useState(false);
  const p = policy;
  const update = (patch) => { setPolicy({ ...p, ...patch }); setDirty(true); };
  const updateSC = (patch) => { setPolicy({ ...p, supply_chain: { ...p.supply_chain, ...patch } }); setDirty(true); };

  const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const MODES = [["enforce", "Enforce"], ["dry_run", "Dry-run"], ["off", "Off"]];

  return (
    <div className="content-inner">
      <div className="section-head">
        <span className="head-kanji kanji">法</span>
        <div>
          <div className="eyebrow">Policy profile</div>
          <h2 className="row" style={{ gap: 12 }}>
            <select className="select" style={{ fontSize: 18, fontWeight: 600, padding: "4px 30px 4px 10px" }}
              value={p.profile} onChange={(e) => update({ profile: e.target.value })}>
              {p.profiles.map((pr) => <option key={pr} value={pr}>{pr}</option>)}
            </select>
          </h2>
        </div>
        <div className="spacer"></div>
        <div className="seg">
          <button className={!yaml ? "active" : ""} onClick={() => setYaml(false)}>Form</button>
          <button className={yaml ? "active" : ""} onClick={() => setYaml(true)}>View as YAML</button>
        </div>
        <button className={`btn ${dirty ? "primary" : ""}`} disabled={!dirty}
          style={!dirty ? { opacity: .5 } : undefined}
          onClick={() => { setDirty(false); notify({ kind: "ok", code: "200 OK", title: "Policy saved", msg: <>Profile <b>{p.profile}</b> applied to the gate.</> }); }}>
          {dirty ? "Save & apply" : "Saved"}
        </button>
      </div>

      {yaml ? (
        <div className="card" style={{ padding: 22 }}><YamlView p={p} /></div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, alignItems: "start" }}>
          {/* enforcement mode */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label>Global enforcement mode</label>
              <div className="hint">How the gate acts on a failing verdict.</div>
              <div className="seg-radio" style={{ marginTop: 8 }}>
                {MODES.map(([k, l]) => (
                  <button key={k} className={`${p.mode === k ? "active" : ""} ${k === "enforce" ? "enf" : ""}`}
                    onClick={() => update({ mode: k })}>{l}</button>
                ))}
              </div>
            </div>
            <div className="divider"></div>
            <div className="field">
              <label>CVE — block on severity ≥</label>
              <div className="hint">Returns <span className="mono">403 Forbidden</span> when any CVE meets or exceeds this level.</div>
              <div className="seg-radio" style={{ marginTop: 8 }}>
                {SEV.map((s) => (
                  <button key={s} className={`${p.cve_block_on === s ? "active" : ""} ${s === "CRITICAL" ? "crit" : ""}`}
                    onClick={() => update({ cve_block_on: s })}>{s}</button>
                ))}
              </div>
            </div>
          </div>

          {/* supply chain */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label>衛 Supply-chain · minimum age</label>
              <div className="hint">Hold new releases (<span className="mono">423 Locked</span>) until they reach this age.</div>
              <div className="row" style={{ gap: 14, marginTop: 10 }}>
                <input type="range" min="0" max="72" step="1" value={p.supply_chain.min_age_hours}
                  onChange={(e) => updateSC({ min_age_hours: +e.target.value })} style={{ flex: 1, accentColor: "var(--gold)" }} />
                <span className="mono" style={{ fontSize: 18, color: "var(--gold-l)", minWidth: 64, textAlign: "right" }}>
                  {p.supply_chain.min_age_hours}h
                </span>
              </div>
            </div>
            <div className="divider"></div>
            <div className="field">
              <label>Supply-chain mode</label>
              <div className="seg-radio" style={{ marginTop: 8 }}>
                {MODES.map(([k, l]) => (
                  <button key={k} className={`${p.supply_chain.mode === k ? "active" : ""} ${k === "enforce" ? "enf" : ""}`}
                    onClick={() => updateSC({ mode: k })}>{l}</button>
                ))}
              </div>
            </div>
          </div>

          {/* allowlist */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label style={{ color: "var(--jade-l)" }}>Allowlist · always trust</label>
              <div className="hint">Format <span className="mono">ecosystem/name</span> or <span className="mono">ecosystem/name@version</span>. Bypasses all gates.</div>
            </div>
            <div style={{ marginTop: 12 }}>
              <ListEditor kind="allow" items={p.allowlist}
                onAdd={(v) => update({ allowlist: [...p.allowlist, v] })}
                onRemove={(v) => update({ allowlist: p.allowlist.filter((x) => x !== v) })} />
            </div>
          </div>

          {/* denylist */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label style={{ color: "var(--vermilion-l)" }}>Denylist · always block</label>
              <div className="hint">Returns <span className="mono">403 Forbidden</span> regardless of scan results.</div>
            </div>
            <div style={{ marginTop: 12 }}>
              <ListEditor kind="deny" items={p.denylist}
                onAdd={(v) => update({ denylist: [...p.denylist, v] })}
                onRemove={(v) => update({ denylist: p.denylist.filter((x) => x !== v) })} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

Object.assign(window, { Policy, ListEditor, YamlView });
