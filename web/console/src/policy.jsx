/* 浄衛 Jōei :: POLICY EDITOR */

function ListEditor({ kind, items, onAdd, onRemove }) {
  const [val, setVal] = useState("");
  const [busy, setBusy] = useState(false);
  // onAdd resolves true when the entry was saved; on failure the typed value
  // stays so it can be corrected.
  const submit = () => {
    const v = val.trim();
    if (!v || busy) return;
    setBusy(true);
    Promise.resolve(onAdd(v))
      .then((ok) => { if (ok !== false) setVal(""); })
      .finally(() => setBusy(false));
  };
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
          value={val} onChange={(e) => setVal(e.target.value)} disabled={busy}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />
        <button className="btn sm ghost" onClick={submit} disabled={busy}>Add</button>
      </div>
    </div>
  );
}

function buildYaml(p) {
  return [
    ["c", "# 浄衛 runtime policy — persisted to the database"],
    ["k", "mode", "v", p.mode],
    ["k", "min_age_hours", "d", p.min_age_hours],
    ["k", "cve_block_on", "v", p.cve_block_on],
    ["c", ""],
    ["k", "allowlist_supply:"],
    ...p.allowlist_supply.map((x) => ["li", x]),
    ["c", ""],
    ["k", "allowlist_cve:"],
    ...p.allowlist_cve.map((x) => ["li", x]),
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

const SETTINGS_KEYS = ["mode", "min_age_hours", "cve_block_on"];
const pickSettings = (p) => ({ mode: p.mode, min_age_hours: p.min_age_hours, cve_block_on: p.cve_block_on });

function Policy({ notify }) {
  useJoeiData(); // lists render straight from JOEI.policy
  const admin = JOEI.isAdmin();
  const [yaml, setYaml] = useState(false);
  // Only the settings block is drafted; list edits apply immediately.
  const [draft, setDraft] = useState(() => pickSettings(JOEI.policy));
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [fieldError, setFieldError] = useState(null);

  // Pick up server-side changes unless the user has unsaved edits. dirtyRef
  // keeps the mount-only listener reading the current dirty flag.
  const dirtyRef = useRef(dirty);
  useEffect(() => { dirtyRef.current = dirty; }, [dirty]);
  useEffect(() => {
    const sync = () => { if (!dirtyRef.current) setDraft(pickSettings(JOEI.policy)); };
    window.addEventListener("joei:policy", sync);
    window.addEventListener("joei:data", sync);
    return () => {
      window.removeEventListener("joei:policy", sync);
      window.removeEventListener("joei:data", sync);
    };
  }, []);

  const lists = JOEI.policy;
  const p = { ...lists, ...(admin ? draft : pickSettings(lists)) };
  const update = (patch) => {
    if (!admin) return;
    setDraft({ ...draft, ...patch });
    setDirty(true);
    setFieldError(null);
  };

  const errCode = (err) => (err.status === 403 ? "403 Forbidden"
    : err.status === 413 ? "413 Payload Too Large" : "400 Bad Request");

  const save = () => {
    setSaving(true);
    JOEI.savePolicy(draft)
      .then(() => {
        setDirty(false);
        setDraft(pickSettings(JOEI.policy));
        notify({ kind: "ok", code: "200 OK", title: "Policy applied",
          msg: <>Policy updated and saved to the database.</> });
      })
      .catch((err) => {
        setFieldError(err.field || null);
        notify({ kind: "block", code: errCode(err), title: "Policy rejected",
          msg: String(err.message || err) });
      })
      .finally(() => setSaving(false));
  };

  // One entry at a time through the atomic list endpoints. Resolves true on
  // success so the editor clears its input.
  const editList = (list, entry, add) => JOEI.editList(list, entry, add)
    .then(() => true)
    .catch((err) => {
      setFieldError(err.field || null);
      notify({ kind: "block", code: errCode(err), title: add ? "Entry rejected" : "Remove failed",
        msg: String(err.message || err) });
      return false;
    });
  const listEditor = (list, kind) => (
    <ListEditor kind={kind} items={lists[list]}
      onAdd={(v) => editList(list, v, true)}
      onRemove={(v) => editList(list, v, false)} />
  );

  const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const MODES = [["enforce", "Enforce"], ["dry_run", "Dry-run"], ["off", "Off"]];

  return (
    <div className="content-inner">
      <div className="section-head">
        <span className="head-kanji kanji">法</span>
        <div>
          <div className="eyebrow">Runtime policy · applies immediately, persisted</div>
          <h2>Effective policy</h2>
        </div>
        <div className="spacer"></div>
        <div className="seg">
          <button className={!yaml ? "active" : ""} onClick={() => setYaml(false)}>Form</button>
          <button className={yaml ? "active" : ""} onClick={() => setYaml(true)}>View as YAML</button>
        </div>
        {admin && (
          <button className={`btn ${dirty ? "primary" : ""}`} disabled={!dirty || saving}
            style={!dirty ? { opacity: .5 } : undefined} onClick={save}>
            {saving ? "Applying…" : dirty ? "Save & apply" : "Saved"}
          </button>
        )}
      </div>

      <p className="muted" style={{ maxWidth: 680, marginTop: -4, marginBottom: 18, fontSize: 13 }}>
        Changes apply to the gate immediately and are <b style={{ color: "var(--jade-l)" }}>saved to the database</b>, so they survive a restart.
        {" "}List entries are saved as soon as you add or remove them{admin ? "; the settings below need Save & apply" : ""}.
        {fieldError && <span role="alert" style={{ color: "var(--vermilion-l)" }}> · rejected field: <span className="mono">{fieldError}</span></span>}
      </p>

      {yaml ? (
        <div className="card" style={{ padding: 22 }}><YamlView p={p} /></div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, alignItems: "start" }}>
          {!admin && (
            <div className="card" role="note" style={{ gridColumn: "1 / -1", padding: "12px 16px", borderColor: "var(--gold)" }}>
              <span className="muted">🔒 Only an admin can change these settings</span>
            </div>
          )}

          {/* supply-chain mode + CVE threshold */}
          <div className="card" style={{ padding: 22, ...(admin ? {} : { opacity: .75 }) }}>
            <div className="field">
              <label>衛 Supply-chain mode{!admin && " 🔒"}</label>
              <div className="hint">How the gate acts on an immature package.</div>
              <div className="seg-radio" style={{ marginTop: 8 }}>
                {MODES.map(([k, l]) => (
                  <button key={k} className={`${p.mode === k ? "active" : ""} ${k === "enforce" ? "enf" : ""}`}
                    disabled={!admin} onClick={() => update({ mode: k })}>{l}</button>
                ))}
              </div>
            </div>
            <div className="divider"></div>
            <div className="field">
              <label>CVE — block on severity ≥{!admin && " 🔒"}</label>
              <div className="hint">Returns <span className="mono">403 Forbidden</span> when any CVE meets or exceeds this level.</div>
              <div className="seg-radio" style={{ marginTop: 8 }}>
                {SEV.map((s) => (
                  <button key={s} className={`${p.cve_block_on === s ? "active" : ""} ${s === "CRITICAL" ? "crit" : ""}`}
                    disabled={!admin} onClick={() => update({ cve_block_on: s })}>{s}</button>
                ))}
              </div>
            </div>
          </div>

          {/* min age */}
          <div className="card" style={{ padding: 22, ...(admin ? {} : { opacity: .75 }) }}>
            <div className="field">
              <label>衛 Minimum age{!admin && " 🔒"}</label>
              <div className="hint">Hold new releases (<span className="mono">423 Locked</span>) until they reach this age.</div>
              <div className="row" style={{ gap: 14, marginTop: 10 }}>
                <input type="range" min="0" max="72" step="1" value={p.min_age_hours} disabled={!admin}
                  onChange={(e) => update({ min_age_hours: +e.target.value })} style={{ flex: 1, accentColor: "var(--gold)" }} />
                <span className="mono" style={{ fontSize: 18, color: "var(--gold-l)", minWidth: 64, textAlign: "right" }}>
                  {p.min_age_hours}h
                </span>
              </div>
            </div>
          </div>

          {/* supply-chain allowlist */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label style={{ color: "var(--jade-l)" }}>Allowlist · 衛 supply-chain</label>
              <div className="hint">Format <span className="mono">ecosystem/name</span> or <span className="mono">ecosystem/name@version</span>. Bypasses only the minimum-age hold — CVE and malware scans still run.</div>
            </div>
            <div style={{ marginTop: 12 }}>{listEditor("allowlist_supply", "allow")}</div>
          </div>

          {/* CVE allowlist */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label style={{ color: "var(--jade-l)" }}>Allowlist · 浄 CVE</label>
              <div className="hint">Format <span className="mono">ecosystem/name</span> or <span className="mono">ecosystem/name@version</span>. Bypasses only the CVE block — age hold and malware scan still run.</div>
            </div>
            <div style={{ marginTop: 12 }}>{listEditor("allowlist_cve", "allow")}</div>
          </div>

          {/* denylist */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label style={{ color: "var(--vermilion-l)" }}>Denylist · always block</label>
              <div className="hint">Returns <span className="mono">403 Forbidden</span> regardless of scan results.</div>
            </div>
            <div style={{ marginTop: 12 }}>{listEditor("denylist", "deny")}</div>
          </div>
        </div>
      )}
    </div>
  );
}

Object.assign(window, { Policy, ListEditor, YamlView });
