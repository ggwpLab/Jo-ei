/* 浄衛 Jōei :: THREAT DETAIL DRAWER */

function jsonLines(r) {
  // build a beautified verdict object
  const obj = {
    verdict: "BLOCKED",
    http_status: r.http,
    reason: r.blocked_by.includes("cve") ? "cve_threshold_exceeded"
      : r.blocked_by.includes("malware") ? "malware_signature_match"
      : r.blocked_by.includes("supply_chain") ? "supply_chain_min_age"
      : "denylisted",
    package: `${r.eco}/${r.pkg}`,
    version: r.ver,
    blocked_by: r.blocked_by,
    request_id: r.request_id,
    gate: GATE_LABEL[r.blocked_by[0]],
  };
  if (r.cves) obj.cve_ids = r.cves;
  if (r.malware) { obj.engine = r.malware.engine; obj.signature = r.malware.signature; }
  if (r.supply) { obj.published_at = r.supply.published_at.toISOString(); obj.age_hours = r.supply.age_hours; obj.min_age_hours = r.supply.min_age_hours; }
  return obj;
}

function JsonView({ obj }) {
  const render = (v) => {
    if (Array.isArray(v)) return "[" + v.map((x) => `"${x}"`).join(", ") + "]";
    if (typeof v === "number") return <span className="jn">{v}</span>;
    return <span className="js">"{String(v)}"</span>;
  };
  const entries = Object.entries(obj);
  return (
    <div className="json-block">
      <span className="jp">{"{"}</span>{"\n"}
      {entries.map(([k, v], i) => (
        <span key={k}>
          {"  "}<span className="jk">"{k}"</span><span className="jp">: </span>
          {Array.isArray(v)
            ? <span className="js">{render(v)}</span>
            : render(v)}
          {i < entries.length - 1 ? <span className="jp">,</span> : ""}{"\n"}
        </span>
      ))}
      <span className="jp">{"}"}</span>
    </div>
  );
}

function ThreatDrawer({ r, onClose, onAllowlist, onDenylist }) {
  const [confirm, setConfirm] = useState(null); // 'allow' | 'deny' | null
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  if (!r) return null;

  const verdict = jsonLines(r);
  const reasonText = r.blocked_by.includes("cve") ? "CVE threshold exceeded"
    : r.blocked_by.includes("malware") ? "Malware signature matched"
    : r.blocked_by.includes("supply_chain") ? "Supply-chain maturity hold"
    : "Package is denylisted";

  const target = `${r.eco}/${r.pkg}`;

  return (
    <>
      <div className="scrim" onClick={onClose}></div>
      <aside className="drawer" role="dialog" aria-modal="true">
        <div className="drawer-head">
          <div className="verm-bar"></div>
          <div style={{ flex: 1 }}>
            <div className="row" style={{ gap: 9 }}>
              <Eco id={r.eco} />
              <span className="badge block">BLOCKED · {r.http}</span>
            </div>
            <div className="mono" style={{ fontSize: 16, fontWeight: 600, marginTop: 10 }}>
              {r.pkg}<span className="muted">@{r.ver}</span>
            </div>
            <div className="muted" style={{ fontSize: 13, marginTop: 3 }}>{reasonText}</div>
          </div>
          <button className="x-btn" onClick={onClose}><Icons.x /></button>
        </div>

        <div className="drawer-body">
          {/* key facts */}
          <dl className="kv">
            <dt>request_id</dt><dd>{r.request_id}</dd>
            <dt>gate</dt><dd>{GATE_LABEL[r.blocked_by[0]]}</dd>
            <dt>latency</dt><dd>{r.lat}ms</dd>
            <dt>timestamp</dt><dd>{r.ts.toISOString()}</dd>
          </dl>

          {/* CVE list */}
          {r.cves && (
            <>
              <div className="label-h">Vulnerabilities · blocking ≥ {JOEI.policy.cve_block_on}</div>
              <div className="col" style={{ gap: 10 }}>
                {r.cves.map((id) => {
                  const c = JOEI.CVES[id] || { id, severity: "UNKNOWN", cvss: 0, summary: "" };
                  return (
                    <div className="cve-card" key={id}>
                      <div className="cve-top">
                        <span className={`sev ${c.severity}`}>{c.severity}</span>
                        <span className="cve-id">{c.id}</span>
                        <span className="right mono muted" style={{ fontSize: 11.5 }}>CVSS {(c.cvss || 0).toFixed(1)}</span>
                      </div>
                      <div className="cve-sum">{c.summary}</div>
                      <a className="cve-link" href={`https://osv.dev/vulnerability/${c.id}`} target="_blank" rel="noreferrer">
                        osv.dev/vulnerability/{c.id} <Icons.ext />
                      </a>
                    </div>
                  );
                })}
              </div>
            </>
          )}

          {/* malware */}
          {r.malware && (
            <>
              <div className="label-h">Malware detection</div>
              <div className="cve-card">
                <div className="cve-top">
                  <span className="sev CRITICAL">SIGNATURE</span>
                  <span className="cve-id">{r.malware.signature}</span>
                </div>
                <dl className="kv" style={{ gridTemplateColumns: "100px 1fr", marginTop: 4 }}>
                  <dt>engine</dt><dd>{r.malware.engine}</dd>
                  <dt>action</dt><dd style={{ color: "var(--vermilion-l)" }}>{r.malware.action}</dd>
                </dl>
                {r.note && <div className="cve-sum" style={{ color: "var(--gold-l)" }}>⚠ {r.note}</div>}
              </div>
            </>
          )}

          {/* supply chain */}
          {r.supply && (
            <>
              <div className="label-h">Supply-chain hold</div>
              <div className="cve-card">
                <div className="cve-sum">
                  Published {r.supply.age_hours}h ago — below the <b style={{ color: "var(--washi)" }}>{r.supply.min_age_hours}h</b> minimum-age policy.
                  Held to let the ecosystem catch malicious releases before they reach builds.
                </div>
              </div>
            </>
          )}

          {/* raw verdict */}
          <div className="label-h">Verdict · structured response</div>
          <JsonView obj={verdict} />
        </div>

        <div className="drawer-foot">
          {confirm === "allow" ? (
            <>
              <span className="muted grow" style={{ fontSize: 12.5 }}>Trust <b className="mono" style={{ color: "var(--washi)" }}>{target}</b> on all gates?</span>
              <button className="btn ghost sm" onClick={() => setConfirm(null)}>Cancel</button>
              <button className="btn jade sm" onClick={() => { onAllowlist(target); onClose(); }}>Confirm allowlist</button>
            </>
          ) : confirm === "deny" ? (
            <>
              <span className="muted grow" style={{ fontSize: 12.5 }}>Permanently deny <b className="mono" style={{ color: "var(--washi)" }}>{target}@{r.ver}</b>?</span>
              <button className="btn ghost sm" onClick={() => setConfirm(null)}>Cancel</button>
              <button className="btn primary sm" onClick={() => { onDenylist(`${target}@${r.ver}`); onClose(); }}>Confirm denylist</button>
            </>
          ) : (
            <>
              <button className="btn primary grow" onClick={() => setConfirm("allow")}>
                <Icons.check /> Add to allowlist
              </button>
              <button className="btn danger" onClick={() => setConfirm("deny")}>Add to denylist</button>
            </>
          )}
        </div>
      </aside>
    </>
  );
}

Object.assign(window, { ThreatDrawer, JsonView });
