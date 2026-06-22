/* 浄衛 Jōei :: REGISTRIES & CACHE */

function RegistryCard({ reg }) {
  const e = JOEI.ECO[reg.eco] || { name: reg.eco };
  return (
    <div className="card reg-card">
      <div className="reg-head">
        <Eco id={JOEI.ECO[reg.eco] ? reg.eco : "pypi"} size={30} />
        <div className="col">
          <span className="reg-name">{e.name}</span>
          <span className="reg-vol">{reg.enabled ? `${reg.upstreams.length} upstream${reg.upstreams.length === 1 ? "" : "s"}` : "disabled"}</span>
        </div>
        <div className="right row" style={{ gap: 10 }}>
          <span className="muted" style={{ fontSize: 12 }}>{reg.enabled ? "enabled" : "off"}</span>
          <button className={`toggle ${reg.enabled ? "on" : ""}`} disabled
            title="Configured in config.yaml — console management arrives in a later phase" aria-label="toggle"></button>
        </div>
      </div>
      <div className="upstream">
        {reg.upstreams.map((u, i) => (
          <div className="upstream-item" key={u} style={{ opacity: reg.enabled ? 1 : 0.45 }}>
            <span className="ord">{i + 1}</span>
            <span>{u}</span>
            <span className="pri">{i === 0 ? "primary" : "fallback"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Registries() {
  useJoeiData();
  const regs = JOEI.registries;
  const c = JOEI.cache;
  const usedPct = c.max_gb > 0 ? Math.min(100, (c.used_gb / c.max_gb) * 100) : 0;

  return (
    <div className="content-inner">
      <div className="section-head">
        <span className="head-kanji kanji">蔵</span>
        <div>
          <div className="eyebrow">Upstreams &amp; storage</div>
          <h2>Registries &amp; cache</h2>
        </div>
      </div>

      {/* cache panel */}
      <div className="card" style={{ padding: 22, marginBottom: 22 }}>
        <div className="row" style={{ alignItems: "flex-end", marginBottom: 16 }}>
          <div>
            <div className="eyebrow" style={{ fontSize: 11, letterSpacing: ".18em", color: "var(--washi-mut)" }}>LOCAL CACHE</div>
            <div className="row" style={{ alignItems: "baseline", gap: 8, marginTop: 4 }}>
              <span className="mono" style={{ fontSize: 28, fontWeight: 600, color: "var(--jade-l)" }}>{c.used_gb}</span>
              <span className="muted mono">/ {c.max_gb} GB used</span>
            </div>
          </div>
        </div>
        <div className="cache-meter">
          <i className="used" style={{ width: usedPct + "%" }}></i>
        </div>
        <div className="row" style={{ marginTop: 12, gap: 28, fontSize: 12.5 }}>
          <span className="muted">Objects <b className="mono" style={{ color: "var(--washi)" }}>{c.objects}</b></span>
          <span className="muted">Hit rate · since start <b className="mono" style={{ color: "var(--jade-l)" }}>{(c.hit_rate * 100).toFixed(1)}%</b></span>
          <span className="muted">LRU evictions · since start <b className="mono" style={{ color: "var(--gold-l)" }}>{fmtNum(c.evictions)}</b></span>
        </div>
      </div>

      <div className="section-head" style={{ marginBottom: 14 }}>
        <h2 style={{ fontSize: 16 }}>Per-ecosystem upstreams</h2>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        {regs.length === 0
          ? <div className="card"><div className="empty"><span className="e-kanji">無</span><div className="e-title">No registries</div></div></div>
          : regs.map((r) => <RegistryCard key={r.eco} reg={r} />)}
      </div>
    </div>
  );
}

Object.assign(window, { Registries, RegistryCard });
