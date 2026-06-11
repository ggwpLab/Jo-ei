/* 浄衛 Jōei :: REGISTRIES & CACHE */

function RegistryCard({ reg, onToggle }) {
  const e = JOEI.ECO[reg.eco];
  return (
    <div className="card reg-card">
      <div className="reg-head">
        <Eco id={reg.eco} size={30} />
        <div className="col">
          <span className="reg-name">{e.name}</span>
          <span className="reg-vol">{reg.enabled ? `${reg.vol} requests · 24h` : "disabled"}</span>
        </div>
        <div className="right row" style={{ gap: 10 }}>
          <span className="muted" style={{ fontSize: 12 }}>{reg.enabled ? "enabled" : "off"}</span>
          <button className={`toggle ${reg.enabled ? "on" : ""}`} onClick={() => onToggle(reg.eco)} aria-label="toggle"></button>
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

function Registries({ notify }) {
  const [regs, setRegs] = useState(() => JOEI.registries.slice());
  const c = JOEI.cache;
  const toggle = (eco) => {
    setRegs((rs) => rs.map((r) => r.eco === eco ? { ...r, enabled: !r.enabled } : r));
    const r = regs.find((x) => x.eco === eco);
    notify({ kind: r.enabled ? "hold" : "ok", code: "200 OK", title: `${JOEI.ECO[eco].name} ${r.enabled ? "disabled" : "enabled"}`, msg: r.enabled ? "Upstream fetches paused for this ecosystem." : "Now proxying & purifying requests." });
  };

  const usedPct = (c.used_gb / c.max_gb) * 100;
  const evictPct = 8;

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
          <div className="right col" style={{ alignItems: "flex-end" }}>
            <span className="muted" style={{ fontSize: 12 }}>hit rate · 24h</span>
            <div style={{ width: 160, height: 34 }}><Spark data={c.spark} color="var(--jade)" h={34} w={160} /></div>
          </div>
        </div>
        <div className="cache-meter">
          <i className="used" style={{ width: usedPct - evictPct + "%" }}></i>
          <i className="evict" style={{ width: evictPct + "%" }}></i>
        </div>
        <div className="row" style={{ marginTop: 12, gap: 28, fontSize: 12.5 }}>
          <span className="muted">Objects <b className="mono" style={{ color: "var(--washi)" }}>{c.objects}</b></span>
          <span className="muted">Hit rate <b className="mono" style={{ color: "var(--jade-l)" }}>{(c.hit_rate * 100).toFixed(1)}%</b></span>
          <span className="muted">LRU evictions · 24h <b className="mono" style={{ color: "var(--gold-l)" }}>{fmtNum(c.evictions_24h)}</b></span>
          <span className="right row" style={{ gap: 6, color: "var(--gold-l)", fontSize: 12 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: "repeating-linear-gradient(45deg,var(--gold-t),var(--gold-t) 3px,transparent 3px,transparent 6px)", display: "inline-block" }}></span>
            eviction headroom
          </span>
        </div>
      </div>

      <div className="section-head" style={{ marginBottom: 14 }}>
        <h2 style={{ fontSize: 16 }}>Per-ecosystem upstreams</h2>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        {regs.map((r) => <RegistryCard key={r.eco} reg={r} onToggle={toggle} />)}
      </div>
    </div>
  );
}

Object.assign(window, { Registries, RegistryCard });
