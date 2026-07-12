/* 浄衛 Jōei :: REGISTRIES & CACHE */

const REG_ECOS = ["pypi", "npm", "maven", "rubygems", "docker"];

function UpstreamEditor({ upstreams, onChange }) {
  const [val, setVal] = useState("");
  const add = () => { const v = val.trim(); if (v) { onChange([...upstreams, v]); setVal(""); } };
  const remove = (i) => onChange(upstreams.filter((_, j) => j !== i));
  const move = (i, d) => {
    const j = i + d;
    if (j < 0 || j >= upstreams.length) return;
    const next = upstreams.slice();
    [next[i], next[j]] = [next[j], next[i]];
    onChange(next);
  };
  return (
    <div className="upstream">
      {upstreams.map((u, i) => (
        <div className="upstream-item" key={u + i}>
          <span className="ord">{i + 1}</span>
          <span style={{ flex: 1 }}>{u}</span>
          <span className="pri">{i === 0 ? "primary" : "fallback"}</span>
          <button className="btn sm ghost" disabled={i === 0} onClick={() => move(i, -1)} aria-label="up">↑</button>
          <button className="btn sm ghost" disabled={i === upstreams.length - 1} onClick={() => move(i, 1)} aria-label="down">↓</button>
          <button className="lc-del" onClick={() => remove(i)}><Icons.trash /></button>
        </div>
      ))}
      <div className="upstream-item" style={{ borderStyle: "dashed" }}>
        <Icons.plus />
        <input
          className="lc-val" style={{ background: "none", border: "none", outline: "none", color: "var(--washi)", flex: 1 }}
          placeholder="https://registry.example.org"
          value={val} onChange={(e) => setVal(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add()}
        />
        <button className="btn sm ghost" onClick={add}>Add</button>
      </div>
    </div>
  );
}

function RegistryCard({ reg, onToggle, onUpstreams }) {
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
          <button className={`toggle ${reg.enabled ? "on" : ""}`} onClick={() => onToggle(!reg.enabled)} aria-label="toggle"></button>
        </div>
      </div>
      <UpstreamEditor upstreams={reg.upstreams} onChange={onUpstreams} />
    </div>
  );
}

function Registries({ notify }) {
  useJoeiData();
  const c = JOEI.cache;
  const usedPct = c.max_gb > 0 ? Math.min(100, (c.used_gb / c.max_gb) * 100) : 0;

  // Per-day request-level hit rate, same series the Overview uses. Spark
  // breaks on <2 points, so pass undefined and render number-only below.
  const hitSpark = JOEI.daily.length >= 2
    ? JOEI.daily.map((r) => (r.requests ? r.cache_hits / r.requests : 0))
    : undefined;

  // Normalize to all five ecosystems in canonical order for editing.
  const initial = () => REG_ECOS.map((eco) => {
    const found = JOEI.registries.find((r) => r.eco === eco);
    return found ? { ...found, upstreams: [...found.upstreams] } : { eco, enabled: false, upstreams: [] };
  });
  const [draft, setDraft] = useState(initial);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [pending, setPending] = useState(JOEI.registriesPending);
  const [warnings, setWarnings] = useState(JOEI.registriesWarnings);

  const dirtyRef = useRef(dirty);
  useEffect(() => { dirtyRef.current = dirty; }, [dirty]);
  useEffect(() => {
    const sync = () => { if (!dirtyRef.current) { setDraft(initial()); setPending(JOEI.registriesPending); setWarnings(JOEI.registriesWarnings); } };
    window.addEventListener("joei:data", sync);
    return () => window.removeEventListener("joei:data", sync);
  }, []);

  const patch = (eco, change) => {
    setDraft(draft.map((r) => (r.eco === eco ? { ...r, ...change } : r)));
    setDirty(true);
  };

  const save = () => {
    setSaving(true);
    JOEI.saveRegistries(draft)
      .then(({ pending, warnings }) => {
        setDirty(false);
        setPending(pending);
        setWarnings(warnings);
        notify({ kind: "ok", code: "200 OK", title: "Registries saved",
          msg: <>Saved to the database — changes apply on the next restart.{warnings.length ? " " + warnings[0] : ""}</> });
      })
      .catch((err) => notify({ kind: "block", code: "400 Bad Request", title: "Registries rejected",
        msg: String(err.message || err) }))
      .finally(() => setSaving(false));
  };

  return (
    <div className="content-inner">
      <div className="section-head">
        <span className="head-kanji kanji">蔵</span>
        <div>
          <div className="eyebrow">Upstreams &amp; storage · persisted, applies on restart</div>
          <h2>Registries &amp; cache</h2>
        </div>
        <div className="spacer"></div>
        <button className={`btn ${dirty ? "primary" : ""}`} disabled={!dirty || saving}
          style={!dirty ? { opacity: .5 } : undefined} onClick={save}>
          {saving ? "Saving…" : dirty ? "Save" : "Saved"}
        </button>
      </div>

      {pending && (
        <div className="card" role="status" style={{ padding: 14, marginBottom: 16, borderColor: "var(--gold)" }}>
          <span className="muted">⟳ Registry changes are saved but <b style={{ color: "var(--gold-l)" }}>apply on the next restart</b>.</span>
        </div>
      )}

      {warnings.length > 0 && (
        <div className="card" role="status" style={{ padding: 14, marginBottom: 16, borderColor: "var(--warn, #c8892a)" }}>
          {warnings.map((w, i) => (
            <span key={i} className="muted">⚠ {w}</span>
          ))}
        </div>
      )}

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
          {hitSpark && (
            <div className="right" style={{ width: 200 }}>
              <div className="muted" style={{ fontSize: 11, textAlign: "right", marginBottom: 4 }}>hit rate · 30d</div>
              <Spark data={hitSpark} color="var(--jade)" h={36} w={200} />
            </div>
          )}
        </div>
        <div className="cache-meter">
          <i className="used" style={{ width: usedPct + "%" }}></i>
          <i className="evict" style={{ width: (100 - usedPct) + "%" }}></i>
        </div>
        <div className="row" style={{ marginTop: 12, gap: 28, fontSize: 12.5 }}>
          <span className="muted">Objects <b className="mono" style={{ color: "var(--washi)" }}>{c.objects}</b></span>
          <span className="muted">Hit rate · total <b className="mono" style={{ color: "var(--jade-l)" }}>{(c.hit_rate * 100).toFixed(1)}%</b></span>
          <span className="muted">LRU evictions · since restart <b className="mono" style={{ color: "var(--gold-l)" }}>{fmtNum(c.evictions)}</b></span>
          <span className="muted right" style={{ fontSize: 11 }}>⟍ eviction headroom</span>
        </div>
      </div>

      <div className="section-head" style={{ marginBottom: 14 }}>
        <h2 style={{ fontSize: 16 }}>Per-ecosystem upstreams</h2>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        {draft.map((r) => (
          <RegistryCard key={r.eco} reg={r}
            onToggle={(enabled) => patch(r.eco, { enabled })}
            onUpstreams={(upstreams) => patch(r.eco, { upstreams })} />
        ))}
      </div>
    </div>
  );
}

Object.assign(window, { Registries, RegistryCard, UpstreamEditor });
