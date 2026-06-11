/* 浄衛 Jōei :: APP SHELL — nav, topbar, routing, toasts, loader */

const NAV = [
  { id: "overview", label: "Overview", icon: "overview" },
  { id: "feed", label: "Live Feed", icon: "feed", badge: "live", live: true },
  { id: "quarantine", label: "Quarantine", icon: "quar", badge: "5", gold: true },
  { id: "policy", label: "Policy", icon: "policy" },
  { id: "registries", label: "Registries & Cache", icon: "registry" },
];

const PAGE_META = {
  overview:   { kanji: "衛", title: "Overview" },
  feed:       { kanji: "流", title: "Live Request Feed" },
  quarantine: { kanji: "衛", title: "Quarantine" },
  policy:     { kanji: "法", title: "Policy Editor" },
  registries: { kanji: "蔵", title: "Registries & Cache" },
};

/* ---------- toasts ---------- */
function ToastHost({ toasts, dismiss }) {
  return (
    <div className="toast-wrap">
      {toasts.map((t) => (
        <div className={`toast ${t.kind || ""}`} key={t.id}>
          <div className="t-bar"></div>
          <div style={{ flex: 1 }}>
            <div className="t-code mono">{t.code}</div>
            <div className="t-title">{t.title}</div>
            <div className="t-msg">{t.msg}</div>
          </div>
          <button className="x-btn" style={{ width: 24, height: 24 }} onClick={() => dismiss(t.id)}><Icons.x /></button>
        </div>
      ))}
    </div>
  );
}

/* ---------- purification loader ---------- */
function PurifyLoader({ hide }) {
  return (
    <div className={`purify-overlay ${hide ? "hide" : ""}`}>
      <div className="purify-gate">
        <svg className="pg-torii" viewBox="0 0 132 116" style={{ overflow: "visible" }}>
          <path className="lit" d="M6 22 Q66 6 126 22 L126 33 Q66 19 6 33 Z" fill="var(--ink-600)"/>
          <rect className="lit" x="18" y="40" width="96" height="9" rx="2" fill="var(--ink-600)" style={{ animationDelay: ".3s" }}/>
          <rect x="60" y="30" width="12" height="14" rx="1.5" fill="var(--ink-650)"/>
          <path d="M30 49 L36 110 L46 110 L40 49 Z" fill="var(--washi-faint)"/>
          <path d="M102 49 L96 110 L86 110 L92 49 Z" fill="var(--washi-faint)"/>
        </svg>
        <div className="pg-label kanji">浄 衛</div>
        <div className="pg-sub">opening the gate…</div>
      </div>
    </div>
  );
}

function App() {
  const [page, setPage] = useState("overview");
  const [treatment, setTreatment] = useState("procession");
  const [threat, setThreat] = useState(null);
  const [policy, setPolicy] = useState(JOEI.policy);
  const [toasts, setToasts] = useState([]);
  const [loading, setLoading] = useState(true);
  const tid = useRef(0);

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 1500);
    return () => clearTimeout(t);
  }, []);

  const notify = useCallback((t) => {
    const id = ++tid.current;
    setToasts((xs) => [...xs, { ...t, id }]);
    setTimeout(() => setToasts((xs) => xs.filter((x) => x.id !== id)), 4800);
  }, []);
  const dismiss = (id) => setToasts((xs) => xs.filter((x) => x.id !== id));

  const onAllowlist = (target) => {
    const t = typeof target === "string" ? target : `${target.eco}/${target.pkg}@${target.ver}`;
    setPolicy((p) => p.allowlist.includes(t) ? p : { ...p, allowlist: [...p.allowlist, t] });
    notify({ kind: "ok", code: "200 OK", title: "Added to allowlist", msg: <>Now trusted on all gates: <span className="t-pkg">{t}</span></> });
  };
  const onDenylist = (target) => {
    setPolicy((p) => p.denylist.includes(target) ? p : { ...p, denylist: [...p.denylist, target] });
    notify({ kind: "block", code: "403 Forbidden", title: "Added to denylist", msg: <>Will be blocked at the gate: <span className="t-pkg">{target}</span></> });
  };
  const openThreat = (r) => {
    setThreat(r);
    // surface a block toast on the matching ecosystem rule for flavor
  };

  const meta = PAGE_META[page];

  return (
    <div className="app">
      <PurifyLoader hide={!loading} />

      {/* ---------- sidebar ---------- */}
      <nav className="sidebar">
        <div className="brand">
          <div className="brand-mark"><ToriiMark size={34} /></div>
          <div className="brand-text">
            <span className="brand-name kanji">浄衛 <small>Jōei</small></span>
            <span className="brand-sub">Purification Gate</span>
          </div>
        </div>

        <div className="nav-group-label">Console</div>
        {NAV.map((n) => (
          <button key={n.id} className={`nav-item ${page === n.id ? "active" : ""}`} onClick={() => { setPage(n.id); }}>
            {Icons[n.icon]()}
            <span>{n.label}</span>
            {n.badge && (
              n.live
                ? <span className="nav-badge"><span className="dot live" style={{ display: "inline-block", width: 6, height: 6, borderRadius: 6, background: "var(--jade)", marginRight: 4 }}></span></span>
                : <span className={`nav-badge ${n.gold ? "" : "danger"}`}>{n.badge}</span>
            )}
          </button>
        ))}

        <div className="sidebar-foot">
          <div className="row" style={{ gap: 10, padding: "2px 8px" }}>
            <span className="health ok" style={{ fontSize: 11 }}><i className="hdot"></i>gate healthy</span>
          </div>
          <div className="row" style={{ gap: 10, padding: "0 8px" }}>
            <div style={{ width: 30, height: 30, borderRadius: 8, background: "var(--ink-700)", display: "grid", placeItems: "center", fontSize: 12, fontWeight: 700, color: "var(--washi-soft)" }}>SK</div>
            <div className="col" style={{ lineHeight: 1.25 }}>
              <span style={{ fontSize: 12.5, fontWeight: 600 }}>S. Kurosawa</span>
              <span className="faint" style={{ fontSize: 11 }}>DevSecOps · admin</span>
            </div>
          </div>
        </div>
      </nav>

      {/* ---------- main ---------- */}
      <div className="main">
        <header className="topbar">
          <h1><span className="crumb-kanji kanji">{meta.kanji}</span> {meta.title}</h1>
          <div className="topbar-spacer"></div>

          <span className="pill"><span className="muted" style={{ fontWeight: 500 }}>env</span>&nbsp;production</span>
          <span className="pill"><span className="muted" style={{ fontWeight: 500 }}>profile</span>&nbsp;{policy.profile}</span>
          <span className={`pill ${policy.mode === "enforce" ? "enforce" : policy.mode === "dry_run" ? "dry" : "off"}`}>
            <span className="dot"></span>
            {policy.mode === "enforce" ? "Enforcing" : policy.mode === "dry_run" ? "Dry-run" : "Off"}
          </span>
        </header>

        <div className="content">
          {page === "overview" && <Overview treatment={treatment} setTreatment={setTreatment} openThreat={openThreat} />}
          {page === "feed" && <LiveFeed openThreat={openThreat} />}
          {page === "quarantine" && <Quarantine onAllowlist={onAllowlist} />}
          {page === "policy" && <Policy policy={policy} setPolicy={setPolicy} notify={notify} />}
          {page === "registries" && <Registries notify={notify} />}
        </div>
      </div>

      {threat && <ThreatDrawer r={threat} onClose={() => setThreat(null)} onAllowlist={onAllowlist} onDenylist={onDenylist} />}
      <ToastHost toasts={toasts} dismiss={dismiss} />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
