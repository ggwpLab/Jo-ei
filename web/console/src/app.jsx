/* 浄衛 Jōei :: APP SHELL — nav, topbar, routing, toasts, loader */

const NAV = [
  { id: "overview", label: "Overview", icon: "overview" },
  { id: "feed", label: "Live Feed", icon: "feed", badge: "live", live: true },
  { id: "quarantine", label: "Quarantine", icon: "quar", gold: true },
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

/* ---------- login ---------- */
function LoginScreen() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = (e) => {
    e.preventDefault();
    if (busy || !username || !password) return;
    setBusy(true);
    setErr("");
    JOEI.login(username, password)
      .catch((ex) => {
        setErr(ex.status === 0
          ? "Cannot reach the proxy. Check that it is running, then try again."
          : ex.status === 429
          ? `Too many attempts, try again in ${ex.retryAfter} s`
          : ex.status === 503
          ? "Authentication is not configured on this server. Add console.auth.users or JOEI_CONSOLE_AUTH_USERS and restart."
          : "Incorrect username or password.");
        setPassword("");
      })
      .finally(() => setBusy(false));
  };

  return (
    <div className="login-wrap">
      <form className="card login-card" onSubmit={submit}>
        <div className="login-mark"><ToriiMark size={44} /></div>
        <div className="login-title kanji">浄衛 <small>Jōei</small></div>
        <div className="login-sub">The Purification Gate · console</div>

        <label className="login-field">
          <span>Username</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)}
            autoFocus autoComplete="username" disabled={busy} />
        </label>
        <label className="login-field">
          <span>Password</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password" disabled={busy} />
        </label>

        {err && <div className="login-err">{err}</div>}

        <button className="btn primary login-submit" type="submit" disabled={busy || !username || !password}>
          {busy ? "Opening the gate…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

/* ---------- change password (forced screen + sidebar modal) ---------- */
function PasswordForm({ onDone, onCancel, submitLabel }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const ready = current && next && confirm;
  const submit = (e) => {
    e.preventDefault();
    if (busy || !ready) return;
    if (next !== confirm) { setErr("The new passwords do not match."); return; }
    setBusy(true);
    setErr("");
    JOEI.changePassword(current, next)
      .then(() => { setBusy(false); if (onDone) onDone(); })
      .catch((ex) => {
        setBusy(false);
        // A lapsed session already sent the shell back to the login screen.
        if (ex.message === "unauthorized") return;
        setErr(String(ex.message || ex));
        if (ex.status === 401) setCurrent("");
      });
  };

  return (
    <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <label className="login-field">
        <span>Current password</span>
        <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)}
          autoFocus autoComplete="current-password" disabled={busy} />
      </label>
      <label className="login-field">
        <span>New password</span>
        <input type="password" value={next} onChange={(e) => setNext(e.target.value)}
          autoComplete="new-password" disabled={busy} />
      </label>
      <label className="login-field">
        <span>Confirm new password</span>
        <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password" disabled={busy} />
      </label>
      <div className="faint" style={{ fontSize: 11 }}>At least 12 characters, and not your username.</div>

      {err && <div className="login-err" role="alert">{err}</div>}

      <div className="row" style={{ gap: 10 }}>
        {onCancel && <button type="button" className="btn ghost" onClick={onCancel} disabled={busy}>Cancel</button>}
        <button className="btn primary login-submit" style={{ marginTop: 0, flex: 1 }} type="submit" disabled={busy || !ready}>
          {busy ? "Changing…" : submitLabel}
        </button>
      </div>
    </form>
  );
}

function ForcedPasswordScreen({ username }) {
  return (
    <div className="login-wrap">
      <div className="card login-card">
        <div className="login-mark"><ToriiMark size={44} /></div>
        <div className="login-title kanji">浄衛 <small>Jōei</small></div>
        <div className="login-sub">
          Signed in as <b style={{ color: "var(--washi)" }}>{username}</b> · choose a new password to continue
        </div>
        <PasswordForm submitLabel="Change password" />
        <button className="btn sm ghost" style={{ alignSelf: "center" }} onClick={() => JOEI.logout()}>Sign out</button>
      </div>
    </div>
  );
}

function ChangePasswordModal({ onClose, notify }) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="scrim" onClick={onClose}></div>
      <div role="dialog" aria-modal="true" aria-label="Change password"
        style={{ position: "fixed", inset: 0, zIndex: 41, display: "grid", placeItems: "center", padding: 24, pointerEvents: "none" }}>
        <div className="card login-card" style={{ pointerEvents: "auto" }}>
          <div className="row">
            <div style={{ fontSize: 15, fontWeight: 600 }}>Change password</div>
            <button className="x-btn right" style={{ width: 24, height: 24 }} onClick={onClose} aria-label="close"><Icons.x /></button>
          </div>
          <div className="faint" style={{ fontSize: 11.5, marginTop: -6 }}>Your other sessions will be signed out.</div>
          <PasswordForm submitLabel="Change password" onCancel={onClose}
            onDone={() => {
              onClose();
              notify({ kind: "ok", code: "200 OK", title: "Password changed", msg: "Other sessions were signed out." });
            }} />
        </div>
      </div>
    </>
  );
}

function App() {
  const [page, setPage] = useState("overview");
  const [treatment, setTreatment] = useState("procession");
  const [threat, setThreat] = useState(null);
  const [policy, setPolicyState] = useState(JOEI.policy);
  const [toasts, setToasts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showLoader, setShowLoader] = useState(true);
  const [connected, setConnected] = useState(JOEI.connected);
  const [scanners, setScanners] = useState(JOEI.scanners);
  const [authed, setAuthed] = useState(JOEI.authenticated);
  const [username, setUsername] = useState(JOEI.username);
  const [role, setRole] = useState(JOEI.role);
  const [mustChange, setMustChange] = useState(JOEI.mustChangePassword);
  const [pwModal, setPwModal] = useState(false);
  const tid = useRef(0);

  // The overlay is hidden by opacity alone, which does not stop its infinite
  // torii animation: left mounted, it repainted a fully transparent element
  // for as long as the tab stayed open. Keep it through the 0.6s fade-out
  // (see .purify-overlay in screens.css), then drop the node.
  useEffect(() => {
    if (loading) {
      setShowLoader(true);
      return;
    }
    const id = setTimeout(() => setShowLoader(false), 600);
    return () => clearTimeout(id);
  }, [loading]);

  useEffect(() => {
    const onData = () => { setLoading(false); setPolicyState(JOEI.policy); setScanners(JOEI.scanners); };
    const onConn = () => setConnected(JOEI.connected);
    const onAuth = () => {
      setAuthed(JOEI.authenticated);
      setUsername(JOEI.username);
      setRole(JOEI.role);
      setMustChange(JOEI.mustChangePassword);
      if (!JOEI.authenticated) setPwModal(false);
    };
    window.addEventListener("joei:data", onData);
    window.addEventListener("joei:policy", onData);
    window.addEventListener("joei:connection", onConn);
    window.addEventListener("joei:auth", onAuth);
    // The initial load can settle before this subscription exists (the
    // fetches finish while Babel is still compiling the app), so the events
    // above may already have fired into the void — sync from current state.
    if (JOEI.ready) onData();
    onConn();
    onAuth();
    return () => {
      window.removeEventListener("joei:data", onData);
      window.removeEventListener("joei:policy", onData);
      window.removeEventListener("joei:connection", onConn);
      window.removeEventListener("joei:auth", onAuth);
    };
  }, []);

  const notify = useCallback((t) => {
    const id = ++tid.current;
    setToasts((xs) => [...xs, { ...t, id }]);
    setTimeout(() => setToasts((xs) => xs.filter((x) => x.id !== id)), 4800);
  }, []);
  const dismiss = (id) => setToasts((xs) => xs.filter((x) => x.id !== id));

  // J.editList serialises every list edit (here and on the Policy page), so
  // toasts arrive in click order and J.policy ends on the last response.
  const editList = (list, entry, toast) => {
    JOEI.editList(list, entry, true)
      .then(() => notify(toast))
      .catch((err) => notify({
        kind: "block", code: err.status === 403 ? "403 Forbidden" : err.status === 413 ? "413 Payload Too Large" : "400 Bad Request",
        title: "Policy update failed", msg: String(err.message || err),
      }));
  };

  // target: { eco, pkg, ver }; gate: "supply" | "cve" — each gate has its own
  // allowlist, so trusting a quarantined package does not waive its CVE check
  // (and vice versa). Entries added from the console always pin the exact
  // version — a bare eco/pkg entry would trust every future release of a
  // package that was just blocked.
  const GATE_LIST = {
    supply: { key: "allowlist_supply", label: "supply-chain gate" },
    cve: { key: "allowlist_cve", label: "CVE gate" },
  };
  const onAllowlist = (target, gate) => {
    const { key, label } = GATE_LIST[gate] || GATE_LIST.supply;
    const t = `${target.eco}/${target.pkg}@${target.ver}`;
    editList(key, t,
      { kind: "ok", code: "200 OK", title: "Added to allowlist", msg: <>Now trusted at the {label}: <span className="t-pkg">{t}</span></> });
  };
  const onDenylist = (target) => {
    editList("denylist", target,
      { kind: "block", code: "403 Forbidden", title: "Added to denylist", msg: <>Will be blocked at the gate: <span className="t-pkg">{target}</span></> });
  };
  const openThreat = (r) => setThreat(r);

  const meta = PAGE_META[page];

  // The sidebar badge reports the worst scan-engine status. "off" (configured
  // but not attached by the active profile) and "unknown" (not probed yet) are
  // not failures, so they stay green — otherwise every boot looks broken for
  // its first probe interval. A dead API outranks everything.
  const down = scanners.filter((s) => s.status === "down");
  const warn = scanners.filter((s) => s.status === "warn");
  const gateBadge = !connected
    ? { cls: "off", label: "no connection", title: "The console cannot reach the API" }
    : down.length
    ? { cls: "down", label: "gate degraded", title: `Not responding: ${down.map((s) => s.name).join(", ")}` }
    : warn.length
    ? { cls: "warn", label: "gate slow", title: `Slow to respond: ${warn.map((s) => s.name).join(", ")}` }
    : { cls: "ok", label: "gate healthy", title: "All attached scan engines are responding" };

  // The purify overlay covers the /api/auth/me probe, so an operator with a
  // live session never sees a flash of the login screen.
  if (!authed) {
    return (
      <>
        {showLoader && <PurifyLoader hide={!loading} />}
        {!loading && !connected && (
          <div className="conn-banner">&#9888; No connection to the proxy — check that it is running.</div>
        )}
        {!loading && <LoginScreen />}
      </>
    );
  }

  // Signed in with a temporary password: nothing but the change form until it
  // is replaced (the API refuses everything else with 403).
  if (mustChange) {
    return (
      <>
        {!connected && (
          <div className="conn-banner">&#9888; No connection to the proxy — check that it is running.</div>
        )}
        <ForcedPasswordScreen username={username} />
      </>
    );
  }

  return (
    <div className="app">
      {showLoader && <PurifyLoader hide={!loading} />}

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
            <span className={`health ${gateBadge.cls}`} style={{ fontSize: 11 }} title={gateBadge.title}><i className="hdot"></i>{gateBadge.label}</span>
          </div>
          <div className="row" style={{ gap: 10, padding: "0 8px" }}>
            <div style={{ width: 30, height: 30, borderRadius: 8, background: "var(--ink-700)", display: "grid", placeItems: "center", fontSize: 12, fontWeight: 700, color: "var(--washi-soft)" }}>
              {username.slice(0, 2).toUpperCase()}
            </div>
            <div className="col" style={{ lineHeight: 1.25, minWidth: 0 }}>
              <span style={{ fontSize: 12.5, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                title={`${username} · ${role}`}>
                {username} <span className="faint" style={{ fontWeight: 500 }}>· {role}</span>
              </span>
              <span className="faint" style={{ fontSize: 11 }}>signed in</span>
            </div>
          </div>
          <div className="row" style={{ gap: 6, padding: "0 8px" }}>
            <button className="btn sm ghost" onClick={() => setPwModal(true)}>Change password</button>
            <button className="btn sm ghost" style={{ marginLeft: "auto" }} onClick={() => JOEI.logout()}>Sign out</button>
          </div>
        </div>
      </nav>

      {/* ---------- main ---------- */}
      <div className="main">
        <header className="topbar">
          <h1><span className="crumb-kanji kanji">{meta.kanji}</span> {meta.title}</h1>
          <div className="topbar-spacer"></div>

          <span className="pill" title="Console edits are persisted to the database and survive restart">
            <span className="muted" style={{ fontWeight: 500 }}>settings</span>&nbsp;·&nbsp;persisted
          </span>
          <span className={`pill ${policy.mode === "enforce" ? "enforce" : policy.mode === "dry_run" ? "dry" : "off"}`}>
            <span className="dot"></span>
            {policy.mode === "enforce" ? "Enforcing" : policy.mode === "dry_run" ? "Dry-run" : "Off"}
          </span>
        </header>

        {!connected && !loading && (
          <div className="conn-banner">&#9888; No connection to the proxy — data may be stale; retrying…</div>
        )}

        <div className="content">
          {page === "overview" && <Overview treatment={treatment} setTreatment={setTreatment} openThreat={openThreat} />}
          {page === "feed" && <LiveFeed openThreat={openThreat} />}
          {page === "quarantine" && <Quarantine onAllowlist={onAllowlist} />}
          {page === "policy" && <Policy notify={notify} />}
          {page === "registries" && <Registries notify={notify} />}
        </div>
      </div>

      {threat && <ThreatDrawer r={threat} onClose={() => setThreat(null)} onAllowlist={onAllowlist} onDenylist={onDenylist} />}
      {pwModal && <ChangePasswordModal onClose={() => setPwModal(false)} notify={notify} />}
      <ToastHost toasts={toasts} dismiss={dismiss} />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
