/* 浄衛 Jōei :: QUARANTINE — 衛 24h supply-chain hold */

function QuarantineCard({ q, onAllowlist }) {
  const [, tick] = useState(0);
  useEffect(() => {
    const enabled = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const id = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, []);

  const total = Math.max(1, q.block_until.getTime() - q.published_at.getTime());
  const remaining = Math.max(0, q.block_until.getTime() - Date.now());
  const matured = (total - remaining) / total; // 0..1
  const pct = Math.min(100, Math.max(0, matured * 100));

  return (
    <div className="card q-card">
      <span className="seal kanji">衛</span>
      <div className="q-head">
        <Eco id={q.eco} />
        <span className="badge hold">423 LOCKED</span>
      </div>
      <div>
        <div className="q-pkg">{q.pkg}<span className="muted">@{q.ver}</span></div>
        <div className="q-pub">published <b>{fmtAgo(q.published_at)}</b> · {(JOEI.ECO[q.eco] || { name: q.eco }).name}</div>
      </div>

      <div>
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 6 }}>
          <span className="muted" style={{ fontSize: 11.5 }}>maturing to {JOEI.policy.min_age_hours}h</span>
          <span className="countdown">{fmtCountdown(q.block_until)}</span>
        </div>
        <div className="hourglass-bar"><i style={{ width: pct + "%" }}></i></div>
      </div>

      <div className="q-actions">
        <button className="btn jade sm grow" onClick={() => onAllowlist(q)}>
          <Icons.check /> Allowlist (trust)
        </button>
        <button className="btn ghost sm">Wait</button>
      </div>
    </div>
  );
}

function Quarantine({ onAllowlist }) {
  useJoeiData();
  const [items, setItems] = useState(() => JOEI.quarantine.slice());
  useEffect(() => {
    const fn = () => setItems(JOEI.quarantine.slice());
    window.addEventListener("joei:data", fn);
    return () => window.removeEventListener("joei:data", fn);
  }, []);
  const handle = (q) => {
    setItems((xs) => xs.filter((x) => x !== q));
    onAllowlist(q);
  };

  return (
    <div className="content-inner">
      <div className="section-head">
        <span className="head-kanji kanji" style={{ color: "var(--gold-l)", opacity: .9 }}>衛</span>
        <div>
          <div className="eyebrow">Supply-chain hold · HTTP 423 Locked</div>
          <h2>Quarantine</h2>
        </div>
        <div className="spacer"></div>
        <span className="pill"><span className="dot" style={{ color: "var(--gold)" }}></span>{items.length} held</span>
      </div>

      <p className="muted" style={{ maxWidth: 680, marginTop: -4, marginBottom: 22, fontSize: 13.5, lineHeight: 1.6 }}>
        Packages published less than <b style={{ color: "var(--washi)" }}>{JOEI.policy.min_age_hours} hours</b> ago are held at the 衛 gate
        until they mature — the window where most malicious releases are caught and yanked. Trust one early by adding it to the allowlist.
      </p>

      {items.length === 0 ? (
        <div className="card">
          <div className="empty">
            <span className="e-kanji">空</span>
            <div className="e-title">The gate is clear</div>
            <div className="e-sub">No packages are currently held for maturity. New releases will appear here automatically while they age toward the 24h threshold.</div>
          </div>
        </div>
      ) : (
        <div className="q-grid">
          {items.map((q) => <QuarantineCard key={q.pkg + q.ver} q={q} onAllowlist={handle} />)}
        </div>
      )}
    </div>
  );
}

Object.assign(window, { Quarantine, QuarantineCard });
