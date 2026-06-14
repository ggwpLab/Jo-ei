/* 浄衛 Jōei :: LIVE REQUEST FEED */

function FeedRow({ r, onOpen, isNew }) {
  const blocked = r.verdict === "BLOCK";
  const gateName = blocked ? GATE_LABEL[r.blocked_by[0]] : GATE_LABEL[r.gate] || "—";
  return (
    <div
      className={`feed-row ${blocked ? "clickable" : ""} ${isNew ? "new-row" : ""}`}
      onClick={blocked ? () => onOpen(r) : undefined}
    >
      <span className="ts mono">{fmtClock(r.ts)}</span>
      <Eco id={r.eco} />
      <span className="pkg" title={`${r.pkg}@${r.ver}`}>
        {r.pkg}<span className="ver">@{r.ver}</span>
      </span>
      <span><Verdict v={r.verdict} /></span>
      <span className="gate-cell">
        {blocked && <span style={{ color: "var(--vermilion-l)", fontFamily: "var(--mono)", fontSize: 11, marginRight: 6 }}>{r.http}</span>}
        {gateName}
      </span>
      <span className="lat mono" style={{ color: r.lat > 400 ? "var(--gold-l)" : undefined }}>{r.lat}ms</span>
      <span className="rid mono">{r.request_id}</span>
      <span className="chev">{blocked ? <Icons.chevron /> : null}</span>
    </div>
  );
}

const FILTERS = [
  ["all", "All"], ["BLOCK", "Blocked"], ["PASS", "Passed"], ["CACHE", "Cache"],
];

function LiveFeed({ openThreat }) {
  const [rows, setRows] = useState(() => JOEI.requests.slice(0, 120));
  const [filter, setFilter] = useState("all");
  const [q, setQ] = useState("");
  const [paused, setPaused] = useState(false);
  const [newId, setNewId] = useState(null);

  useEffect(() => {
    const onEvent = (e) => {
      if (paused) return;
      setNewId(e.detail.request_id);
      setRows((rs) => [e.detail, ...rs].slice(0, 120));
    };
    const onData = () => { if (!paused) setRows(JOEI.requests.slice(0, 120)); };
    window.addEventListener("joei:event", onEvent);
    window.addEventListener("joei:data", onData);
    return () => {
      window.removeEventListener("joei:event", onEvent);
      window.removeEventListener("joei:data", onData);
    };
  }, [paused]);

  const shown = rows.filter((r) => {
    if (filter !== "all" && r.verdict !== filter) return false;
    if (q && !(`${r.pkg}@${r.ver}`.toLowerCase().includes(q.toLowerCase()) || r.request_id.includes(q))) return false;
    return true;
  });

  return (
    <div className="content-inner">
      <div className="section-head">
        <span className="head-kanji kanji">流</span>
        <div>
          <div className="eyebrow">Live · request_id stream</div>
          <h2>Request feed</h2>
        </div>
        <div className="spacer"></div>
        <button className="btn sm ghost" onClick={() => setPaused((p) => !p)}>
          {paused ? "Resume" : "Pause"} stream
        </button>
        <span className="pill">
          <span className="dot live" style={{ color: paused ? "var(--washi-faint)" : "var(--jade)" }}></span>
          {paused ? "paused" : "live"}
        </span>
      </div>

      <div className="card" style={{ overflow: "hidden" }}>
        <div className="feed-toolbar">
          <div className="seg">
            {FILTERS.map(([k, l]) => (
              <button key={k} className={filter === k ? "active" : ""} onClick={() => setFilter(k)}>{l}</button>
            ))}
          </div>
          <div className="search">
            <Icons.search />
            <input placeholder="filter by package or request_id…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <span className="right muted mono" style={{ fontSize: 12 }}>{shown.length} shown</span>
        </div>

        <div className="feed-row head">
          <span>TIME</span><span></span><span>PACKAGE</span><span>VERDICT</span>
          <span>GATE</span><span style={{ textAlign: "right" }}>LATENCY</span><span>REQUEST ID</span><span></span>
        </div>

        {shown.length === 0 ? (
          <div className="empty">
            <span className="e-kanji">無</span>
            <div className="e-title">No matching requests</div>
            <div className="e-sub">{q || filter !== "all"
              ? <>Nothing in the stream matches “{q || filter}”. Clear the filter to see all traffic.</>
              : <>No requests have passed through the gate yet. Point a package manager at the proxy and traffic will appear here live.</>}</div>
          </div>
        ) : (
          shown.map((r) => (
            <FeedRow key={r.request_id} r={r} onOpen={openThreat} isNew={r.request_id === newId} />
          ))
        )}
      </div>
    </div>
  );
}

Object.assign(window, { FeedRow, LiveFeed });
