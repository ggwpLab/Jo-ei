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
        {(blocked || r.verdict === "ERROR") && r.http ? (
          <span style={{ color: "var(--vermilion-l)", fontFamily: "var(--mono)", fontSize: 11, marginRight: 6 }}>{r.http}</span>
        ) : null}
        {gateName}
      </span>
      <span className="lat mono" style={{ color: r.lat > 400 ? "var(--gold-l)" : undefined }}>{r.lat}ms</span>
      <span className="rid mono">{r.request_id}</span>
      <span className="chev">{blocked ? <Icons.chevron /> : null}</span>
    </div>
  );
}

const FILTERS = [
  ["all", "All"], ["BLOCK", "Blocked"], ["PASS", "Passed"],
  ["CACHE", "Cache"], ["ERROR", "Error"],
];

// Verdict filters that browse the full SQLite history (server-paged) rather
// than the live in-memory window. The chip value is sent verbatim as ?verdict=.
const HISTORY_FILTERS = { BLOCK: true, ERROR: true };

const PAGE_SIZE = 50;

function LiveFeed({ openThreat }) {
  const [rows, setRows] = useState(() => JOEI.requests.slice(0, 120));
  const [filter, setFilter] = useState("all");
  const [q, setQ] = useState("");
  const [paused, setPaused] = useState(false);
  const [newId, setNewId] = useState(null);

  // History-mode state, active only while filter is in HISTORY_FILTERS.
  const [histRows, setHistRows] = useState([]);
  const [cursor, setCursor] = useState("");
  const [loading, setLoading] = useState(false);
  const [histErr, setHistErr] = useState(false);
  // Monotonic token: bumped whenever the filter changes, so an in-flight
  // first-page or "Show more" fetch from a previous filter is ignored when it
  // resolves (otherwise a late response could write into the new filter's rows).
  const reqToken = useRef(0);

  const history = !!HISTORY_FILTERS[filter];

  // Live window: prepend SSE events and resync on full refresh. Kept warm even
  // in history mode so switching back to a live filter is instant.
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

  // Entering a history filter loads its first page; leaving one clears the
  // history state so a live filter shows the live window again. Keyed on
  // `filter` only (history is derived from it).
  useEffect(() => {
    const token = ++reqToken.current; // invalidate any prior in-flight fetch
    if (!history) {
      setHistRows([]); setCursor(""); setHistErr(false); setLoading(false);
      return;
    }
    setLoading(true); setHistErr(false); setHistRows([]); setCursor("");
    JOEI.pageRequests({ verdict: filter, cursor: "", limit: PAGE_SIZE })
      .then(({ rows: got, nextCursor }) => {
        if (token !== reqToken.current) return;
        setHistRows(got); setCursor(nextCursor);
      })
      .catch(() => { if (token === reqToken.current) setHistErr(true); })
      .finally(() => { if (token === reqToken.current) setLoading(false); });
  }, [filter]);

  const loadMore = () => {
    if (loading || !cursor) return;
    const token = reqToken.current; // tie this fetch to the current filter
    setHistErr(false);
    setLoading(true);
    JOEI.pageRequests({ verdict: filter, cursor, limit: PAGE_SIZE })
      .then(({ rows: got, nextCursor }) => {
        if (token !== reqToken.current) return; // filter changed mid-flight
        setHistRows((rs) => rs.concat(got));
        setCursor(nextCursor);
      })
      .catch(() => { if (token === reqToken.current) setHistErr(true); })
      .finally(() => { if (token === reqToken.current) setLoading(false); });
  };

  const hasMore = cursor !== "";

  const source = history ? histRows : rows;
  const shown = source.filter((r) => {
    // Live filters narrow the in-memory window client-side; history rows are
    // already verdict-filtered by the server.
    if (!history && filter !== "all" && r.verdict !== filter) return false;
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
        {history ? (
          <span className="pill">
            <span className="dot" style={{ color: "var(--washi-mut)" }}></span>
            history · {filter.toLowerCase()}
          </span>
        ) : (
          <>
            <button className="btn sm ghost" onClick={() => setPaused((p) => !p)}>
              {paused ? "Resume" : "Pause"} stream
            </button>
            <span className="pill">
              <span className="dot live" style={{ color: paused ? "var(--washi-faint)" : "var(--jade)" }}></span>
              {paused ? "paused" : "live"}
            </span>
          </>
        )}
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

        {histErr && histRows.length === 0 ? (
          <div className="empty">
            <span className="e-kanji">録</span>
            <div className="e-title">Could not load history</div>
            <div className="e-sub">The request history could not be fetched. Check the connection and try the filter again.</div>
          </div>
        ) : shown.length === 0 ? (
          loading ? (
            <div className="empty"><div className="e-sub">Loading…</div></div>
          ) : (
            <div className="empty">
              <span className="e-kanji">無</span>
              <div className="e-title">No matching requests</div>
              <div className="e-sub">{q || filter !== "all"
                ? <>Nothing matches "{q || filter}". Clear the filter to see all traffic.</>
                : <>No requests have passed through the gate yet. Point a package manager at the proxy and traffic will appear here live.</>}</div>
            </div>
          )
        ) : (
          shown.map((r) => (
            <FeedRow key={r.request_id} r={r} onOpen={openThreat} isNew={r.request_id === newId} />
          ))
        )}

        {history && histErr && histRows.length > 0 ? (
          // A page already loaded but "Show more" failed: keep the rows visible
          // and offer a retry instead of replacing the whole view with an error.
          <div style={{ padding: "12px", textAlign: "center", borderTop: "1px solid var(--washi-faint)" }}>
            <span className="muted mono" style={{ fontSize: 12, marginRight: 8 }}>Couldn't load more.</span>
            <button className="btn sm ghost" onClick={loadMore} disabled={loading}>Retry</button>
          </div>
        ) : history && !histErr && (hasMore || loading) ? (
          <div style={{ padding: "12px", textAlign: "center", borderTop: "1px solid var(--washi-faint)" }}>
            <button className="btn sm ghost" onClick={loadMore} disabled={loading || !hasMore}>
              {loading ? "Loading…" : "Show more"}
            </button>
          </div>
        ) : null}
      </div>
    </div>
  );
}

Object.assign(window, { FeedRow, LiveFeed });
