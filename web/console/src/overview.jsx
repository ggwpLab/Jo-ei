/* 浄衛 Jōei :: OVERVIEW dashboard */

function KpiCard({ label, value, accent, delta, spark, sparkColor, watermark }) {
  return (
    <div className="card kpi">
      {watermark && <span className="kpi-watermark">{watermark}</span>}
      <div className="kpi-label">{label}</div>
      <div className={`kpi-val ${accent || ""}`}>{value}</div>
      {delta && <div className="kpi-delta">{delta}</div>}
      {spark && <div className="kpi-spark"><Spark data={spark} color={sparkColor} h={44} /></div>}
    </div>
  );
}

function Overview({ treatment, setTreatment, openThreat }) {
  useJoeiData();
  const [, setTick] = useState(0);
  useEffect(() => {
    const fn = () => setTick((t) => t + 1);
    window.addEventListener("joei:event", fn);
    return () => window.removeEventListener("joei:event", fn);
  }, []);

  const k = JOEI.kpis;
  const recent = JOEI.requests.slice(0, 6);
  const uptime = k.started_at ? fmtAgo(k.started_at).replace(" ago", "") : "—";

  const [win, setWin] = useState(30);
  // Toggling the window only re-slices the already-loaded array — no refetch.
  const rows = JOEI.daily.slice(-win);
  // Spark breaks on <2 points (Math.max(...[]) === -Infinity, divide by len-1).
  // With fewer points pass `undefined` so the card renders exactly as before.
  const haveTrend = rows.length >= 2;
  const reqSpark = haveTrend ? rows.map((r) => r.requests) : undefined;
  const hitSpark = haveTrend ? rows.map((r) => (r.requests ? r.cache_hits / r.requests : 0)) : undefined;
  const blkSpark = haveTrend ? rows.map((r) => r.blocked) : undefined;
  // Quarantine has no daily counter; supply_blocked (423 min-age holds) is its
  // daily flow — the new "awaiting maturity" holds per day.
  const qSpark = haveTrend ? rows.map((r) => r.supply_blocked) : undefined;

  return (
    <div className="content-inner">
      {/* hero */}
      <GateHero treatment={treatment} setTreatment={setTreatment} />

      {/* KPI cards */}
      <div className="section-head" style={{ marginTop: 28 }}>
        <span className="head-kanji kanji">衛</span>
        <div>
          <div className="eyebrow">Totals · uptime {uptime}</div>
          <h2>Gate throughput</h2>
        </div>
        <div className="spacer"></div>
        {JOEI.daily.length >= 2 ? (
          <div className="seg" role="group" aria-label="Sparkline window">
            {[7, 30].map((n) => (
              <button key={n} className={win === n ? "active" : ""} onClick={() => setWin(n)}>{n}d</button>
            ))}
          </div>
        ) : (
          <span className="faint" style={{ fontSize: 11 }}>
            {JOEI.daily.length === 0
              ? "no history yet · set database.path to persist daily metrics"
              : "charts appear after 2+ days of history"}
          </span>
        )}
      </div>

      <div className="kpi-grid">
        <KpiCard label="Requests · total" value={fmtCompact(k.requests_total)}
          delta={<><b>{fmtNum(k.requests_total)}</b> total · {fmtNum(k.errors)} errors</>} watermark="求"
          spark={reqSpark} sparkColor="var(--washi-mut)" />
        <KpiCard label="Served from cache" value={(k.hit_rate * 100).toFixed(1) + "%"} accent="jade"
          delta={<><b>{fmtCompact(k.cache_hits)}</b> hits total</>} watermark="蔵"
          spark={hitSpark} sparkColor="var(--jade)" />
        <KpiCard label="Blocked · total" value={fmtNum(k.blocked_total)} accent="verm"
          delta={<>423 Locked + 403 Forbidden</>} watermark="封"
          spark={blkSpark} sparkColor="var(--vermilion)" />
        <KpiCard label="In quarantine" value={fmtNum(k.quarantined)} accent="gold"
          delta={<>held until min-age maturity</>} watermark="守"
          spark={qSpark} sparkColor="var(--gold)" />
      </div>

      {/* block breakdown */}
      <div className="card breakdown" style={{ marginTop: 14 }}>
        <div className="bd">
          <span className="v" style={{ color: "var(--gold-l)" }}>{fmtNum(k.supply_blocked)}</span>
          <span className="l">衛 Supply-chain · 423</span>
        </div>
        <div className="bd">
          <span className="v" style={{ color: "var(--vermilion-l)" }}>{fmtNum(k.cve_blocked)}</span>
          <span className="l">浄 CVE blocked · 403</span>
        </div>
        <div className="bd">
          <span className="v" style={{ color: "var(--vermilion-l)" }}>{fmtNum(k.malware_blocked)}</span>
          <span className="l">浄 Malware blocked · 403</span>
        </div>
        <div className="bd">
          <span className="v" style={{ color: "var(--washi-soft)" }}>{fmtNum(k.denylisted)}</span>
          <span className="l">Denylisted · 403</span>
        </div>
      </div>

      {/* recent blocks preview */}
      <div className="section-head" style={{ marginTop: 32 }}>
        <span className="head-kanji kanji">浄</span>
        <div>
          <div className="eyebrow">Last few verdicts</div>
          <h2>Recent activity</h2>
        </div>
        <div className="spacer"></div>
        <span className="pill"><span className="dot live" style={{ color: "var(--jade)" }}></span>streaming</span>
      </div>

      <div className="card" style={{ overflow: "hidden" }}>
        <div className="feed-row head">
          <span>TIME</span><span></span><span>PACKAGE</span><span>VERDICT</span>
          <span>GATE</span><span style={{ textAlign: "right" }}>LATENCY</span><span>REQUEST ID</span><span></span>
        </div>
        {recent.map((r) => (
          <FeedRow key={r.request_id} r={r} onOpen={openThreat} />
        ))}
      </div>
    </div>
  );
}

Object.assign(window, { Overview, KpiCard });
