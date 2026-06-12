/* 浄衛 Jōei :: OVERVIEW dashboard */

function KpiCard({ label, value, accent, delta, spark, sparkColor, watermark }) {
  return (
    <div className="card kpi">
      {watermark && <span className="kpi-watermark">{watermark}</span>}
      <div className="kpi-label">{label}</div>
      <div className={`kpi-val ${accent || ""}`}>{value}</div>
      {delta && <div className="kpi-delta">{delta}</div>}
      {spark && <div className="kpi-spark"><Spark data={spark} color={sparkColor} /></div>}
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

  return (
    <div className="content-inner">
      {/* hero */}
      <GateHero treatment={treatment} setTreatment={setTreatment} />

      {/* KPI cards */}
      <div className="section-head" style={{ marginTop: 28 }}>
        <span className="head-kanji kanji">衛</span>
        <div>
          <div className="eyebrow">Since start · uptime {uptime}</div>
          <h2>Gate throughput</h2>
        </div>
      </div>

      <div className="kpi-grid">
        <KpiCard label="Requests · since start" value={fmtCompact(k.requests_total)}
          delta={<><b>{fmtNum(k.requests_total)}</b> total · {fmtNum(k.errors)} errors</>} watermark="求" />
        <KpiCard label="Served from cache" value={(k.hit_rate * 100).toFixed(1) + "%"} accent="jade"
          delta={<><b>{fmtCompact(k.cache_hits)}</b> hits since start</>} watermark="蔵" />
        <KpiCard label="Blocked · since start" value={fmtNum(k.blocked_total)} accent="verm"
          delta={<>423 Locked + 403 Forbidden</>} watermark="封" />
        <KpiCard label="In quarantine" value={fmtNum(k.quarantined)} accent="gold"
          delta={<>held until min-age maturity</>} watermark="守" />
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
