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
  const k = JOEI.kpis;
  const recent = JOEI.requests.slice(0, 6);

  return (
    <div className="content-inner">
      {/* hero */}
      <GateHero treatment={treatment} setTreatment={setTreatment} />

      {/* KPI cards */}
      <div className="section-head" style={{ marginTop: 28 }}>
        <span className="head-kanji kanji">衛</span>
        <div>
          <div className="eyebrow">Today · {new Date().toLocaleDateString("en-US", { month: "short", day: "numeric" })}</div>
          <h2>Gate throughput</h2>
        </div>
      </div>

      <div className="kpi-grid">
        <KpiCard label="Requests today" value={fmtCompact(k.requests_today)}
          delta={<><b>{fmtNum(k.requests_today)}</b> total · +8.2% vs yesterday</>}
          spark={k.requests_spark} sparkColor="var(--washi-mut)" watermark="求" />
        <KpiCard label="Served from cache" value={(k.hit_rate * 100).toFixed(1) + "%"} accent="jade"
          delta={<><b>{fmtCompact(k.cache_hits)}</b> hits · LRU, 64 GB</>}
          spark={[68,70,69,72,71,73,72,74,73,75,73,73]} sparkColor="var(--jade)" watermark="蔵" />
        <KpiCard label="Blocked total" value={fmtNum(k.blocked_total)} accent="verm"
          delta={<>423 Locked + 403 Forbidden · +12% spike</>}
          spark={k.blocked_spark} sparkColor="var(--vermilion)" watermark="封" />
        <KpiCard label="Quarantined · 24h" value={fmtNum(k.quarantined_24h)} accent="gold"
          delta={<>held &lt; 24h old · awaiting maturity</>}
          spark={[8,11,9,14,12,16,15,19,17,15,18,14]} sparkColor="var(--gold)" watermark="守" />
      </div>

      {/* block breakdown */}
      <div className="card breakdown" style={{ marginTop: 14 }}>
        <div className="bd">
          <span className="v" style={{ color: "var(--gold-l)" }}>{fmtNum(k.quarantined_24h)}</span>
          <span className="l">衛 Quarantined (24h) · 423</span>
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
