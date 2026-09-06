/* 浄衛 Jōei :: OVERVIEW dashboard */

// sparkNote captions the sparkline. The card's value is an all-time counter
// while the sparkline is a 30-day daily trend, so the two are deliberately
// labelled as different things rather than read as a total and its breakdown.
function KpiCard({ label, value, accent, delta, spark, sparkColor, sparkNote, watermark }) {
  return (
    <div className="card kpi">
      {watermark && <span className="kpi-watermark">{watermark}</span>}
      <div className="kpi-label">{label}</div>
      <div className={`kpi-val ${accent || ""}`}>{value}</div>
      {delta && <div className="kpi-delta">{delta}</div>}
      {spark && <div className="kpi-spark"><Spark data={spark} color={sparkColor} h={44} /></div>}
      {spark && sparkNote && <div className="kpi-sparknote">{sparkNote}</div>}
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

  // Every card value is an all-time counter from /api/overview. Telemetry is
  // SQLite-only (database.path is required), so those counters survive
  // restarts and "all time" is literally true — there is no second time base
  // to reconcile them against.
  //
  // The sparklines are the one exception and are captioned as a separate
  // thing: a fixed 30-day daily trend. Daily rows exist only for days that saw
  // traffic, so the window is a UTC-date cutoff rather than a positional slice
  // — r.day is UTC YYYY-MM-DD, so a string compare is a date compare, and the
  // window includes today, hence 29 days back. daily_metrics is also pruned by
  // database.daily_retention_days while the counters never are, which is the
  // other reason the trend must not read as a breakdown of the value.
  const TREND_DAYS = 30;
  const cutoff = new Date(Date.now() - (TREND_DAYS - 1) * 86400000).toISOString().slice(0, 10);
  const rows = JOEI.daily.filter((r) => r.day >= cutoff);
  // Spark breaks on <2 points (Math.max(...[]) === -Infinity, divide by len-1).
  // With fewer points pass `undefined` and the card renders without a trend.
  const haveTrend = rows.length >= 2;
  const trendNote = `${TREND_DAYS}d trend`;
  const reqSpark = haveTrend ? rows.map((r) => r.requests) : undefined;
  const hitSpark = haveTrend ? rows.map((r) => (r.requests ? r.cache_hits / r.requests : 0)) : undefined;
  const blkSpark = haveTrend ? rows.map((r) => r.blocked) : undefined;

  return (
    <div className="content-inner">
      {/* hero */}
      <GateHero treatment={treatment} setTreatment={setTreatment} />

      {/* KPI cards */}
      <div className="section-head" style={{ marginTop: 28 }}>
        <span className="head-kanji kanji">衛</span>
        <div>
          <div className="eyebrow">All time · uptime {uptime}</div>
          <h2>Gate throughput</h2>
        </div>
        <div className="spacer"></div>
        {!haveTrend && (
          <span className="faint" style={{ fontSize: 11 }}>
            {JOEI.daily.length === 0
              ? "no traffic recorded yet"
              : `${trendNote} appears after 2+ days of traffic`}
          </span>
        )}
      </div>

      <div className="kpi-grid">
        <KpiCard label="Requests" value={fmtCompact(k.requests_total)}
          delta={<><b>{fmtNum(k.errors)}</b> errors</>} watermark="求"
          spark={reqSpark} sparkColor="var(--washi-mut)" sparkNote={trendNote} />
        <KpiCard label="Served from cache" value={(k.hit_rate * 100).toFixed(1) + "%"} accent="jade"
          delta={<><b>{fmtCompact(k.cache_hits)}</b> hits</>} watermark="蔵"
          spark={hitSpark} sparkColor="var(--jade)" sparkNote={trendNote} />
        <KpiCard label="Blocked" value={fmtNum(k.blocked_total)} accent="verm"
          delta={<>423 Locked + 403 Forbidden</>} watermark="封"
          spark={blkSpark} sparkColor="var(--vermilion)" sparkNote={trendNote} />
        {/* Quarantine is a live gauge (quarantine.length), not a counter: how
            many packages are held right now. It gets no sparkline — the daily
            rows carry no quarantine depth, only the supply-block flow that
            fills it, and plotting that under this number read as a history of
            the gauge itself. */}
        <KpiCard label="In quarantine" value={fmtNum(k.quarantined)} accent="gold"
          delta={<>held now · released at min-age maturity</>} watermark="守" />
      </div>

      {/* Block breakdown. "of which" and not "totalling": a block on a gate
          outside supply/cve/malware that carries no denylist reason counts
          toward blocked_total but lands in none of these buckets, so the four
          are not promised to add up to the Blocked card. */}
      <div className="faint" style={{ marginTop: 14, fontSize: 11, letterSpacing: ".04em" }}>
        of which · all time
      </div>
      <div className="card breakdown" style={{ marginTop: 6 }}>
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
