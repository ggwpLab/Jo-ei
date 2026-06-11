/* 浄衛 Jōei :: shared primitives (icons, torii, badges, helpers) */

const { useState, useEffect, useRef, useMemo, useCallback } = React;

/* ---------- formatters ---------- */
function fmtNum(n) { return n.toLocaleString("en-US"); }
function fmtCompact(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(2).replace(/\.?0+$/, "") + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, "") + "k";
  return String(n);
}
function fmtClock(d) {
  return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function fmtAgo(d) {
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 60) return s + "s ago";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m ago";
  const h = Math.floor(m / 60);
  return h + "h ago";
}
function fmtCountdown(target) {
  let ms = target.getTime() - Date.now();
  if (ms < 0) ms = 0;
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

/* re-render when api.js refreshes window.JOEI */
function useJoeiData() {
  const [, setTick] = useState(0);
  useEffect(() => {
    const fn = () => setTick((t) => t + 1);
    window.addEventListener("joei:data", fn);
    window.addEventListener("joei:policy", fn);
    return () => {
      window.removeEventListener("joei:data", fn);
      window.removeEventListener("joei:policy", fn);
    };
  }, []);
}

/* ---------- icons (1.6 stroke, currentColor) ---------- */
function Ico({ d, size = 18, fill = false, stroke = true, vb = 24, children }) {
  return (
    <svg className="nav-ico" width={size} height={size} viewBox={`0 0 ${vb} ${vb}`}
      fill={fill ? "currentColor" : "none"} stroke={stroke ? "currentColor" : "none"}
      strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      {children || <path d={d} />}
    </svg>
  );
}
const Icons = {
  overview: () => <Ico><path d="M3 13h8V3H3zM13 21h8V8h-8zM13 3v3h8V3zM3 21h8v-4H3z"/></Ico>,
  feed:     () => <Ico><path d="M4 6h16M4 12h16M4 18h10"/><circle cx="19" cy="18" r="2"/></Ico>,
  quar:     () => <Ico><path d="M6 2h12M6 22h12M8 2c0 4 8 6 8 10s-8 6-8 10M16 2c0 4-8 6-8 10"/></Ico>,
  policy:   () => <Ico><path d="M5 3h11l3 3v15H5zM9 9h6M9 13h6M9 17h3"/></Ico>,
  registry: () => <Ico><rect x="3" y="4" width="18" height="5" rx="1"/><rect x="3" y="14" width="18" height="5" rx="1"/><path d="M7 6.5h.01M7 16.5h.01"/></Ico>,
  shield:   () => <Ico><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></Ico>,
  search:   () => <Ico size={15}><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></Ico>,
  chevron:  () => <Ico size={15}><path d="M9 6l6 6-6 6"/></Ico>,
  x:        () => <Ico size={16}><path d="M6 6l12 12M18 6L6 18"/></Ico>,
  check:    () => <Ico size={15}><path d="M5 12l5 5 9-11"/></Ico>,
  plus:     () => <Ico size={15}><path d="M12 5v14M5 12h14"/></Ico>,
  bolt:     () => <Ico size={15}><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></Ico>,
  trash:    () => <Ico size={15}><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></Ico>,
  ext:      () => <Ico size={13}><path d="M14 4h6v6M20 4l-9 9M19 13v6H5V5h6"/></Ico>,
  dot6:     () => <Ico size={13}><circle cx="9" cy="6" r="1.4" fill="currentColor" stroke="none"/><circle cx="15" cy="6" r="1.4" fill="currentColor" stroke="none"/><circle cx="9" cy="12" r="1.4" fill="currentColor" stroke="none"/><circle cx="15" cy="12" r="1.4" fill="currentColor" stroke="none"/><circle cx="9" cy="18" r="1.4" fill="currentColor" stroke="none"/><circle cx="15" cy="18" r="1.4" fill="currentColor" stroke="none"/></Ico>,
  refresh:  () => <Ico size={15}><path d="M20 11a8 8 0 10-2 5M20 5v6h-6"/></Ico>,
};

/* ---------- torii SVG (the gate motif) ---------- */
function Torii({ state }) {
  // state: idle | pass | block  -> drives kasagi (top beam) color
  const beam = state === "pass" ? "var(--jade)" : state === "block" ? "var(--vermilion)" : "var(--ink-600)";
  const pillar = "var(--ink-650)";
  const stroke = "rgba(237,231,218,0.10)";
  return (
    <div className="torii">
      <svg viewBox="0 0 132 116">
        {/* kasagi — curved top lintel */}
        <path className="arch-glow" d="M6 22 Q66 6 126 22 L126 33 Q66 19 6 33 Z" fill={beam} stroke={stroke}/>
        {/* nuki — second beam */}
        <rect className="arch-glow" x="18" y="40" width="96" height="9" rx="2" fill={beam} opacity="0.78" stroke={stroke}/>
        {/* gakuzuka — center tablet */}
        <rect x="60" y="30" width="12" height="14" rx="1.5" fill={pillar} stroke={stroke}/>
        {/* pillars (slight inward lean) */}
        <path d="M30 49 L36 110 L46 110 L40 49 Z" fill={pillar} stroke={stroke}/>
        <path d="M102 49 L96 110 L86 110 L92 49 Z" fill={pillar} stroke={stroke}/>
      </svg>
    </div>
  );
}

/* small torii used for brand mark + loader */
function ToriiMark({ size = 28, lit = false }) {
  return (
    <svg width={size} height={size} viewBox="0 0 132 116" style={{ overflow: "visible" }}>
      <path className={lit ? "lit" : ""} d="M6 22 Q66 6 126 22 L126 33 Q66 19 6 33 Z" fill="var(--vermilion)"/>
      <rect className={lit ? "lit" : ""} x="18" y="40" width="96" height="9" rx="2" fill="var(--vermilion)" opacity="0.82"/>
      <rect x="60" y="30" width="12" height="14" rx="1.5" fill="var(--ink-650)"/>
      <path d="M30 49 L36 110 L46 110 L40 49 Z" fill="var(--washi-soft)"/>
      <path d="M102 49 L96 110 L86 110 L92 49 Z" fill="var(--washi-soft)"/>
    </svg>
  );
}

/* ---------- ecosystem chip ---------- */
function Eco({ id, size }) {
  const e = JOEI.ECO[id] || { label: id, id: "pypi" };
  return <span className={`eco ${id}`} style={size ? { width: size, height: size } : undefined} title={e.name}>{e.label}</span>;
}

/* ---------- verdict badge ---------- */
function Verdict({ v }) {
  if (v === "PASS")  return <span className="badge pass"><i className="dot" style={{width:5,height:5,borderRadius:9,background:"currentColor"}}></i>PASS</span>;
  if (v === "CACHE") return <span className="badge cache">CACHE HIT</span>;
  if (v === "BLOCK") return <span className="badge block">BLOCKED</span>;
  return <span className="badge">{v}</span>;
}

/* ---------- sparkline ---------- */
function Spark({ data, color = "var(--washi-mut)", h = 30, w = 130, fill = true }) {
  const { path, area } = useMemo(() => {
    const max = Math.max(...data), min = Math.min(...data);
    const rng = max - min || 1;
    const step = w / (data.length - 1);
    const pts = data.map((d, i) => [i * step, h - ((d - min) / rng) * (h - 4) - 2]);
    const path = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    const area = path + ` L${w} ${h} L0 ${h} Z`;
    return { path, area };
  }, [data, h, w]);
  const gid = useMemo(() => "sg" + Math.random().toString(36).slice(2, 7), []);
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      {fill && <defs><linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stopColor={color} stopOpacity="0.22"/><stop offset="1" stopColor={color} stopOpacity="0"/>
      </linearGradient></defs>}
      {fill && <path d={area} fill={`url(#${gid})`}/>}
      <path d={path} fill="none" stroke={color} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}

/* ---------- gate label helper ---------- */
const GATE_LABEL = {
  cache: "Cache", supply: "Supply Chain", cve: "CVE", malware: "Malware",
  supply_chain: "Supply Chain", denylist: "Denylist",
};

Object.assign(window, {
  fmtNum, fmtCompact, fmtClock, fmtAgo, fmtCountdown,
  useJoeiData,
  Ico, Icons, Torii, ToriiMark, Eco, Verdict, Spark, GATE_LABEL,
  useState, useEffect, useRef, useMemo, useCallback,
});
