/* 浄衛 Jōei :: mock data store (realistic packages + CVEs) */
(function () {
  "use strict";

  const ECO = {
    pypi:     { id: "pypi",     label: "py",   name: "PyPI" },
    npm:      { id: "npm",      label: "npm",  name: "npm" },
    maven:    { id: "maven",    label: "mvn",  name: "Maven" },
    yarn:     { id: "yarn",     label: "yarn", name: "yarn" },
    rubygems: { id: "rubygems", label: "rb",   name: "RubyGems" },
  };

  // CVE library keyed by id
  const CVES = {
    "CVE-2021-44228": { id: "CVE-2021-44228", severity: "CRITICAL", cvss: 10.0, summary: "Log4Shell — JNDI lookups in Log4j 2 allow remote code execution via crafted log messages.", source: "osv.dev" },
    "CVE-2021-45046": { id: "CVE-2021-45046", severity: "CRITICAL", cvss: 9.0, summary: "Incomplete Log4Shell fix — Thread Context Map lookups still permit RCE in non-default configs.", source: "osv.dev" },
    "CVE-2023-50782": { id: "CVE-2023-50782", severity: "HIGH", cvss: 7.5, summary: "Bleichenbacher timing oracle in cryptography's RSA decryption enables plaintext recovery.", source: "osv.dev" },
    "CVE-2024-37891": { id: "CVE-2024-37891", severity: "MEDIUM", cvss: 4.4, summary: "urllib3 — Proxy-Authorization header not stripped on cross-origin redirect.", source: "osv.dev" },
    "CVE-2023-43804": { id: "CVE-2023-43804", severity: "MEDIUM", cvss: 6.5, summary: "urllib3 — Cookie header leaks across cross-origin redirects when set on the request.", source: "osv.dev" },
    "CVE-2023-44271": { id: "CVE-2023-44271", severity: "HIGH", cvss: 7.5, summary: "Pillow — uncontrolled memory consumption when rendering text with very long lines (DoS).", source: "osv.dev" },
    "CVE-2022-40897": { id: "CVE-2022-40897", severity: "MEDIUM", cvss: 5.9, summary: "setuptools — ReDoS in package_index via crafted HTML index page.", source: "osv.dev" },
    "CVE-2020-36518": { id: "CVE-2020-36518", severity: "HIGH", cvss: 7.5, summary: "jackson-databind — deeply nested JSON triggers StackOverflow denial of service.", source: "osv.dev" },
    "CVE-2023-32681": { id: "CVE-2023-32681", severity: "MEDIUM", cvss: 6.1, summary: "requests — Proxy-Authorization header leaked to destination server on redirect.", source: "osv.dev" },
  };

  const now = Date.now();
  const ago = (s) => new Date(now - s * 1000);

  // verdict: PASS | CACHE | BLOCK ; gate: cache | supply | cve | malware
  const GATES = ["cache", "supply", "cve", "malware"];

  function rid() {
    const c = "0123456789abcdef";
    let s = "";
    for (let i = 0; i < 12; i++) s += c[Math.floor(Math.random() * 16)];
    return "req_" + s;
  }

  // -------- seed request feed --------
  const SEED = [
    { eco: "maven", pkg: "org.apache.logging.log4j:log4j-core", ver: "2.14.1", verdict: "BLOCK", gate: "cve", lat: 412, http: 403,
      blocked_by: ["cve"], cves: ["CVE-2021-44228", "CVE-2021-45046"] },
    { eco: "npm", pkg: "lodash", ver: "4.17.21", verdict: "CACHE", gate: "cache", lat: 6 },
    { eco: "pypi", pkg: "requests", ver: "2.31.0", verdict: "PASS", gate: "malware", lat: 188 },
    { eco: "npm", pkg: "event-stream", ver: "3.3.6", verdict: "BLOCK", gate: "malware", lat: 524, http: 403,
      blocked_by: ["malware"], malware: { engine: "ClamAV 1.3.1", signature: "JS.Trojan.Flatmap-Stream", action: "ICAP REJECT" } },
    { eco: "pypi", pkg: "urllib3", ver: "1.26.4", verdict: "BLOCK", gate: "cve", lat: 233, http: 403,
      blocked_by: ["cve"], cves: ["CVE-2024-37891", "CVE-2023-43804"] },
    { eco: "yarn", pkg: "chalk", ver: "5.3.0", verdict: "CACHE", gate: "cache", lat: 5 },
    { eco: "pypi", pkg: "cryptography", ver: "41.0.1", verdict: "BLOCK", gate: "cve", lat: 277, http: 403,
      blocked_by: ["cve"], cves: ["CVE-2023-50782"] },
    { eco: "npm", pkg: "express", ver: "4.19.2", verdict: "PASS", gate: "malware", lat: 201 },
    { eco: "pypi", pkg: "reqursts", ver: "9.9.9", verdict: "BLOCK", gate: "malware", lat: 689, http: 403,
      blocked_by: ["malware"], malware: { engine: "ClamAV 1.3.1", signature: "Python.Trojan.PyPIStealer-A", action: "ICAP REJECT" }, note: "Typosquat of 'requests'" },
    { eco: "rubygems", pkg: "nokogiri", ver: "1.16.5", verdict: "PASS", gate: "malware", lat: 312 },
    { eco: "npm", pkg: "freshtelemetry", ver: "1.0.2", verdict: "BLOCK", gate: "supply", lat: 41, http: 423,
      blocked_by: ["supply_chain"], supply: { published_at: ago(6 * 3600), age_hours: 6, min_age_hours: 24 } },
    { eco: "maven", pkg: "com.fasterxml.jackson.core:jackson-databind", ver: "2.12.1", verdict: "BLOCK", gate: "cve", lat: 256, http: 403,
      blocked_by: ["cve"], cves: ["CVE-2020-36518"] },
    { eco: "pypi", pkg: "pillow", ver: "9.5.0", verdict: "BLOCK", gate: "cve", lat: 244, http: 403,
      blocked_by: ["cve"], cves: ["CVE-2023-44271"] },
    { eco: "npm", pkg: "axios", ver: "1.7.2", verdict: "PASS", gate: "malware", lat: 176 },
    { eco: "pypi", pkg: "numpy", ver: "1.26.4", verdict: "CACHE", gate: "cache", lat: 7 },
    { eco: "pypi", pkg: "colourama", ver: "0.4.6", verdict: "BLOCK", gate: "supply", lat: 12, http: 403,
      blocked_by: ["denylist"], note: "Denylisted — typosquat of 'colorama'" },
    { eco: "yarn", pkg: "debug", ver: "4.3.4", verdict: "CACHE", gate: "cache", lat: 4 },
    { eco: "rubygems", pkg: "rails", ver: "7.1.3", verdict: "PASS", gate: "malware", lat: 298 },
    { eco: "pypi", pkg: "pandas", ver: "2.2.2", verdict: "PASS", gate: "malware", lat: 209 },
    { eco: "npm", pkg: "react", ver: "18.3.1", verdict: "CACHE", gate: "cache", lat: 6 },
  ];

  let counter = 1000;
  const requests = SEED.map((r, i) => ({
    ...r,
    request_id: rid(),
    seq: counter--,
    ts: ago(i * 37 + 4),
  }));

  // -------- pool used to generate streamed requests --------
  const STREAM_POOL = [
    { eco: "pypi", pkg: "fastapi", ver: "0.111.0", verdict: "PASS", gate: "malware", lat: 192 },
    { eco: "npm", pkg: "vite", ver: "5.3.1", verdict: "PASS", gate: "malware", lat: 221 },
    { eco: "pypi", pkg: "certifi", ver: "2024.6.2", verdict: "CACHE", gate: "cache", lat: 5 },
    { eco: "yarn", pkg: "typescript", ver: "5.5.2", verdict: "CACHE", gate: "cache", lat: 6 },
    { eco: "rubygems", pkg: "puma", ver: "6.4.2", verdict: "PASS", gate: "malware", lat: 244 },
    { eco: "maven", pkg: "org.springframework:spring-core", ver: "6.1.8", verdict: "PASS", gate: "malware", lat: 281 },
    { eco: "pypi", pkg: "setuptools", ver: "65.5.0", verdict: "BLOCK", gate: "cve", lat: 231, http: 403,
      blocked_by: ["cve"], cves: ["CVE-2022-40897"] },
    { eco: "npm", pkg: "ua-parser-js", ver: "0.7.29", verdict: "BLOCK", gate: "malware", lat: 561, http: 403,
      blocked_by: ["malware"], malware: { engine: "ClamAV 1.3.1", signature: "Unix.Trojan.CoinMiner-9854", action: "ICAP REJECT" } },
    { eco: "pypi", pkg: "requests", ver: "2.19.0", verdict: "BLOCK", gate: "cve", lat: 218, http: 403,
      blocked_by: ["cve"], cves: ["CVE-2023-32681"] },
    { eco: "npm", pkg: "scope-utils", ver: "1.0.0", verdict: "BLOCK", gate: "supply", lat: 38, http: 423,
      blocked_by: ["supply_chain"], supply: { published_at: ago(3 * 3600), age_hours: 3, min_age_hours: 24 } },
    { eco: "pypi", pkg: "flask", ver: "3.0.3", verdict: "PASS", gate: "malware", lat: 203 },
    { eco: "yarn", pkg: "esbuild", ver: "0.21.5", verdict: "CACHE", gate: "cache", lat: 5 },
    { eco: "rubygems", pkg: "devise", ver: "4.9.4", verdict: "PASS", gate: "malware", lat: 267 },
  ];

  // -------- quarantine (held < 24h) --------
  const quarantine = [
    { eco: "npm", pkg: "freshtelemetry", ver: "1.0.2", published_at: ago(6 * 3600), block_until: new Date(now + 18 * 3600 * 1000), request_id: requests[10].request_id },
    { eco: "pypi", pkg: "datayoke", ver: "0.3.1", published_at: ago(2 * 3600 + 1200), block_until: new Date(now + 21.6 * 3600 * 1000) },
    { eco: "npm", pkg: "scope-utils", ver: "1.0.0", published_at: ago(3 * 3600), block_until: new Date(now + 21 * 3600 * 1000) },
    { eco: "maven", pkg: "io.glyph:glyph-runtime", ver: "0.9.0", published_at: ago(11 * 3600), block_until: new Date(now + 13 * 3600 * 1000) },
    { eco: "rubygems", pkg: "swift-mailer", ver: "2.1.0", published_at: ago(0.7 * 3600), block_until: new Date(now + 23.3 * 3600 * 1000) },
  ];

  // -------- policy profile --------
  const policy = {
    profile: "production",
    profiles: ["production", "staging", "sandbox"],
    mode: "enforce", // enforce | dry_run | off
    cve_block_on: "HIGH", // CRITICAL | HIGH | MEDIUM | LOW
    supply_chain: { min_age_hours: 24, mode: "enforce" },
    allowlist: ["pypi/internal-telemetry", "npm/@acme/ui-kit", "pypi/requests@2.31.0", "maven/com.acme:core"],
    denylist: ["pypi/colourama", "npm/crossenv", "pypi/reqursts", "npm/event-stream@3.3.6"],
  };

  // -------- registries + cache --------
  const registries = [
    { eco: "pypi", enabled: true, vol: "184.2k", upstreams: ["https://pypi.org/simple", "https://mirror.acme.internal/pypi"] },
    { eco: "npm", enabled: true, vol: "271.9k", upstreams: ["https://registry.npmjs.org", "https://mirror.acme.internal/npm"] },
    { eco: "maven", enabled: true, vol: "58.4k", upstreams: ["https://repo1.maven.org/maven2", "https://mirror.acme.internal/maven"] },
    { eco: "yarn", enabled: true, vol: "96.1k", upstreams: ["https://registry.yarnpkg.com"] },
    { eco: "rubygems", enabled: false, vol: "0", upstreams: ["https://rubygems.org"] },
  ];

  const cache = {
    used_gb: 41.7,
    max_gb: 64,
    objects: "128,402",
    hit_rate: 0.732,
    evictions_24h: 1843,
    spark: [62, 65, 61, 70, 73, 69, 74, 71, 75, 73, 77, 73],
  };

  const kpis = {
    requests_today: 611742,
    cache_hits: 448021,
    hit_rate: 0.732,
    blocked_total: 3187,
    quarantined_24h: 142,
    cve_blocked: 1894,
    malware_blocked: 38,
    denylisted: 1113,
    requests_spark: [380, 420, 460, 440, 510, 560, 540, 600, 620, 590, 640, 611],
    blocked_spark: [22, 31, 28, 44, 39, 52, 47, 61, 55, 49, 63, 58],
  };

  // per-gate live counts (pass/block)
  const gateStats = {
    cache:   { pass: 448021, block: 0, label: "Cache", sub: "LRU · 73% hit", kanji: null, role: "Served from store" },
    supply:  { pass: 159420, block: 1255, label: "Supply Chain", sub: "≥ 24h hold", kanji: "衛", role: "Maturity & lists" },
    cve:     { pass: 157488, block: 1894, label: "CVE", sub: "osv.dev", kanji: "浄", role: "Vulnerability scan" },
    malware: { pass: 157450, block: 38, label: "Malware", sub: "ClamAV · ICAP", kanji: "浄", role: "Content scan" },
  };

  const scanners = [
    { name: "ClamAV", detail: "icap://clamav.acme.internal:1344", status: "ok", latency: "31ms" },
    { name: "osv.dev", detail: "https://api.osv.dev/v1", status: "ok", latency: "88ms" },
    { name: "Upstream PyPI", detail: "pypi.org", status: "ok", latency: "112ms" },
    { name: "Upstream npm", detail: "registry.npmjs.org", status: "warn", latency: "642ms" },
  ];

  window.JOEI = {
    ECO, CVES, GATES, requests, STREAM_POOL, quarantine, policy,
    registries, cache, kpis, gateStats, scanners, rid, _now: now,
  };
})();
