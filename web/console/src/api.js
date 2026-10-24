/* 浄衛 Jōei :: live API client — populates window.JOEI from the proxy API.
   Events: "joei:data" (full refresh), "joei:event" (one SSE event, detail = row),
   "joei:policy" (policy changed), "joei:connection" (JOEI.connected flipped),
   "joei:auth" (signed in/out, role or must-change-password flag changed). */
(function () {
  "use strict";

  const ECO = {
    pypi:     { id: "pypi",     label: "py",   name: "PyPI" },
    npm:      { id: "npm",      label: "npm",  name: "npm" },
    maven:    { id: "maven",    label: "mvn",  name: "Maven" },
    yarn:     { id: "yarn",     label: "yarn", name: "yarn" },
    rubygems: { id: "rubygems", label: "rb",   name: "RubyGems" },
    go:       { id: "go",       label: "go",   name: "Go" },
    docker:   { id: "docker",   label: "dck",  name: "Docker" },
  };

  const GATES = ["cache", "supply", "cve", "malware"];

  const GATE_META = {
    cache:   { label: "Cache",        sub: "LRU store",    kanji: null, role: "Served from store" },
    supply:  { label: "Supply Chain", sub: "min-age hold", kanji: "衛", role: "Maturity & lists" },
    cve:     { label: "CVE",          sub: "osv.dev",      kanji: "浄", role: "Vulnerability scan" },
    malware: { label: "Malware",      sub: "content scan", kanji: "浄", role: "Content scan" },
  };

  const emptyGateStats = () => {
    const g = {};
    GATES.forEach((k) => { g[k] = { ...GATE_META[k], pass: 0, block: 0 }; });
    return g;
  };

  const J = (window.JOEI = {
    ECO, GATES, CVES: {},
    requests: [],
    quarantine: [],
    daily: [], // per-UTC-day metric rows, oldest-first (for left→right sparklines)
    policy: {
      mode: "off", min_age_hours: 0, cve_block_on: "CRITICAL",
      allowlist_supply: [], allowlist_cve: [], denylist: [], persistence: "database",
    },
    registries: [],
    registriesPending: false, registriesWarnings: [],
    cache: { used_gb: 0, max_gb: 0, stale_gb: 0, stale_after_days: 0, objects: "0", hit_rate: 0, evictions: 0 },
    kpis: {
      requests_total: 0, cache_hits: 0, hit_rate: 0, blocked_total: 0, errors: 0,
      supply_blocked: 0, cve_blocked: 0, malware_blocked: 0, denylisted: 0,
      quarantined: 0, started_at: null,
    },
    gateStats: emptyGateStats(),
    scanners: [],
    connected: false,
    ready: false, // true once the initial load() has settled (either way)
    authenticated: false, // set by the boot probe, login, and any 401
    username: "",
    role: "", // "admin" | "operator" | "" (signed out)
    mustChangePassword: false, // signed in, but only the forced change screen is allowed
  });

  J.isAdmin = () => J.role === "admin";

  function fire(name, detail) {
    window.dispatchEvent(new CustomEvent(name, { detail }));
  }

  function setConnected(v) {
    if (J.connected !== v) { J.connected = v; fire("joei:connection"); }
  }

  // me: { username, role, must_change_password } from /api/auth/me, login or
  // a password change. Signing out clears the whole identity.
  function setAuthenticated(v, me) {
    const next = v
      ? {
          username: (me && me.username) || J.username,
          role: (me && me.role) || J.role,
          mustChangePassword: me ? !!me.must_change_password : J.mustChangePassword,
        }
      : { username: "", role: "", mustChangePassword: false };
    const changed = J.authenticated !== v || J.username !== next.username ||
      J.role !== next.role || J.mustChangePassword !== next.mustChangePassword;
    J.authenticated = v;
    J.username = next.username;
    J.role = next.role;
    J.mustChangePassword = next.mustChangePassword;
    if (changed) fire("joei:auth");
  }

  // Only a signed-in user with no pending password change may call the data
  // endpoints; for anyone else they answer 403 password_change_required.
  const canLoad = () => J.authenticated && !J.mustChangePassword;

  // Raised when a call fails because the session is gone. The app shell shows
  // the login screen for it, rather than the "no connection" banner: an
  // expired session is not a dead proxy.
  class AuthError extends Error {}

  // One refresh at a time: a page load fires several requests at once and they
  // would otherwise race to rotate the refresh cookie, each invalidating the
  // others' new token.
  let refreshing = null;
  function refreshSession() {
    if (!refreshing) {
      refreshing = fetch("/api/auth/refresh", { method: "POST" })
        .then((res) => res.ok)
        .catch(() => false)
        .finally(() => { refreshing = null; });
    }
    return refreshing;
  }

  // Every API call goes through here: on 401 it refreshes once and replays the
  // request, and gives up to the login screen if that fails. A 403
  // password_change_required sends the shell to the forced change screen; a
  // 403 forbidden (role) becomes an error with status 403. A 503 is only
  // treated as "auth not configured" when the body actually says so — other
  // endpoints (e.g. PUT /api/registries) use 503 for their own reasons, and
  // those must reach the caller as a normal error, not a forced sign-out.
  async function authFetch(path, opts) {
    let res = await fetch(path, opts);
    if (res.status === 401 && await refreshSession()) {
      res = await fetch(path, opts);
    }
    if (res.status === 401) {
      disconnectEvents();
      setAuthenticated(false);
      throw new AuthError("unauthorized");
    }
    if (res.status === 403) {
      let body = null;
      try { body = await res.clone().json(); } catch (_) { /* non-JSON error body */ }
      if (body && body.error === "password_change_required") {
        disconnectEvents();
        setAuthenticated(true, { username: J.username, role: J.role, must_change_password: true });
        throw new AuthError("password_change_required");
      }
      if (body && body.error === "forbidden") {
        const err = new Error("You don't have permission for this action");
        err.status = 403;
        throw err;
      }
    }
    if (res.status === 503) {
      let body = null;
      try { body = await res.clone().json(); } catch (_) { /* non-JSON error body */ }
      if (body && body.error === "auth_not_configured") {
        // The stream authenticates by cookie too, and EventSource reconnects
        // on its own: leaving it open would retry /api/events forever behind
        // the login screen.
        disconnectEvents();
        setAuthenticated(false);
        throw new AuthError("auth_not_configured");
      }
    }
    return res;
  }

  async function getJSON(path) {
    const res = await authFetch(path);
    if (!res.ok) throw new Error(path + " -> HTTP " + res.status);
    return res.json();
  }

  /* Convert a wire event into the row shape the screens render. CVE details
     are registered into J.CVES so the drawer can look them up by id. */
  function reviveEvent(e) {
    const r = { ...e, ts: new Date(e.ts) };
    if (r.cves) {
      r.cves = r.cves.map((c) => {
        J.CVES[c.id] = { id: c.id, severity: c.severity, cvss: c.cvss || 0, summary: c.summary || "", source: "osv.dev" };
        return c.id;
      });
    }
    if (r.supply) {
      r.supply.published_at = new Date(r.supply.published_at);
      if (r.supply.block_until) r.supply.block_until = new Date(r.supply.block_until);
      r.supply.age_hours = Math.max(0, Math.round((Date.now() - r.supply.published_at.getTime()) / 3600000));
      r.supply.min_age_hours = J.policy.min_age_hours;
    }
    if (r.malware) r.malware.action = "REJECT";
    if (!r.blocked_by) r.blocked_by = [];
    return r;
  }

  function applyPolicy(p) {
    J.policy = { ...p };
  }

  function applyOverview(o) {
    J.kpis = { ...o.kpis, quarantined: J.quarantine.length, started_at: new Date(o.started_at) };
    const gates = emptyGateStats();
    GATES.forEach((g) => {
      if (o.gates[g]) { gates[g].pass = o.gates[g].pass; gates[g].block = o.gates[g].block; }
    });
    J.gateStats = gates;
    const GB = 1024 ** 3;
    J.cache = {
      used_gb: +(o.cache.size_bytes / GB).toFixed(2),
      max_gb: Math.round(o.cache.max_bytes / GB),
      stale_gb: +((o.cache.stale_bytes || 0) / GB).toFixed(2),
      stale_after_days: o.cache.stale_after_days || 0,
      objects: Number(o.cache.objects).toLocaleString("en-US"),
      hit_rate: o.cache.hit_rate,
      evictions: o.cache.evictions,
    };
    J.scanners = (o.scanners || []).map((s) => ({
      name: s.name, detail: s.detail,
      status: s.status || (s.enabled ? "ok" : "off"),
      latency: s.latency_ms ? `${s.latency_ms}ms` : "",
    }));
  }

  async function load() {
    const [overview, requests, quarantine, pol, registries, daily] = await Promise.all([
      getJSON("/api/overview"),
      getJSON("/api/requests?limit=500"),
      getJSON("/api/quarantine"),
      getJSON("/api/policy"),
      getJSON("/api/registries"),
      getJSON("/api/metrics/daily?days=30"),
    ]);
    applyPolicy(pol);
    // "|| []" guards: one unexpected null must degrade a panel, not fail the
    // whole load() (a rejected load shows the no-connection banner).
    J.quarantine = (quarantine.quarantine || []).map((q) => ({
      ...q, published_at: new Date(q.published_at), block_until: new Date(q.block_until),
    }));
    applyOverview(overview);
    J.requests = (requests.requests || []).map(reviveEvent);
    J.registries = (registries.registries || []).map((r) => ({ eco: r.eco, enabled: r.enabled, upstreams: r.upstreams || [] }));
    J.registriesPending = !!registries.pending_restart;
    J.registriesWarnings = registries.warnings || [];
    // The endpoint returns newest-first; reverse to oldest-first so sparklines
    // read left→right in time order. "|| []" degrades only the sparklines (e.g.
    // when persistence is off and the array is empty), never the whole load().
    J.daily = (daily.daily || []).slice().reverse();
    J.ready = true;
    setConnected(true);
    fire("joei:data");
  }

  // Fetch one page of history filtered by verdict (server-paged). cursor ""
  // starts from the newest matching event. Returns revived rows (ts as Date,
  // cves/supply expanded) plus nextCursor ("" when there are no more pages).
  async function pageRequests({ verdict, cursor, limit }) {
    const params = new URLSearchParams();
    if (verdict) params.set("verdict", verdict);
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));
    const data = await getJSON("/api/requests?" + params.toString());
    return {
      rows: (data.requests || []).map(reviveEvent),
      nextCursor: data.next_cursor || "",
    };
  }

  // Both policy writes answer with the full policy: apply it, or throw an
  // error carrying the server's message, rejected field and status.
  async function applyPolicyResponse(res, what) {
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON error body */ }
    if (!res.ok) {
      const err = new Error((data && data.message) || what + " failed (HTTP " + res.status + ")");
      err.field = data && data.field;
      err.status = res.status;
      throw err;
    }
    applyPolicy(data);
    fire("joei:policy");
    return J.policy;
  }

  // Settings only (admin): absent lists are kept server-side, so a settings
  // save can never drop a list entry someone else just added.
  async function savePolicy(p) {
    const body = { mode: p.mode, min_age_hours: p.min_age_hours, cve_block_on: p.cve_block_on };
    const res = await authFetch("/api/policy", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return applyPolicyResponse(res, "policy update");
  }

  // Add (add=true) or remove one entry of allowlist_supply | allowlist_cve |
  // denylist. The server edits the list atomically.
  async function editList(list, entry, add) {
    const res = await authFetch("/api/policy/lists/" + encodeURIComponent(list), {
      method: add ? "POST" : "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ entry }),
    });
    return applyPolicyResponse(res, "policy list update");
  }

  async function saveRegistries(list) {
    const body = { registries: list.map((r) => ({ eco: r.eco, enabled: r.enabled, upstreams: r.upstreams })) };
    const res = await authFetch("/api/registries", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON error body */ }
    if (!res.ok) {
      const err = new Error((data && data.message) || "registries update failed (HTTP " + res.status + ")");
      err.field = data && data.field;
      throw err;
    }
    J.registries = (data.registries || []).map((r) => ({ eco: r.eco, enabled: r.enabled, upstreams: r.upstreams || [] }));
    J.registriesPending = !!data.pending_restart;
    J.registriesWarnings = data.warnings || [];
    fire("joei:data");
    return { pending: J.registriesPending, warnings: J.registriesWarnings };
  }

  // Purge stale cache entries (idle past the server-side threshold), then
  // refresh so the meter reflects the freed space immediately.
  async function cleanupCache() {
    const res = await authFetch("/api/cache/cleanup", { method: "POST" });
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON error body */ }
    if (!res.ok) throw new Error((data && data.error) || "cache cleanup failed (HTTP " + res.status + ")");
    await load();
    return data; // { removed, freed_bytes }
  }

  // An SSE drop alone does not mean the API is down: EventSource reconnects
  // transparently and every panel is refreshed by the 15s polls regardless.
  // Probe the API once per error burst; only a failing probe shows the
  // "no connection" banner.
  let probing = false;
  function probeConnection() {
    if (probing || !canLoad()) return;
    probing = true;
    load()
      .then(() => connectEvents()) // no-op if a live stream is already open
      .catch(() => setConnected(false))
      .finally(() => { probing = false; });
  }

  let es = null;
  function connectEvents() {
    if (es) return; // already streaming
    es = new EventSource("/api/events");
    es.onmessage = (m) => {
      const r = reviveEvent(JSON.parse(m.data));
      J.requests = [r, ...J.requests].slice(0, 500);
      fire("joei:event", r);
    };
    es.onopen = () => setConnected(true);
    es.onerror = () => {
      // A closed EventSource never retries on its own (the spec fails the
      // connection on a non-200, which is what a lapsed session produces).
      // Drop it so a successful probe can open a fresh one.
      if (es && es.readyState === 2) es = null;
      probeConnection();
    };
  }

  function disconnectEvents() {
    if (es) { es.close(); es = null; }
  }

  // Sign in, then start the session: load the panels and open the stream. The
  // server sets HttpOnly cookies; the access_token in the body is for curl and
  // CI, and the console deliberately never touches it.
  async function login(username, password) {
    let res;
    try {
      res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
    } catch (_) {
      // Never reached the proxy: not a credential problem.
      setConnected(false);
      const err = new Error("unreachable");
      err.status = 0;
      throw err;
    }
    setConnected(true);
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON error body */ }
    if (!res.ok) {
      const err = new Error((data && data.error) || "login_failed");
      err.status = res.status;
      err.retryAfter = retryAfter(res);
      throw err;
    }
    setAuthenticated(true, data);
    await startSession();
    return J.username;
  }

  // Load the panels and open the stream, unless a password change is
  // pending: every data endpoint would answer 403 until it is done.
  async function startSession() {
    if (!canLoad()) return;
    await load().catch(() => setConnected(false));
    connectEvents();
  }

  function retryAfter(res) {
    const n = parseInt(res.headers.get("Retry-After") || "", 10);
    return Number.isFinite(n) ? n : 0;
  }

  // Change the caller's own password. The server re-issues this session's
  // cookies and revokes every other session. Not routed through authFetch: a
  // 401 invalid_credentials here means a wrong current password, not a lapsed
  // session, and must not trigger a refresh-and-replay or a sign-out.
  async function changePassword(current, next) {
    let res;
    try {
      res = await fetch("/api/auth/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current, new: next }),
      });
    } catch (_) {
      setConnected(false);
      const err = new Error("Cannot reach the proxy. Check that it is running, then try again.");
      err.status = 0;
      throw err;
    }
    setConnected(true);
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON error body */ }
    if (!res.ok) {
      const code = data && data.error;
      if (res.status === 401 && code !== "invalid_credentials") {
        disconnectEvents();
        setAuthenticated(false);
        throw new AuthError("unauthorized");
      }
      const err = new Error(
        res.status === 401 ? "Current password is incorrect."
        : res.status === 429 ? "Too many attempts, try again in " + retryAfter(res) + " s"
        : (data && data.message) || "Password change failed (HTTP " + res.status + ")");
      err.status = res.status;
      err.retryAfter = retryAfter(res);
      throw err;
    }
    const wasForced = J.mustChangePassword;
    setAuthenticated(true, data);
    // Leaving the forced screen: run the normal boot path now that the data
    // endpoints accept this session.
    if (wasForced) await startSession();
    return J.username;
  }

  async function logout() {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      disconnectEvents();
      setAuthenticated(false);
      fire("joei:data"); // let the shell re-render against the signed-out state
    }
  }

  // Boot: ask who we are before loading anything. A 401 here is a normal cold
  // start, not an error — it renders the login screen.
  async function boot() {
    try {
      let res = await fetch("/api/auth/me");
      if (res.status === 401 && await refreshSession()) {
        res = await fetch("/api/auth/me");
      }
      // Any HTTP response — 200, 401, 503 — proves the proxy is reachable. Only
      // a thrown fetch (handled in the catch below) means it is not.
      setConnected(true);
      if (!res.ok) {
        setAuthenticated(false);
        return;
      }
      const me = await res.json();
      setAuthenticated(true, me);
      if (canLoad()) {
        await load();
        connectEvents();
      }
    } catch (_) {
      // A throw here means the request never reached the proxy — that is a
      // connectivity failure, not a lapsed session.
      setConnected(false);
    } finally {
      J.ready = true;
      fire("joei:data");
    }
  }

  J.load = load;
  J.savePolicy = savePolicy;
  J.editList = editList;
  J.changePassword = changePassword;
  J.pageRequests = pageRequests;
  J.saveRegistries = saveRegistries;
  J.cleanupCache = cleanupCache;
  J.login = login;
  J.logout = logout;

  boot();
  // Counters and quarantine are not pushed over SSE — refresh periodically.
  setInterval(() => {
    if (!document.hidden && canLoad()) load().catch(() => { if (canLoad()) setConnected(false); });
  }, 15000);
  // Returning to a backgrounded tab: timers were paused and the SSE socket may
  // have died silently — refresh now instead of waiting for the next poll.
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && canLoad()) load().catch(() => { if (canLoad()) setConnected(false); });
  });
})();
