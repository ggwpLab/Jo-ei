# Console–Backend Integration Design

**Date:** 2026-06-11
**Status:** Approved
**Scope:** Wire the embedded admin console (`web/console/`) to live proxy state, replacing its client-side mock data.

## Goals

- The console shows real proxy state: request feed, KPIs, per-gate counters, quarantine, cache stats, registries, and the effective policy.
- The policy editor works: changes to mode, CVE threshold, and allow/deny lists apply immediately without restart.
- The proxy data path is never slowed or broken by telemetry.

## Decisions (settled during brainstorming)

| Question | Decision |
|---|---|
| Phase scope | Read-only telemetry + working policy editor. Registry/cache management is a later phase. |
| Event/stat storage | In-memory only: ring buffer + atomic counters. History is lost on restart; acceptable for a live console. |
| Live updates | Server-Sent Events (`/api/events`), browser `EventSource` with built-in reconnect. No new dependencies. |
| Policy persistence | Runtime-only. Edits live until restart, then the YAML config wins again. The console must make this visible (e.g., a "runtime override, resets on restart" note). |
| Authorization | None this phase. The console and API are open to anyone who can reach the port. Documented as a known risk in README; auth is a later phase. |
| Capture mechanism | Approach A: explicit optional `Recorder` interface instrumented at the handler's decision points. (Rejected: middleware response-inference — lossy/brittle; zerolog hook — couples telemetry to log message format.) |

## Architecture

```
internal/proxy/Handler ──emit──▶ internal/telemetry.Store ◀──read── internal/console (API)
        │                              │  ring buffer N=500            │ GET /api/overview
        │ Recorder (optional,          │  atomic counters              │ GET /api/requests
        │ nil = no-op)                 │  quarantine (derived)         │ GET /api/quarantine
        │                              │  SSE broadcaster              │ GET/PUT /api/policy
        ▼                              ▼                               │ GET /api/registries
   policy.Engine / supplychain.Filter behind atomic swap               │ GET /api/events (SSE)
                                                                       ▼
                                                          web/console SPA (same go:embed)
```

### New package: `internal/telemetry`

- **`Event`** — one record per intercepted request outcome: `request_id`, `ecosystem`, `package`, `version`, `verdict` (`PASS | CACHE | BLOCK | ERROR`), `gate` (`cache | supply | cve | malware`), latency, HTTP status, and block details (CVE findings, malware engine+signature, supply-chain `published_at`/`block_until`, denylist reason). `ERROR` events set `gate` to the stage that failed (e.g., upstream metadata fetch → `supply`, CVE scanner error → `cve`). Field semantics mirror the mock objects in `web/console/data.js` so the JSX screens change minimally.
- **`Store`** — ring buffer of the last 500 events + per-gate pass/block counters + KPI totals since process start, guarded by an `RWMutex`. `Record` never returns an error and never blocks beyond the mutex.
- **`Broadcaster`** — fans out each new event to SSE subscribers over buffered channels; a subscriber whose channel is full is dropped (slow client loses events, proxy never stalls).

### New package: `internal/console`

HTTP API over the Store plus references to runtime state (mutable policy, registry config, cache stats). Kept separate so `web` stays purely static assets.

| Endpoint | Method | Returns |
|---|---|---|
| `/api/overview` | GET | KPIs, per-gate counters, cache stats, scanner configuration (which engines are enabled — no live health probes) |
| `/api/requests` | GET | recent events from the buffer (`?limit=`, newest first) |
| `/api/events` | GET | SSE stream of new events |
| `/api/quarantine` | GET | active quarantine entries |
| `/api/policy` | GET / PUT | effective policy; PUT validates and atomically applies |
| `/api/registries` | GET | configured registries: ecosystem, upstreams, enabled |

### Mutable policy (atomic swap)

`policy.Engine` and `supplychain.Filter` are immutable, built once at boot. A new wrapper type holds the current `*policy.Engine`, `*supplychain.Filter`, and their source parameters behind an `atomic.Pointer` snapshot. The handler already depends on the `PolicyDecider` / `SCFilter` interfaces, so the wrapper slots in without handler changes. `PUT /api/policy` validates the input, builds a fresh Engine/Filter pair, and swaps the pointer — there is no partial application.

**PUT /api/policy body:** `mode` (enforce/dry_run/off, supply chain), `min_age_hours` (≥ 0), `cve_block_on` (CRITICAL/HIGH/MEDIUM/LOW), `allowlist[]`, `denylist[]` (entries `eco/name[@version]`). Invalid body → 400 naming the bad field; policy unchanged. Response echoes the applied policy.

### Changes to existing code

- `proxy.HandlerConfig` gains an optional `Recorder` field (interface declared in `proxy`, like `ArtifactCache`, to avoid import cycles; nil = no-op). `ServeHTTP` records exactly one event per intercepted request at each outcome: cache hit, cache fail-closed, supply block, dry-run pass, CVE block, malware block, scanner/upstream errors, successful serve. Request start time is captured at the top for latency.
- `cmd/jo-ei/main.go` — construct Store + console API, mount `/api/` on the root mux next to `/console/`.
- `internal/cache` — expose a stats snapshot (object count, used/max bytes, hit rate); add it if the index does not already provide one.

## Data flow notes

- **Quarantine is derived, not stored:** supply-chain block events with `block_until` in the future, deduplicated by `eco/pkg@ver`, expired entries filtered at read time.
- **Counters are process-lifetime**, not calendar-day. The UI labels them accordingly ("since start", uptime window). Mock-only visuals with no real data source (request sparklines per day, scanner latency badges, cache volume history) are either fed honestly or removed from the screens.

## Frontend changes

- Replace `web/console/data.js` with `api.js`: same `window.JOEI`-shaped state, but populated by `fetch` of the REST endpoints on load and an `EventSource('/api/events')` subscription for live updates.
- JSX screens: minimal edits — field renames, drop `STREAM_POOL` simulation and mock-only widgets.
- Policy editor: submit via `PUT /api/policy`, render validation errors, show the "runtime-only, resets on restart" notice.
- React/Babel still load from CDN — replacing that with vendored assets is a separate later phase.

## Error handling

- Telemetry can never fail a proxy request: `Record` returns nothing; broadcaster drops slow SSE clients.
- API unreachable from the SPA → visible "no connection to proxy" banner; `EventSource` auto-reconnects.
- Empty buffer after restart renders as an honest empty state, not placeholder data.

## Testing

- `internal/telemetry` unit tests: ring-buffer overflow and ordering, counters, concurrent record/read under `-race`, broadcaster subscribe/unsubscribe/slow-client drop.
- `internal/console` httptest: every endpoint; PUT policy validation (valid + invalid bodies); SSE delivers an event after `Record`.
- Atomic policy swap: after PUT, new requests are evaluated under the new policy, concurrently with reads.
- Integration: handler with a Recorder + mock adapter — one request per verdict path, assert the recorded event's verdict/gate (modeled on the existing integration tests).
- Frontend: manual verification via docker-compose; no SPA test harness exists in the repo and this phase does not introduce one.

## Out of scope (later phases)

- Registry enable/disable and cache invalidation from the console
- Console/API authentication
- Persistent event history and calendar-day metrics
- Vendoring React/Babel (removing the CDN dependency)
- Live scanner health probes (ClamAV/osv.dev latency)
