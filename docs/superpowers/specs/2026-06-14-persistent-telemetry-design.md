# Persistent Telemetry (SQLite) — Design

**Date:** 2026-06-14
**Status:** Approved
**Stage:** Production-readiness (task 4 of 4)

## Problem

Telemetry is process-lifetime only. `internal/telemetry.Store` keeps a 500-event
ring buffer plus aggregate counters in memory; a restart wipes the request feed,
the lifetime KPIs, and the derived quarantine list. There is also no per-day
breakdown — only cumulative totals since process start.

## Goal

Persist telemetry across restarts using an embedded database, and add
per-calendar-day metrics:

- **Event history** survives restart (powers the console request feed and the
  derived quarantine list).
- **Lifetime counters** survive restart (the overview KPIs).
- **Per-calendar-day metrics** — daily buckets exposed via a new API.

The database is introduced as a **general, extensible persistence layer**. This
cycle uses it for telemetry only; persisting the runtime policy (so console
edits survive restart) is a deliberate follow-up cycle on the same database.

Non-goals this cycle (YAGNI): runtime-policy persistence, any console UI for
daily metrics (API only), historical charts, multi-node/shared databases.

## Database choice

Embedded **SQLite via `modernc.org/sqlite`** — a pure-Go driver (no cgo). This
matters: the project must build without cgo on Windows, and CI enables cgo only
for `-race`; a cgo driver (mattn/go-sqlite3) would break the no-cgo build. The
pure-Go driver works under `-race`. Registered driver name: `sqlite`.

WAL mode (`PRAGMA journal_mode=WAL`) so the console's reads never block the
writer, plus a `busy_timeout` to tolerate brief contention.

## Architecture — two layers

### Layer 1: `internal/storage` (generic foundation)

Owns the `*sql.DB`. Reusable for future runtime-settings persistence.

```go
package storage

type DB struct { /* wraps *sql.DB */ }

func Open(path string) (*DB, error) // opens sqlite, sets WAL + busy_timeout, runs Migrate
func (db *DB) SQL() *sql.DB
func (db *DB) Close() error
```

- Migrations are versioned via `PRAGMA user_version`: an ordered list of
  migration steps; `Open` applies any whose index exceeds the current
  `user_version`, then bumps it. Idempotent and forward-only.
- `Open` creates the parent directory if missing.

### Layer 2: telemetry persistence (`internal/telemetry`)

The existing in-memory `Store` stays the **authoritative, fast read/write model**
— the console keeps reading from it unchanged (zero regression). Persistence is
added behind an interface so the in-memory-only path (and all current tests)
still work when no database is configured.

```go
// Repo persists and restores telemetry. A nil Repo means in-memory only.
type Repo interface {
	LoadState() (State, error)            // called once at startup
	AppendEvents(evs []proxy.Event) error // async, batched
	Flush(counters Snapshot, daily []DailyMetric) error // periodic + shutdown
	PruneOlderThan(events, daily time.Time) error
	DailyMetrics(days int) ([]DailyMetric, error) // for the API
}
```

- `State` carries the loaded lifetime counters, the recent events (to seed the
  ring buffer), and the existing daily rows.
- A SQLite implementation (`sqliteRepo`, constructed from a `*storage.DB`) lives
  in the telemetry package.
- The `Store` gains an optional `Repo` and a background writer. Construction:
  `NewStore(capacity)` (in-memory, unchanged) and a new
  `NewPersistentStore(capacity, repo)` (or an option) that seeds from
  `repo.LoadState()` and starts the writer.

## Data model (3 tables)

**`events`** — recent events; powers the feed and quarantine derivation.
Indexed/queryable columns for filtering + a JSON blob for full fidelity (CVE
findings, malware details) so the schema stays narrow and round-trips exactly:

| column | type | note |
|--------|------|------|
| `id` | INTEGER PK AUTOINCREMENT | insertion order |
| `ts` | INTEGER (unix ns) | event time; index |
| `request_id` | TEXT | |
| `ecosystem`,`package`,`version` | TEXT | quarantine key |
| `verdict`,`gate`,`reason` | TEXT | |
| `http_status` | INTEGER | |
| `published_at`,`block_until` | INTEGER (unix ns, 0 if zero) | quarantine filter |
| `detail_json` | TEXT | full `proxy.Event` JSON (BlockedBy, CVEs, Malware*) |

Append-only; pruned by retention (default: events older than ~30 days).

**`daily_metrics`** — one row per UTC day; upserted on each Record/flush.

`day TEXT PK` (`YYYY-MM-DD`, UTC), then integer columns mirroring the Snapshot
counters: `requests`, `cache_hits`, `blocked`, `errors`, `supply_blocked`,
`cve_blocked`, `malware_blocked`, `denylisted`, and per-gate
`gate_<name>_pass` / `gate_<name>_block` for cache/supply/cve/malware. Retained
long (~365 days).

**`counters`** — a single row (`id=1`) holding cumulative lifetime totals (same
columns as the Snapshot aggregates). Never pruned; survives restart.

> **Semantics note:** `Snapshot.StartedAt` stays the **process** start time (so
> "uptime" remains process uptime), while the counters are **cumulative across
> restarts**. The overview already shows uptime and totals separately; this is a
> deliberate, documented choice.

## Data flow

- **Startup:** `storage.Open(path)` → migrate → `repo.LoadState()` seeds the
  in-memory Store (counters, today's+recent daily rows, last N events into the
  ring buffer).
- **Record() (hot path):** updates in-memory counters + today's daily bucket
  under the Store's existing mutex, then enqueues the event on a buffered
  channel. **Never blocks the proxy:** if the channel is full, the event is
  still counted in memory but its persistence is skipped (best-effort
  durability). A single writer goroutine batches `events` inserts.
- **Periodically (default 10s) + on graceful shutdown:** `Flush` writes the
  `counters` row and the current day's `daily_metrics` row, then prunes by
  retention.

## New API

`GET /api/metrics/daily?days=N` — returns the last `N` UTC days (default 30,
clamped to a sane max, e.g. 365) from `daily_metrics`, newest first, as JSON.
Mounted behind the existing console auth like the other `/api/` routes. No UI
change this cycle.

## Configuration

New `database:` block:

```yaml
database:
  path: "/var/lib/jo-ei/jo-ei.db"   # empty disables persistence (in-memory only)
  # event_retention_days: 30
  # daily_retention_days: 365
```

Empty/omitted `path` ⇒ persistence disabled (in-memory only). Retention fields
default when zero/omitted. Negative retention values are rejected by config
validation.

## Error handling (fail-safe)

Telemetry **must never take down the proxy.** If the database fails to open or
migrate at startup, log a WARN and run in-memory-only (no persistence); the
proxy serves normally. This contrasts with the fail-closed posture of auth and
scanners, and is appropriate because telemetry is observational, not on the
request-security path. A failed async write or flush logs at WARN and is
retried on the next cycle; it never propagates to `Record`.

## Testing

- **`storage`**: migrations apply from a fresh DB and are idempotent on reopen;
  `user_version` bumped correctly; WAL enabled; parent dir created.
- **`telemetry`**: `sqliteRepo` round-trip (Flush→LoadState restores counters,
  daily rows, events); Store seeded from a Repo reproduces Snapshot/Recent/
  Quarantine; async writer batches and Flush persists; daily bucketing across a
  UTC midnight boundary using an injectable clock; `Repo == nil` keeps the
  current in-memory behavior (existing tests unchanged).
- **`console`**: `GET /api/metrics/daily` returns rows and honors `days`.
- **`integration`**: restart simulation — record events, close the store,
  reopen against the same DB file, and assert counters, daily metrics, recent
  events, and quarantine are restored.

## Risks / notes

- **Hot-path latency**: mitigated by in-memory-authoritative writes + async
  event persistence; the request path does no synchronous DB I/O.
- **Crash window**: counters/daily are flushed periodically, so an ungraceful
  crash loses at most the last interval's aggregate deltas and any unwritten
  queued events — acceptable for observational telemetry.
- **Driver footprint**: `modernc.org/sqlite` is a sizable module but pure-Go and
  cgo-free; it is the standard choice for embedded SQLite in cgo-free Go builds.
- **Concurrency**: WAL + `busy_timeout` + a single writer goroutine keep writes
  serialized; console reads use short-lived queries.
- **Forward design**: the `storage` layer and migration mechanism are built to
  host additional tables (e.g. a future `runtime_policy`) without rework.
