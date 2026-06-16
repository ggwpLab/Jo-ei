# Telemetry: SQLite as the single source of truth

**Date:** 2026-06-16
**Status:** Approved
**Supersedes the persistence model in:** [2026-06-14-persistent-telemetry-design.md](2026-06-14-persistent-telemetry-design.md)

## Problem

Telemetry state currently lives in two places at once: an in-memory ring buffer
plus aggregate counters (lifetime + per-day), and a SQLite backing store that a
background goroutine flushes to every 10 seconds. This hybrid has two concrete
problems:

1. **Data loss on restart/crash.** Events recorded since the last flush — up to
   ~10 seconds of traffic, or the entire unflushed batch on an unclean exit — are
   lost because durability waits on a timer rather than happening at record time.
2. **Hybrid fragility.** Two state models must be kept consistent through
   `seed` (load), `flush` (write), and `evictOldDaily` (memory bounding). The
   counters shown by `Snapshot()` (live, in-memory) and `DailyMetrics()` (read
   from SQLite, lagging by up to one flush interval) can disagree. There is no
   single source of truth.

## Goal

Make **SQLite the only place telemetry state lives**. Every event is durably
recorded at the moment it happens. Reads come straight from SQLite. The
in-memory ring buffer, the in-memory aggregates, and all of the
seed/flush/evict/writer machinery are deleted.

## Non-goals

- Changing the wire shape of any console API response.
- Changing the live SSE feed (`Broadcaster`) — it is independent of the Store
  and stays as-is.
- Adding new metrics or gates.

## Approach

`Store` becomes a thin façade over a `Repo`; all metric state is in SQLite.

### Write path — `Record(ev)` is synchronous

`Record` is on the proxy hot path. Today it is a non-blocking channel send; that
non-blocking-ness is exactly what creates the loss window. We accept a synchronous
write: one local WAL transaction per proxied request. Because `storage.Open` sets
`SetMaxOpenConns(1)`, all DB access already serializes through a single
connection, so synchronous writes queue on that connection rather than producing
`SQLITE_BUSY` contention. The added latency (~sub-millisecond local WAL commit) is
negligible next to the upstream fetch and scanning each request already performs.

`Record(ev)` performs, in one transaction:

1. `INSERT` the event row (same columns as today: queryable fields + `detail_json`
   for exact round-tripping).
2. Read the `counters` row (id=1) into an aggregate (empty if no row yet), add the
   one-event delta, and upsert the full row back.
3. Read today's `daily_metrics` row into an aggregate (empty if no row yet), add
   the **same** delta, and upsert the full row back.

The delta is computed once with the existing gate-pipeline logic
(`aggregate.record`, `gatePipeline`, `pipelineIndex`) applied to a fresh empty
aggregate. That domain logic is unchanged — it just moves from "mutate the live
in-memory aggregate" to "compute a delta, then add it to the persisted row."

On any write error `Record` logs a warning and returns. It never blocks
indefinitely and never panics the request goroutine. At most the single in-flight
transaction's event is lost (not a 10-second window).

### Read path — everything queries SQLite

- `Snapshot()` → `SELECT` from `counters`; `StartedAt` is stamped with the process
  start time. Process start is uptime, not metric state, and is the one value
  that legitimately stays in memory. A missing row yields a zero snapshot with
  empty gates.
- `Recent(limit)` → `SELECT detail_json FROM events ORDER BY ts DESC, id DESC
  LIMIT limit`. `limit <= 0` means "all" (bounded in practice by event retention).
- `Quarantine(now)` → `SELECT` block-verdict, supply-gate events newest-first,
  dedupe by `eco/pkg@ver` in Go, then drop entries whose `block_until` is not
  after `now`. Deduplication happens **before** the expiry filter so the newest
  record for a package decides whether it is held — identical semantics to the
  current buffer-derived implementation.
- `DailyMetrics(days)` → unchanged (already reads SQLite).

### Repo interface

```go
type Repo interface {
    RecordEvent(ev proxy.Event) error            // insert + increment counters + increment today
    Snapshot(started time.Time) (Snapshot, error)
    Recent(limit int) ([]proxy.Event, error)
    Quarantine(now time.Time) ([]proxy.Event, error)
    DailyMetrics(days int) ([]DailyMetric, error)
    Prune() error
}
```

Removed from the old interface: `LoadState`, `AppendEvents`, `Flush`. The `State`
type and the seed logic are deleted.

The façade keeps its current method signatures so **no console call sites change**:
`Snapshot()`, `Recent()`, and `Quarantine()` stay non-erroring (the façade logs a
read error and returns a best-effort/empty result — the overview must not 500 on a
telemetry read hiccup), while `DailyMetrics()` keeps returning an error (the
console already handles it).

### Store façade

```go
func New(repo Repo, logger zerolog.Logger) *Store
```

`Store` holds `repo`, `logger`, `started time.Time`, and the prune ticker's
lifecycle (`stop`, `wg`, `closeOnce`). The old in-memory `NewStore(capacity)` and
`NewPersistentStore(...)` constructors are removed.

### Pruning

A lightweight background ticker on `Store` calls `repo.Prune()` once per hour
(retention windows are measured in days, so hourly is ample). `Close()` stops the
ticker and waits for it to exit. Retention values and the `Prune` SQL are
unchanged.

### Schema

The `events`, `daily_metrics`, and `counters` tables are unchanged. One additive,
forward-only migration is appended to `telemetryMigrations`:

```sql
CREATE INDEX IF NOT EXISTS idx_events_verdict_gate ON events(verdict, gate);
```

This keeps `Quarantine`'s `verdict = 'BLOCK' AND gate = 'supply'` filter cheap.
Existing databases pick it up via the per-component migration version bump.

### Fail-fast, no in-memory fallback

There is no in-memory Store anymore, so there is nothing to fall back to.

- `config.Validate()` rejects an **empty `database.path`** with a clear error.
- `cmd/jo-ei` `buildTelemetryStore` returns `(*telemetry.Store, error)`; if the DB
  cannot be opened, the schema cannot be applied, or the repo cannot be built,
  **startup fails** with that error rather than silently degrading.
- `config.yaml`'s `database` comment is updated: the path is now required, not an
  optional "in-memory by default" setting.

## Error handling

| Failure | Behavior |
|---|---|
| `Record` transaction fails | Log warning; drop that one event; request unaffected. |
| `Snapshot`/`Recent`/`Quarantine` read fails | Façade logs; returns zero/empty result (no HTTP 500 from a read hiccup). |
| `DailyMetrics` read fails | Error propagates; console returns `metrics_unavailable` (unchanged). |
| `Prune` fails | Log warning; retry next tick. |
| DB unavailable at startup | Startup fails (fail-fast). |

## Testing

- **Unit (`internal/telemetry`):** construct a `Store` from a temp-file (or
  `:memory:`) SQLite repo via a small test helper. Cover: counter increments and
  gate-pipeline tallies via `Record` → `Snapshot`; `Recent` ordering and limit;
  `Quarantine` dedupe-before-expiry; `DailyMetrics` bucketing across UTC days;
  durability (record, reopen the same file, state intact — replaces the old
  seed/flush round-trip test); prune removes rows past retention.
- **Integration (`integration/telemetry_persistence_test.go`):** keep the
  across-restart assertions, now backed by per-event durability rather than a
  final flush. No `Close()`-to-flush dependency.
- **Console/other integration tests** that built an in-memory `NewStore(n)` switch
  to the DB-backed test helper.

## Files touched

- `internal/telemetry/store.go` — façade + prune ticker; ring buffer/aggregates/
  writer/flush/seed/evict removed.
- `internal/telemetry/aggregate.go` *(new)* — `aggregate`, `record`, gate pipeline,
  `add`, and Snapshot/DailyMetric ↔ aggregate conversions split out of `store.go`.
- `internal/telemetry/repo.go` — new `Repo` interface; `State` removed.
- `internal/telemetry/sqlite.go` — `RecordEvent`, `Snapshot`, `Recent`,
  `Quarantine`; new index migration; `LoadState`/`AppendEvents`/`Flush` removed.
- `internal/telemetry/*_test.go` — rewritten against the new API.
- `internal/config/config.go` — require `database.path`.
- `cmd/jo-ei/main.go` — `buildTelemetryStore` returns an error; startup fails on
  DB error.
- `config.yaml` — `database` comment reflects that the path is required.
- Integration/console tests — DB-backed Store construction.
