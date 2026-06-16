# Telemetry SQLite-Only Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make SQLite the single source of truth for telemetry — delete the in-memory ring buffer and aggregates, record every event durably and synchronously, and fail fast when no database is configured.

**Architecture:** `telemetry.Store` becomes a thin façade over a `Repo`. `Record` runs one synchronous SQLite transaction (insert event + increment `counters` + increment today's `daily_metrics`). All reads (`Snapshot`/`Recent`/`Quarantine`/`DailyMetrics`) query SQLite. A background ticker prunes hourly. No in-memory fallback: empty `database.path` is a config error and a DB open failure aborts startup.

**Tech Stack:** Go, `modernc.org/sqlite` (pure-Go, no cgo), `database/sql` with `SetMaxOpenConns(1)` (writes serialize on one connection), `github.com/rs/zerolog`, `testify`.

**Design reference:** `docs/superpowers/specs/2026-06-16-telemetry-sqlite-only-design.md`

**Reviewer context (read once before starting):**
- `Record` is on the proxy hot path via `telemetry.Hub` (`cmd/jo-ei/main.go:133`). Synchronous write is intentional and approved.
- `storage.Open` sets `SetMaxOpenConns(1)`, so concurrent `Record`/read calls queue on one connection — there is no `SQLITE_BUSY` contention to handle.
- The live SSE feed (`Broadcaster`) is independent of the Store and is **not** touched by this plan.
- Each commit must leave `go build ./...` and `go test ./...` green. Task 2 is an atomic interface change: the telemetry core and **every caller** are updated in one commit because removing the old constructors breaks all callers simultaneously.

---

## Task 1: Extract aggregate logic into its own file

Pure refactor: move the in-memory `aggregate` type and its helpers out of `store.go` into `aggregate.go`, and add an `add` method. No behavior change; all existing tests stay green. This isolates the counter math that Task 2 reuses inside the SQLite write path.

**Files:**
- Create: `internal/telemetry/aggregate.go`
- Modify: `internal/telemetry/store.go` (remove the moved code)

- [ ] **Step 1: Create `internal/telemetry/aggregate.go`**

Move these existing symbols out of `store.go` verbatim into the new file: `aggregate`, `newAggregate`, `(*aggregate).record`, `gatesCopy`, `(*aggregate).snapshot`, `(*aggregate).dailyMetric`, `gatesToPtr`, `aggregateFromSnapshot`, `aggregateFromDaily`, `dayKey`, `gatePipeline`, `pipelineIndex`. Then add the new `add` method. Final file:

```go
package telemetry

import (
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// aggregate holds the counter tallies shared by lifetime totals and per-day
// buckets. Not safe for concurrent use.
type aggregate struct {
	requests, cacheHits, blocked, errors                  uint64
	supplyBlocked, cveBlocked, malwareBlocked, denylisted uint64
	gates                                                 map[string]*GateCounts
}

func newAggregate() *aggregate {
	return &aggregate{gates: map[string]*GateCounts{
		proxy.GateCache:   {},
		proxy.GateSupply:  {},
		proxy.GateCVE:     {},
		proxy.GateMalware: {},
	}}
}

// gatePipeline is the order an artifact clears the scanning gates. A verdict
// at gate i implies a pass at every earlier pipeline gate.
var gatePipeline = []string{proxy.GateSupply, proxy.GateCVE, proxy.GateMalware}

func pipelineIndex(gate string) int {
	for i, g := range gatePipeline {
		if g == gate {
			return i
		}
	}
	return -1
}

// record applies one event to the tallies.
func (a *aggregate) record(ev proxy.Event) {
	a.requests++
	switch ev.Verdict {
	case proxy.VerdictCache:
		a.cacheHits++
		a.gates[proxy.GateCache].Pass++
	case proxy.VerdictPass:
		idx := pipelineIndex(ev.Gate)
		if idx < 0 {
			idx = len(gatePipeline) - 1
		}
		for _, g := range gatePipeline[:idx+1] {
			a.gates[g].Pass++
		}
	case proxy.VerdictBlock:
		a.blocked++
		if c, ok := a.gates[ev.Gate]; ok {
			c.Block++
		}
		// Pass++ for pipeline gates cleared before the blocking gate.
		// idx > 0 also correctly skips non-pipeline gates (cache → idx -1):
		// a cache-gate block implies no pipeline gate was reached at all.
		if idx := pipelineIndex(ev.Gate); idx > 0 {
			for _, g := range gatePipeline[:idx] {
				a.gates[g].Pass++
			}
		}
		switch {
		case ev.Reason == proxy.ReasonDenylisted:
			a.denylisted++
		case ev.Gate == proxy.GateSupply:
			a.supplyBlocked++
		case ev.Gate == proxy.GateCVE:
			a.cveBlocked++
		case ev.Gate == proxy.GateMalware:
			a.malwareBlocked++
		}
	case proxy.VerdictError:
		// Errors are infrastructure failures, not gate verdicts: they count
		// toward Errors only and intentionally leave gate tallies untouched.
		a.errors++
	}
}

// add merges o's tallies into a (a += o).
func (a *aggregate) add(o *aggregate) {
	a.requests += o.requests
	a.cacheHits += o.cacheHits
	a.blocked += o.blocked
	a.errors += o.errors
	a.supplyBlocked += o.supplyBlocked
	a.cveBlocked += o.cveBlocked
	a.malwareBlocked += o.malwareBlocked
	a.denylisted += o.denylisted
	for k, v := range o.gates {
		c, ok := a.gates[k]
		if !ok {
			c = &GateCounts{}
			a.gates[k] = c
		}
		c.Pass += v.Pass
		c.Block += v.Block
	}
}

func gatesCopy(src map[string]*GateCounts) map[string]GateCounts {
	out := make(map[string]GateCounts, len(src))
	for k, v := range src {
		out[k] = *v
	}
	return out
}

func (a *aggregate) snapshot(started time.Time) Snapshot {
	return Snapshot{
		StartedAt:      started,
		Requests:       a.requests,
		CacheHits:      a.cacheHits,
		Blocked:        a.blocked,
		Errors:         a.errors,
		SupplyBlocked:  a.supplyBlocked,
		CVEBlocked:     a.cveBlocked,
		MalwareBlocked: a.malwareBlocked,
		Denylisted:     a.denylisted,
		Gates:          gatesCopy(a.gates),
	}
}

func (a *aggregate) dailyMetric(day string) DailyMetric {
	return DailyMetric{
		Day:            day,
		Requests:       a.requests,
		CacheHits:      a.cacheHits,
		Blocked:        a.blocked,
		Errors:         a.errors,
		SupplyBlocked:  a.supplyBlocked,
		CVEBlocked:     a.cveBlocked,
		MalwareBlocked: a.malwareBlocked,
		Denylisted:     a.denylisted,
		Gates:          gatesCopy(a.gates),
	}
}

func gatesToPtr(src map[string]GateCounts) map[string]*GateCounts {
	out := map[string]*GateCounts{
		proxy.GateCache: {}, proxy.GateSupply: {}, proxy.GateCVE: {}, proxy.GateMalware: {},
	}
	for k, v := range src {
		vv := v
		out[k] = &vv
	}
	return out
}

func aggregateFromSnapshot(s Snapshot) *aggregate {
	return &aggregate{
		requests: s.Requests, cacheHits: s.CacheHits, blocked: s.Blocked, errors: s.Errors,
		supplyBlocked: s.SupplyBlocked, cveBlocked: s.CVEBlocked,
		malwareBlocked: s.MalwareBlocked, denylisted: s.Denylisted,
		gates: gatesToPtr(s.Gates),
	}
}

func aggregateFromDaily(d DailyMetric) *aggregate {
	return &aggregate{
		requests: d.Requests, cacheHits: d.CacheHits, blocked: d.Blocked, errors: d.Errors,
		supplyBlocked: d.SupplyBlocked, cveBlocked: d.CVEBlocked,
		malwareBlocked: d.MalwareBlocked, denylisted: d.Denylisted,
		gates: gatesToPtr(d.Gates),
	}
}

// dayKey is the UTC calendar-day bucket for an event. A zero event time falls
// back to the current time so malformed events still bucket somewhere.
func dayKey(ev proxy.Event) string {
	t := ev.Time
	if t.IsZero() {
		t = time.Now()
	}
	return t.UTC().Format("2006-01-02")
}
```

- [ ] **Step 2: Delete the moved symbols from `store.go`**

Remove from `internal/telemetry/store.go` the now-duplicated definitions listed in Step 1 (`aggregate`, `newAggregate`, `record`, `gatesCopy`, `snapshot`, `dailyMetric`, `gatesToPtr`, `aggregateFromSnapshot`, `aggregateFromDaily`, `dayKey`, `gatePipeline`, `pipelineIndex`). Leave everything else in `store.go` untouched. The `time` and `proxy` imports stay (still used elsewhere in `store.go`).

- [ ] **Step 3: Verify it compiles and all tests pass**

Run: `go build ./... && go test ./internal/telemetry/...`
Expected: PASS (pure move — behavior unchanged).

- [ ] **Step 4: Commit**

```bash
git add internal/telemetry/aggregate.go internal/telemetry/store.go
git commit -m "refactor(telemetry): extract aggregate into its own file"
```

---

## Task 2: Rewrite the telemetry core to be SQLite-only

Atomic interface change. Replace the `Repo` interface, rewrite the SQLite repo, rewrite the `Store` façade, and update every caller and test in one commit so the build stays green.

**Files:**
- Modify: `internal/telemetry/repo.go` (new interface; delete `State`)
- Modify: `internal/telemetry/sqlite.go` (new methods + index migration; delete old ones)
- Modify: `internal/telemetry/store.go` (façade; delete ring buffer / writer / seed / old constructors)
- Modify: `internal/telemetry/store_test.go` (rewrite against new API)
- Modify: `internal/telemetry/sqlite_test.go` (rewrite against new API)
- Modify: `internal/telemetry/broadcaster_test.go` (use DB-backed Store helper)
- Modify: `internal/console/server_test.go` (use DB-backed Store helper)
- Modify: `integration/console_test.go` (add shared helper + use it)
- Modify: `integration/scanner_health_test.go` (use helper)
- Modify: `integration/console_auth_test.go` (use helper)
- Modify: `integration/telemetry_persistence_test.go` (rewrite against new API)

- [ ] **Step 1: Replace `internal/telemetry/repo.go` entirely**

```go
package telemetry

import (
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// Repo persists and retrieves telemetry. SQLite is the single source of truth;
// there is no in-memory implementation. Implementations are safe for concurrent
// use (calls serialize on a single SQLite connection).
type Repo interface {
	// RecordEvent durably persists one event and applies its tallies to the
	// cumulative counters and the event's UTC-day metrics row, atomically.
	RecordEvent(ev proxy.Event) error
	// Snapshot returns the cumulative counters, stamped with started as StartedAt.
	Snapshot(started time.Time) (Snapshot, error)
	// Recent returns up to limit events, newest first. limit <= 0 means all.
	Recent(limit int) ([]proxy.Event, error)
	// Quarantine returns active supply-chain holds (newest BLOCK@supply per
	// eco/pkg@ver whose block_until is after now), newest first.
	Quarantine(now time.Time) ([]proxy.Event, error)
	// DailyMetrics returns per-UTC-day rows, newest first (days <= 0 → all).
	DailyMetrics(days int) ([]DailyMetric, error)
	// Prune deletes events and daily rows older than the configured retention.
	Prune() error
}
```

- [ ] **Step 2: Replace `internal/telemetry/sqlite.go` entirely**

```go
package telemetry

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

// telemetryMigrations is the forward-only schema for the telemetry tables.
// Events keep queryable columns plus a JSON blob for exact round-tripping;
// daily_metrics and counters store gate tallies as JSON to keep the schema narrow.
var telemetryMigrations = []string{`
CREATE TABLE IF NOT EXISTS events (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	ts           INTEGER NOT NULL,
	request_id   TEXT    NOT NULL DEFAULT '',
	ecosystem    TEXT    NOT NULL DEFAULT '',
	package      TEXT    NOT NULL DEFAULT '',
	version      TEXT    NOT NULL DEFAULT '',
	verdict      TEXT    NOT NULL DEFAULT '',
	gate         TEXT    NOT NULL DEFAULT '',
	reason       TEXT    NOT NULL DEFAULT '',
	http_status  INTEGER NOT NULL DEFAULT 0,
	published_at INTEGER NOT NULL DEFAULT 0,
	block_until  INTEGER NOT NULL DEFAULT 0,
	detail_json  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS daily_metrics (
	day             TEXT PRIMARY KEY,
	requests        INTEGER NOT NULL DEFAULT 0,
	cache_hits      INTEGER NOT NULL DEFAULT 0,
	blocked         INTEGER NOT NULL DEFAULT 0,
	errors          INTEGER NOT NULL DEFAULT 0,
	supply_blocked  INTEGER NOT NULL DEFAULT 0,
	cve_blocked     INTEGER NOT NULL DEFAULT 0,
	malware_blocked INTEGER NOT NULL DEFAULT 0,
	denylisted      INTEGER NOT NULL DEFAULT 0,
	gates_json      TEXT    NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS counters (
	id              INTEGER PRIMARY KEY CHECK (id = 1),
	requests        INTEGER NOT NULL DEFAULT 0,
	cache_hits      INTEGER NOT NULL DEFAULT 0,
	blocked         INTEGER NOT NULL DEFAULT 0,
	errors          INTEGER NOT NULL DEFAULT 0,
	supply_blocked  INTEGER NOT NULL DEFAULT 0,
	cve_blocked     INTEGER NOT NULL DEFAULT 0,
	malware_blocked INTEGER NOT NULL DEFAULT 0,
	denylisted      INTEGER NOT NULL DEFAULT 0,
	gates_json      TEXT    NOT NULL DEFAULT '{}'
);
`, `
CREATE INDEX IF NOT EXISTS idx_events_verdict_gate ON events(verdict, gate);
`}

const defaultEventRetentionDays = 30
const defaultDailyRetentionDays = 365

type sqliteRepo struct {
	db             *sql.DB
	eventRetention time.Duration
	dailyRetention time.Duration
}

// NewSQLiteRepo applies the telemetry schema to db and returns a Repo.
// eventRetentionDays/dailyRetentionDays ≤ 0 fall back to defaults (30/365).
func NewSQLiteRepo(db *storage.DB, eventRetentionDays, dailyRetentionDays int) (Repo, error) {
	if err := db.ApplyMigrations("telemetry", telemetryMigrations); err != nil {
		return nil, fmt.Errorf("telemetry migrations: %w", err)
	}
	if eventRetentionDays <= 0 {
		eventRetentionDays = defaultEventRetentionDays
	}
	if dailyRetentionDays <= 0 {
		dailyRetentionDays = defaultDailyRetentionDays
	}
	return &sqliteRepo{
		db:             db.SQL(),
		eventRetention: time.Duration(eventRetentionDays) * 24 * time.Hour,
		dailyRetention: time.Duration(dailyRetentionDays) * 24 * time.Hour,
	}, nil
}

// querier is the subset of *sql.DB / *sql.Tx used by the row helpers, so the
// same read/write code works inside and outside a transaction.
type querier interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

func unixNanoOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func parseGates(blob string) map[string]GateCounts {
	if blob == "" {
		return map[string]GateCounts{}
	}
	var g map[string]GateCounts
	if err := json.Unmarshal([]byte(blob), &g); err != nil {
		return map[string]GateCounts{}
	}
	return g
}

// RecordEvent inserts the event and folds its one-event delta into the
// cumulative counters and the event's UTC-day row, all in one transaction.
func (r *sqliteRepo) RecordEvent(ev proxy.Event) error {
	delta := newAggregate()
	delta.record(ev)

	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	blob, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshalling event: %w", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO events
			(ts, request_id, ecosystem, package, version, verdict, gate, reason,
			 http_status, published_at, block_until, detail_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		unixNanoOrZero(ev.Time), ev.RequestID, ev.Ecosystem, ev.Package, ev.Version,
		ev.Verdict, ev.Gate, ev.Reason, ev.HTTPStatus,
		unixNanoOrZero(ev.PublishedAt), unixNanoOrZero(ev.BlockUntil), string(blob),
	); err != nil {
		return err
	}

	counters, err := readCounters(tx)
	if err != nil {
		return err
	}
	counters.add(delta)
	if err := upsertCounters(tx, counters.snapshot(time.Time{})); err != nil {
		return err
	}

	day := dayKey(ev)
	dailyAgg, err := readDaily(tx, day)
	if err != nil {
		return err
	}
	dailyAgg.add(delta)
	if err := upsertDaily(tx, dailyAgg.dailyMetric(day)); err != nil {
		return err
	}

	return tx.Commit()
}

func readCounters(q querier) (*aggregate, error) {
	var snap Snapshot
	var gatesJSON string
	err := q.QueryRow(`
		SELECT requests, cache_hits, blocked, errors, supply_blocked,
		       cve_blocked, malware_blocked, denylisted, gates_json
		FROM counters WHERE id = 1`).Scan(
		&snap.Requests, &snap.CacheHits, &snap.Blocked, &snap.Errors,
		&snap.SupplyBlocked, &snap.CVEBlocked, &snap.MalwareBlocked,
		&snap.Denylisted, &gatesJSON)
	switch {
	case err == sql.ErrNoRows:
		return newAggregate(), nil
	case err != nil:
		return nil, err
	}
	snap.Gates = parseGates(gatesJSON)
	return aggregateFromSnapshot(snap), nil
}

func upsertCounters(q querier, s Snapshot) error {
	gatesBlob, err := json.Marshal(s.Gates)
	if err != nil {
		return err
	}
	_, err = q.Exec(`
		INSERT INTO counters
			(id, requests, cache_hits, blocked, errors, supply_blocked,
			 cve_blocked, malware_blocked, denylisted, gates_json)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			requests=excluded.requests, cache_hits=excluded.cache_hits,
			blocked=excluded.blocked, errors=excluded.errors,
			supply_blocked=excluded.supply_blocked, cve_blocked=excluded.cve_blocked,
			malware_blocked=excluded.malware_blocked, denylisted=excluded.denylisted,
			gates_json=excluded.gates_json`,
		s.Requests, s.CacheHits, s.Blocked, s.Errors,
		s.SupplyBlocked, s.CVEBlocked, s.MalwareBlocked, s.Denylisted, string(gatesBlob))
	return err
}

func readDaily(q querier, day string) (*aggregate, error) {
	var d DailyMetric
	var gatesJSON string
	err := q.QueryRow(`
		SELECT day, requests, cache_hits, blocked, errors, supply_blocked,
		       cve_blocked, malware_blocked, denylisted, gates_json
		FROM daily_metrics WHERE day = ?`, day).Scan(
		&d.Day, &d.Requests, &d.CacheHits, &d.Blocked, &d.Errors,
		&d.SupplyBlocked, &d.CVEBlocked, &d.MalwareBlocked, &d.Denylisted, &gatesJSON)
	switch {
	case err == sql.ErrNoRows:
		return newAggregate(), nil
	case err != nil:
		return nil, err
	}
	d.Gates = parseGates(gatesJSON)
	return aggregateFromDaily(d), nil
}

func upsertDaily(q querier, d DailyMetric) error {
	gatesBlob, err := json.Marshal(d.Gates)
	if err != nil {
		return err
	}
	_, err = q.Exec(`
		INSERT INTO daily_metrics
			(day, requests, cache_hits, blocked, errors, supply_blocked,
			 cve_blocked, malware_blocked, denylisted, gates_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(day) DO UPDATE SET
			requests=excluded.requests, cache_hits=excluded.cache_hits,
			blocked=excluded.blocked, errors=excluded.errors,
			supply_blocked=excluded.supply_blocked, cve_blocked=excluded.cve_blocked,
			malware_blocked=excluded.malware_blocked, denylisted=excluded.denylisted,
			gates_json=excluded.gates_json`,
		d.Day, d.Requests, d.CacheHits, d.Blocked, d.Errors,
		d.SupplyBlocked, d.CVEBlocked, d.MalwareBlocked, d.Denylisted, string(gatesBlob))
	return err
}

func (r *sqliteRepo) Snapshot(started time.Time) (Snapshot, error) {
	agg, err := readCounters(r.db)
	if err != nil {
		return Snapshot{}, err
	}
	return agg.snapshot(started), nil
}

func (r *sqliteRepo) Recent(limit int) ([]proxy.Event, error) {
	query := `SELECT detail_json FROM events ORDER BY ts DESC, id DESC`
	var args []any
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proxy.Event
	for rows.Next() {
		var blob string
		if err := rows.Scan(&blob); err != nil {
			return nil, err
		}
		var ev proxy.Event
		if err := json.Unmarshal([]byte(blob), &ev); err != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (r *sqliteRepo) Quarantine(now time.Time) ([]proxy.Event, error) {
	rows, err := r.db.Query(`
		SELECT detail_json FROM events
		WHERE verdict = ? AND gate = ?
		ORDER BY ts DESC, id DESC`, proxy.VerdictBlock, proxy.GateSupply)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []proxy.Event
	for rows.Next() {
		var blob string
		if err := rows.Scan(&blob); err != nil {
			return nil, err
		}
		var ev proxy.Event
		if err := json.Unmarshal([]byte(blob), &ev); err != nil {
			continue
		}
		// Deduplicate by eco/pkg@ver BEFORE the expiry filter, so the newest
		// record for a package decides whether it is held at all.
		key := ev.Ecosystem + "/" + ev.Package + "@" + ev.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		if !ev.BlockUntil.After(now) {
			continue
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (r *sqliteRepo) DailyMetrics(days int) ([]DailyMetric, error) {
	query := `
		SELECT day, requests, cache_hits, blocked, errors, supply_blocked,
		       cve_blocked, malware_blocked, denylisted, gates_json
		FROM daily_metrics ORDER BY day DESC`
	args := []any{}
	if days > 0 {
		query += ` LIMIT ?`
		args = append(args, days)
	}
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DailyMetric
	for rows.Next() {
		var d DailyMetric
		var gatesJSON string
		if err := rows.Scan(
			&d.Day, &d.Requests, &d.CacheHits, &d.Blocked, &d.Errors,
			&d.SupplyBlocked, &d.CVEBlocked, &d.MalwareBlocked, &d.Denylisted, &gatesJSON,
		); err != nil {
			return nil, err
		}
		d.Gates = parseGates(gatesJSON)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *sqliteRepo) Prune() error {
	eventCutoff := time.Now().Add(-r.eventRetention).UnixNano()
	if _, err := r.db.Exec(`DELETE FROM events WHERE ts < ?`, eventCutoff); err != nil {
		return err
	}
	dayCutoff := time.Now().Add(-r.dailyRetention).UTC().Format("2006-01-02")
	if _, err := r.db.Exec(`DELETE FROM daily_metrics WHERE day < ?`, dayCutoff); err != nil {
		return err
	}
	return nil
}
```

- [ ] **Step 3: Replace `internal/telemetry/store.go` entirely**

```go
// Package telemetry collects per-request events from the proxy handlers for the
// admin console and persists them to SQLite, the single source of truth. Every
// Record is durable at write time; reads query SQLite directly. There is no
// in-memory mode.
package telemetry

import (
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

// GateCounts is the pass/block tally for one gate.
type GateCounts struct {
	Pass  uint64 `json:"pass"`
	Block uint64 `json:"block"`
}

// Snapshot is a point-in-time copy of all counters since process start.
type Snapshot struct {
	StartedAt      time.Time
	Requests       uint64
	CacheHits      uint64
	Blocked        uint64
	Errors         uint64
	SupplyBlocked  uint64
	CVEBlocked     uint64
	MalwareBlocked uint64
	Denylisted     uint64
	Gates          map[string]GateCounts // keys: cache, supply, cve, malware
}

// DailyMetric is one UTC calendar day's tallies.
type DailyMetric struct {
	Day            string                `json:"day"` // UTC YYYY-MM-DD
	Requests       uint64                `json:"requests"`
	CacheHits      uint64                `json:"cache_hits"`
	Blocked        uint64                `json:"blocked"`
	Errors         uint64                `json:"errors"`
	SupplyBlocked  uint64                `json:"supply_blocked"`
	CVEBlocked     uint64                `json:"cve_blocked"`
	MalwareBlocked uint64                `json:"malware_blocked"`
	Denylisted     uint64                `json:"denylisted"`
	Gates          map[string]GateCounts `json:"gates"`
}

// pruneInterval is how often the background loop deletes rows past retention.
// Retention is measured in days, so hourly is ample and cheap.
const pruneInterval = time.Hour

// Store is a thin façade over a Repo. All telemetry state lives in the Repo
// (SQLite). Store adds the process start time (for uptime) and a periodic prune.
type Store struct {
	repo    Repo
	logger  zerolog.Logger
	started time.Time

	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// New returns a Store backed by repo and starts its background prune loop.
func New(repo Repo, logger zerolog.Logger) *Store {
	s := &Store{
		repo:    repo,
		logger:  logger,
		started: time.Now(),
		stop:    make(chan struct{}),
	}
	s.wg.Add(1)
	go s.pruneLoop()
	return s
}

// Open builds a SQLite-backed Store on db, applying the telemetry schema.
// Retention values ≤ 0 fall back to defaults (30/365 days).
func Open(db *storage.DB, eventRetentionDays, dailyRetentionDays int, logger zerolog.Logger) (*Store, error) {
	repo, err := NewSQLiteRepo(db, eventRetentionDays, dailyRetentionDays)
	if err != nil {
		return nil, err
	}
	return New(repo, logger), nil
}

// Record durably persists ev (insert + counter/daily increments) synchronously.
// Telemetry must never fail a proxy request: on error it logs and returns,
// losing at most this one event (not a flush window).
func (s *Store) Record(ev proxy.Event) {
	if err := s.repo.RecordEvent(ev); err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: recording event")
	}
}

// Snapshot returns the cumulative counters. A read error logs and yields a
// zero snapshot (the overview must not 500 on a transient read failure).
func (s *Store) Snapshot() Snapshot {
	snap, err := s.repo.Snapshot(s.started)
	if err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: reading snapshot")
		return Snapshot{StartedAt: s.started, Gates: map[string]GateCounts{}}
	}
	return snap
}

// Recent returns up to limit events, newest first (limit ≤ 0 → all). A read
// error logs and yields nil.
func (s *Store) Recent(limit int) []proxy.Event {
	evs, err := s.repo.Recent(limit)
	if err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: reading recent events")
		return nil
	}
	return evs
}

// Quarantine returns the active supply-chain holds. A read error logs and
// yields nil.
func (s *Store) Quarantine(now time.Time) []proxy.Event {
	evs, err := s.repo.Quarantine(now)
	if err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: reading quarantine")
		return nil
	}
	return evs
}

// DailyMetrics returns per-UTC-day tallies, newest first (days ≤ 0 → all).
func (s *Store) DailyMetrics(days int) ([]DailyMetric, error) {
	return s.repo.DailyMetrics(days)
}

func (s *Store) pruneLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(pruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			if err := s.repo.Prune(); err != nil {
				s.logger.Warn().Err(err).Msg("telemetry: pruning")
			}
		}
	}
}

// Close stops the prune loop. Safe to call multiple times.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
	})
	return nil
}
```

- [ ] **Step 4: Replace `internal/telemetry/store_test.go` entirely**

```go
package telemetry_test

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func evt(id, verdict, gate, reason string) proxy.Event {
	return proxy.Event{
		RequestID: id, Time: time.Now(),
		Ecosystem: "pypi", Package: "requests", Version: "2.31.0",
		Verdict: verdict, Gate: gate, Reason: reason,
	}
}

// newStore returns a SQLite-backed Store on a fresh temp-file database.
func newStore(t *testing.T) *telemetry.Store {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := telemetry.Open(db, 30, 365, zerolog.Nop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStoreRecentOrderAndLimit(t *testing.T) {
	s := newStore(t)
	for i := 1; i <= 6; i++ {
		s.Record(evt(fmt.Sprintf("r%d", i), proxy.VerdictPass, proxy.GateSupply, "ok"))
	}

	got := s.Recent(10)
	require.Len(t, got, 6, "all events are retained (no ring buffer)")
	assert.Equal(t, "r6", got[0].RequestID, "newest first")
	assert.Equal(t, "r5", got[1].RequestID)

	got = s.Recent(2)
	require.Len(t, got, 2)
	assert.Equal(t, "r6", got[0].RequestID)
	assert.Equal(t, "r5", got[1].RequestID)
}

func TestStoreCounters(t *testing.T) {
	s := newStore(t)
	s.Record(evt("r1", proxy.VerdictCache, proxy.GateCache, "cache_hit"))
	s.Record(evt("r2", proxy.VerdictPass, proxy.GateMalware, "ok"))
	s.Record(evt("r3", proxy.VerdictBlock, proxy.GateCVE, "cve_found"))
	s.Record(evt("r4", proxy.VerdictBlock, proxy.GateCVE, "denylisted"))
	s.Record(evt("r5", proxy.VerdictBlock, proxy.GateSupply, "package_younger_than_min_age"))
	s.Record(evt("r6", proxy.VerdictBlock, proxy.GateMalware, "malware_found"))
	s.Record(evt("r7", proxy.VerdictError, proxy.GateSupply, "upstream_metadata_unavailable"))

	snap := s.Snapshot()
	assert.Equal(t, uint64(7), snap.Requests)
	assert.Equal(t, uint64(1), snap.CacheHits)
	assert.Equal(t, uint64(4), snap.Blocked)
	assert.Equal(t, uint64(1), snap.Errors)
	assert.Equal(t, uint64(1), snap.CVEBlocked)
	assert.Equal(t, uint64(1), snap.Denylisted)
	assert.Equal(t, uint64(1), snap.SupplyBlocked)
	assert.Equal(t, uint64(1), snap.MalwareBlocked)
	assert.False(t, snap.StartedAt.IsZero())

	assert.Equal(t, telemetry.GateCounts{Pass: 1, Block: 0}, snap.Gates[proxy.GateCache])
	assert.Equal(t, telemetry.GateCounts{Pass: 4, Block: 1}, snap.Gates[proxy.GateSupply])
	assert.Equal(t, telemetry.GateCounts{Pass: 2, Block: 2}, snap.Gates[proxy.GateCVE])
	assert.Equal(t, telemetry.GateCounts{Pass: 1, Block: 1}, snap.Gates[proxy.GateMalware])
}

func TestStoreCacheScanFailedBlockDoesNotCountPipelinePasses(t *testing.T) {
	s := newStore(t)
	s.Record(evt("r1", proxy.VerdictBlock, proxy.GateCache, "scan_failed"))

	snap := s.Snapshot()
	assert.Equal(t, telemetry.GateCounts{Pass: 0, Block: 1}, snap.Gates[proxy.GateCache])
	assert.Equal(t, telemetry.GateCounts{}, snap.Gates[proxy.GateSupply])
	assert.Equal(t, telemetry.GateCounts{}, snap.Gates[proxy.GateCVE])
}

func TestStoreQuarantine(t *testing.T) {
	now := time.Now()
	s := newStore(t)

	active := evt("r1", proxy.VerdictBlock, proxy.GateSupply, "package_younger_than_min_age")
	active.BlockUntil = now.Add(6 * time.Hour)
	s.Record(active)

	expired := evt("r2", proxy.VerdictBlock, proxy.GateSupply, "package_younger_than_min_age")
	expired.Package = "old-pkg"
	expired.BlockUntil = now.Add(-time.Hour)
	s.Record(expired)

	dup := active
	dup.RequestID = "r3"
	s.Record(dup)

	s.Record(evt("r4", proxy.VerdictPass, proxy.GateSupply, "ok"))

	q := s.Quarantine(now)
	require.Len(t, q, 1)
	assert.Equal(t, "r3", q[0].RequestID, "newest duplicate wins")
	assert.Equal(t, "requests", q[0].Package)

	gone := active
	gone.RequestID = "r5"
	gone.BlockUntil = now.Add(-time.Minute)
	s.Record(gone)
	assert.Empty(t, s.Quarantine(now))
}

func TestStoreConcurrent(t *testing.T) {
	s := newStore(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ev := evt(fmt.Sprintf("g%d-%d", g, i), proxy.VerdictPass, proxy.GateSupply, "ok")
				if i%10 == 0 {
					ev.Verdict = proxy.VerdictBlock
					ev.BlockUntil = time.Now().Add(time.Hour)
					ev.Version = fmt.Sprintf("1.0.%d", i)
				}
				s.Record(ev)
				s.Recent(10)
				s.Snapshot()
				s.Quarantine(time.Now())
			}
		}(g)
	}
	wg.Wait()
	assert.Equal(t, uint64(1600), s.Snapshot().Requests)
}

func TestDailyMetrics_BucketsByUTCDay(t *testing.T) {
	s := newStore(t)
	day1 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	s.Record(proxy.Event{Time: day1, Verdict: proxy.VerdictCache, Gate: proxy.GateCache})
	s.Record(proxy.Event{Time: day1, Verdict: proxy.VerdictPass, Gate: proxy.GateMalware})
	s.Record(proxy.Event{Time: day2, Verdict: proxy.VerdictCache, Gate: proxy.GateCache})

	daily, err := s.DailyMetrics(0)
	require.NoError(t, err)
	require.Len(t, daily, 2)
	assert.Equal(t, "2026-01-02", daily[0].Day) // newest first
	assert.Equal(t, uint64(1), daily[0].Requests)
	assert.Equal(t, "2026-01-01", daily[1].Day)
	assert.Equal(t, uint64(2), daily[1].Requests)
	assert.Equal(t, uint64(1), daily[1].CacheHits)
	assert.Equal(t, telemetry.GateCounts{Pass: 1, Block: 0}, daily[1].Gates[proxy.GateCache])

	limited, err := s.DailyMetrics(1)
	require.NoError(t, err)
	require.Len(t, limited, 1)
	assert.Equal(t, "2026-01-02", limited[0].Day)
}

func TestDailyMetrics_ZeroTimeBucketsUnderToday(t *testing.T) {
	s := newStore(t)
	s.Record(proxy.Event{Verdict: proxy.VerdictError}) // zero Time
	daily, err := s.DailyMetrics(0)
	require.NoError(t, err)
	require.Len(t, daily, 1)
	today := time.Now().UTC().Format("2006-01-02")
	assert.Equal(t, today, daily[0].Day)
	assert.Equal(t, uint64(1), daily[0].Requests)
	assert.Equal(t, uint64(1), daily[0].Errors)
}

func TestStore_PersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	now := time.Now().UTC()

	db1, err := storage.Open(path)
	require.NoError(t, err)
	s1, err := telemetry.Open(db1, 30, 365, zerolog.Nop())
	require.NoError(t, err)
	s1.Record(proxy.Event{Time: now, Verdict: proxy.VerdictCache, Gate: proxy.GateCache})
	s1.Record(proxy.Event{Time: now, Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply, Reason: "x",
		Ecosystem: "npm", Package: "p", Version: "1", BlockUntil: now.Add(time.Hour)})
	require.NoError(t, s1.Close())
	require.NoError(t, db1.Close())

	db2, err := storage.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db2.Close() })
	s2, err := telemetry.Open(db2, 30, 365, zerolog.Nop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s2.Close() })

	snap := s2.Snapshot()
	assert.Equal(t, uint64(2), snap.Requests)
	assert.Equal(t, uint64(1), snap.CacheHits)
	assert.Equal(t, uint64(1), snap.Blocked)
	assert.Equal(t, uint64(1), snap.SupplyBlocked)
	assert.Equal(t, telemetry.GateCounts{Pass: 0, Block: 1}, snap.Gates[proxy.GateSupply])

	require.Len(t, s2.Recent(0), 2)

	q := s2.Quarantine(now)
	require.Len(t, q, 1)
	assert.Equal(t, "p", q[0].Package)

	daily, err := s2.DailyMetrics(0)
	require.NoError(t, err)
	require.Len(t, daily, 1)
	assert.Equal(t, uint64(2), daily[0].Requests)
}

func TestStore_CloseIdempotent(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close()) // no-op (also called again by t.Cleanup)
}
```

- [ ] **Step 5: Replace `internal/telemetry/sqlite_test.go` entirely**

```go
package telemetry_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func newRepo(t *testing.T) telemetry.Repo {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo, err := telemetry.NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)
	return repo
}

func TestSQLiteRepo_RecordEventRoundTrips(t *testing.T) {
	repo := newRepo(t)
	ev := proxy.Event{
		RequestID: "r1", Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Ecosystem: "npm", Package: "left-pad", Version: "1.0.0",
		Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply, Reason: "package_younger_than_min_age",
		HTTPStatus: 423, BlockedBy: []string{"supply_chain"},
		PublishedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		BlockUntil:  time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC),
	}
	require.NoError(t, repo.RecordEvent(ev))

	got, err := repo.Recent(100)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "r1", got[0].RequestID)
	assert.Equal(t, "left-pad", got[0].Package)
	assert.Equal(t, proxy.VerdictBlock, got[0].Verdict)
	assert.Equal(t, []string{"supply_chain"}, got[0].BlockedBy)
	assert.True(t, got[0].Time.Equal(ev.Time))
	assert.True(t, got[0].BlockUntil.Equal(ev.BlockUntil))
}

func TestSQLiteRepo_RecordEventAccumulatesCountersAndDaily(t *testing.T) {
	repo := newRepo(t)
	today := time.Now().UTC()
	require.NoError(t, repo.RecordEvent(proxy.Event{Time: today, Verdict: proxy.VerdictCache, Gate: proxy.GateCache}))
	require.NoError(t, repo.RecordEvent(proxy.Event{Time: today, Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply,
		Reason: "package_younger_than_min_age", Ecosystem: "npm", Package: "p", Version: "1"}))
	require.NoError(t, repo.RecordEvent(proxy.Event{Time: today, Verdict: proxy.VerdictBlock, Gate: proxy.GateCVE, Reason: "cve_found"}))

	started := time.Now()
	snap, err := repo.Snapshot(started)
	require.NoError(t, err)
	assert.True(t, snap.StartedAt.Equal(started))
	assert.Equal(t, uint64(3), snap.Requests)
	assert.Equal(t, uint64(1), snap.CacheHits)
	assert.Equal(t, uint64(2), snap.Blocked)
	assert.Equal(t, uint64(1), snap.SupplyBlocked)
	assert.Equal(t, uint64(1), snap.CVEBlocked)
	assert.Equal(t, telemetry.GateCounts{Pass: 1, Block: 0}, snap.Gates[proxy.GateCache])
	assert.Equal(t, telemetry.GateCounts{Pass: 1, Block: 1}, snap.Gates[proxy.GateSupply])
	assert.Equal(t, telemetry.GateCounts{Pass: 0, Block: 1}, snap.Gates[proxy.GateCVE])

	rows, err := repo.DailyMetrics(0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, today.Format("2006-01-02"), rows[0].Day)
	assert.Equal(t, uint64(3), rows[0].Requests)
	assert.Equal(t, telemetry.GateCounts{Pass: 1, Block: 1}, rows[0].Gates[proxy.GateSupply])
}

func TestSQLiteRepo_SnapshotEmptyIsZeroValue(t *testing.T) {
	repo := newRepo(t)
	snap, err := repo.Snapshot(time.Now())
	require.NoError(t, err)
	assert.Equal(t, uint64(0), snap.Requests)
	assert.NotNil(t, snap.Gates)
	assert.Equal(t, telemetry.GateCounts{}, snap.Gates[proxy.GateSupply])

	recent, err := repo.Recent(100)
	require.NoError(t, err)
	assert.Empty(t, recent)
}

func TestSQLiteRepo_QuarantineDedupesBeforeExpiry(t *testing.T) {
	repo := newRepo(t)
	now := time.Now()
	mk := func(id, ver string, until time.Time) proxy.Event {
		return proxy.Event{
			RequestID: id, Time: time.Now(), Ecosystem: "npm", Package: "p", Version: ver,
			Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply, BlockUntil: until,
		}
	}
	require.NoError(t, repo.RecordEvent(mk("r1", "1", now.Add(time.Hour))))
	require.NoError(t, repo.RecordEvent(mk("r2", "1", now.Add(2*time.Hour)))) // newer, same key

	q, err := repo.Quarantine(now)
	require.NoError(t, err)
	require.Len(t, q, 1)
	assert.Equal(t, "r2", q[0].RequestID)

	require.NoError(t, repo.RecordEvent(mk("r3", "1", now.Add(-time.Minute)))) // newest expired
	q, err = repo.Quarantine(now)
	require.NoError(t, err)
	assert.Empty(t, q)
}

func TestSQLiteRepo_DailyMetricsLimit(t *testing.T) {
	repo := newRepo(t)
	for _, d := range []time.Time{
		time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 3, 12, 0, 0, 0, time.UTC),
	} {
		require.NoError(t, repo.RecordEvent(proxy.Event{Time: d, Verdict: proxy.VerdictPass, Gate: proxy.GateMalware}))
	}
	rows, err := repo.DailyMetrics(2)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "2026-01-03", rows[0].Day)
	assert.Equal(t, "2026-01-02", rows[1].Day)
}

func TestSQLiteRepo_PruneRemovesOldEvents(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo, err := telemetry.NewSQLiteRepo(db, 1, 1) // 1-day retention
	require.NoError(t, err)

	require.NoError(t, repo.RecordEvent(proxy.Event{RequestID: "old", Time: time.Now().Add(-72 * time.Hour), Verdict: proxy.VerdictPass, Gate: proxy.GateMalware}))
	require.NoError(t, repo.RecordEvent(proxy.Event{RequestID: "fresh", Time: time.Now(), Verdict: proxy.VerdictPass, Gate: proxy.GateMalware}))
	require.NoError(t, repo.Prune())

	got, err := repo.Recent(100)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "fresh", got[0].RequestID)
}
```

- [ ] **Step 6: Update `internal/telemetry/broadcaster_test.go`**

In `TestHubRecordsAndPublishes`, replace `store := telemetry.NewStore(8)` with `store := newStore(t)` (the helper from `store_test.go`, same `telemetry_test` package). No other changes.

- [ ] **Step 7: Update `internal/console/server_test.go`**

Add this helper near the top of the file (after imports). Confirm the import block includes `"path/testing"`-style deps — add `"path/filepath"`, `"github.com/ggwpLab/Jo-ei/internal/storage"`, and `"github.com/rs/zerolog"` if not already imported:

```go
func newTelemetryStore(t *testing.T) *telemetry.Store {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := telemetry.Open(db, 30, 365, zerolog.Nop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}
```

Then replace every `telemetry.NewStore(N)` (lines ~44, ~252, ~293, ~331, ~416) with `newTelemetryStore(t)`. Note line ~416 is inside a struct literal `Store: telemetry.NewStore(8)` → becomes `Store: newTelemetryStore(t)`.

- [ ] **Step 8: Add a shared helper to the integration tests**

In `integration/console_test.go`, add (after imports; add `"path/filepath"`, `"github.com/ggwpLab/Jo-ei/internal/storage"`, `"github.com/rs/zerolog"` to imports if missing):

```go
func newTelemetryStore(t *testing.T) *telemetry.Store {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := telemetry.Open(db, 30, 365, zerolog.Nop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}
```

Replace `telemetry.NewStore(100)` at `integration/console_test.go:46` with `newTelemetryStore(t)`.

- [ ] **Step 9: Update the other integration callers**

- `integration/scanner_health_test.go:34`: replace `store := telemetry.NewStore(100)` with `store := newTelemetryStore(t)` (shared helper; same `integration_test` package — no new import needed).
- `integration/console_auth_test.go:43`: replace `store := telemetry.NewStore(100)` with `store := newTelemetryStore(t)`.

- [ ] **Step 10: Rewrite `integration/telemetry_persistence_test.go`**

```go
//go:build integration

package integration_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func TestTelemetryPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jo-ei.db")
	now := time.Now().UTC()

	// First "process": record (durable at write time), then close.
	{
		db, err := storage.Open(path)
		require.NoError(t, err)
		s, err := telemetry.Open(db, 30, 365, zerolog.Nop())
		require.NoError(t, err)
		s.Record(proxy.Event{Time: now, Verdict: proxy.VerdictCache, Gate: proxy.GateCache})
		s.Record(proxy.Event{Time: now, Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply,
			Reason: "package_younger_than_min_age", Ecosystem: "npm", Package: "p", Version: "1",
			BlockUntil: now.Add(time.Hour)})
		require.NoError(t, s.Close())
		require.NoError(t, db.Close())
	}

	// Second "process": reopen the same file; state restored.
	db, err := storage.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := telemetry.Open(db, 30, 365, zerolog.Nop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	snap := s.Snapshot()
	assert.Equal(t, uint64(2), snap.Requests)
	assert.Equal(t, uint64(1), snap.CacheHits)
	assert.Equal(t, uint64(1), snap.Blocked)
	assert.Equal(t, uint64(1), snap.SupplyBlocked)

	require.Len(t, s.Recent(0), 2)

	q := s.Quarantine(now)
	require.Len(t, q, 1)
	assert.Equal(t, "p", q[0].Package)

	daily, err := s.DailyMetrics(0)
	require.NoError(t, err)
	require.Len(t, daily, 1)
	assert.Equal(t, uint64(2), daily[0].Requests)
}
```

- [ ] **Step 11: Build and run the full suite (including integration)**

Run: `go build ./... && go test ./... && go test -tags integration ./integration/...`
Expected: PASS. `cmd/jo-ei` will not compile yet only if Task 4's `main.go` change were already applied — it is not, so the old `buildTelemetryStore` still references the removed `telemetry.NewStore`/`NewPersistentStore`. **This means `cmd/jo-ei` will fail to build in this step.** To keep this commit green, also apply Task 4 Step 1's `main.go` rewrite and Task 4 Step 4's `eventHistorySize` removal **now**, then build. (Tasks 3 and 4's config/test/doc steps can still follow as their own commits.)

> Sequencing note: removing `telemetry.NewStore`/`NewPersistentStore` breaks `cmd/jo-ei/main.go`. The `main.go` source rewrite (Task 4, Step 1) and `eventHistorySize` removal (Task 4, Step 4) MUST land in this same commit. The remaining Task 3/Task 4 items (config validation, config.yaml/README docs, config tests) are independent and follow as separate commits.

- [ ] **Step 12: Commit**

```bash
git add internal/telemetry/ internal/console/server_test.go integration/ cmd/jo-ei/main.go
git commit -m "feat(telemetry): make SQLite the single source of truth

Delete the in-memory ring buffer and aggregates. Record writes one
synchronous transaction (event + counters + daily). Reads query SQLite.
Hourly background prune. Removes the in-memory Store and the seed/flush/
evict/writer machinery."
```

---

## Task 3: Require database.path in config validation

**Files:**
- Modify: `internal/config/config.go` (`Validate`, ~line 64)
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestValidate_RequiresDatabasePath(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = ""
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database.path")

	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	assert.NoError(t, c.Validate())
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/config/ -run TestValidate_RequiresDatabasePath`
Expected: FAIL (no path requirement yet; second assertion may also surface).

- [ ] **Step 3: Add the check to `Validate`**

In `internal/config/config.go`, after the existing retention checks (the `c.Database.DailyRetentionDays < 0` block ending at ~line 64) and before `return nil`, add:

```go
	if c.Database.Path == "" {
		return fmt.Errorf("database.path is required (telemetry persists to SQLite)")
	}
```

This is placed **after** the malware-scanner checks so `TestValidate_RejectsBadScanners` still hits the scanner error first.

- [ ] **Step 4: Fix the existing test that omits a path**

In `internal/config/config_test.go`, `TestValidate_AcceptsGoodScanners` constructs a config without a path and asserts `NoError`. Add a path to it:

```go
func TestValidate_AcceptsGoodScanners(t *testing.T) {
	c := &config.Config{Malware: config.MalwareConfig{Scanners: []config.ScannerConfig{
		{Type: "clamav", Address: "unix:///s.sock"},
		{Type: "icap", Address: "tcp:k:1344", Service: "avscan"},
	}}}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	assert.NoError(t, c.Validate())
}
```

The negative-field tests (`TestValidate_RejectsNegative*`, `TestValidate_RejectsBadScanners`) only assert `require.Error` / a scanner-specific substring and still pass — their configs error before or regardless of the path check.

- [ ] **Step 5: Run the config package tests**

Run: `go test ./internal/config/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): require database.path (telemetry is SQLite-only)"
```

---

## Task 4: Fail fast on database errors at startup

The `main.go` source rewrite (Step 1) and `eventHistorySize` removal (Step 4) were already committed with Task 2 to keep the build green. This task covers the config.yaml/README doc updates and a final verification. If for any reason `main.go` was **not** updated in Task 2, apply Steps 1 and 4 here.

**Files:**
- Modify: `cmd/jo-ei/main.go` (`buildTelemetryStore` + its caller + remove `eventHistorySize`) — *normally already done in Task 2*
- Modify: `config.yaml` (database comment)
- Modify: `README.md` (telemetry persistence note)

- [ ] **Step 1: Rewrite `buildTelemetryStore` (if not already applied in Task 2)**

Replace the function at `cmd/jo-ei/main.go:342-370` with:

```go
// buildTelemetryStore opens the SQLite-backed telemetry store. Telemetry is
// SQLite-only: a missing path is rejected by config validation, and any open
// or schema error aborts startup (no in-memory fallback).
func buildTelemetryStore(cfg *config.Config, logger zerolog.Logger) (*telemetry.Store, error) {
	sdb, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("opening telemetry database at %q: %w", cfg.Database.Path, err)
	}
	store, err := telemetry.Open(sdb, cfg.Database.EventRetentionDays, cfg.Database.DailyRetentionDays, logger)
	if err != nil {
		_ = sdb.Close()
		return nil, fmt.Errorf("initialising telemetry store: %w", err)
	}
	logger.Info().Str("path", cfg.Database.Path).Msg("telemetry persistence enabled")
	return store, nil
}
```

Confirm `"fmt"` is imported in `main.go` (add it to the import block if not present).

- [ ] **Step 2: Update the caller (if not already applied in Task 2)**

At `cmd/jo-ei/main.go:125`, replace:

```go
	store := buildTelemetryStore(cfg, logger)
	defer func() { _ = store.Close() }()
```

with:

```go
	store, err := buildTelemetryStore(cfg, logger)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
```

If `err` is already declared earlier in `run` with `:=`, use `=` to avoid a redeclaration error; otherwise keep `:=`. Verify by reading the surrounding lines.

- [ ] **Step 3: Remove the now-unused `eventHistorySize` constant (if not already applied in Task 2)**

Delete the comment + const at `cmd/jo-ei/main.go:33-35`:

```go
// eventHistorySize is the telemetry ring-buffer capacity backing the console
// ...
const eventHistorySize = 500
```

- [ ] **Step 4: Update the `database` comment in `config.yaml`**

Replace lines 63-69 (the `database` block and its comment) with:

```yaml
# Persistent state (required). Telemetry — event history, lifetime counters and
# per-day metrics — is stored in an embedded SQLite database and is the single
# source of truth. The path must be set; the proxy fails to start without it.
database:
  path: "/var/lib/jo-ei/jo-ei.db"
  event_retention_days: 30    # prune persisted events older than this
  daily_retention_days: 365   # prune per-day metric rows older than this
```

- [ ] **Step 5: Update the telemetry note in `README.md`**

At `README.md:221-227`, the text says metrics "reset on restart" without a `database.path` and that without one the cards show current counters only. Replace that passage so it reflects that `database.path` is now required and telemetry always persists. Concretely, change the wording to:

```
Telemetry — event history, lifetime counters and per-day metrics — is persisted
to the embedded SQLite database at `database.path`, which is required. Metrics
survive restarts; the Overview daily sparklines and the 7-day / 30-day window
toggle read from that history.
```

(Adjust surrounding sentences minimally so the paragraph reads cleanly; do not touch unrelated README sections.)

- [ ] **Step 6: Build and run everything**

Run: `go build ./... && go test ./... && go test -tags integration ./integration/...`
Expected: PASS.

- [ ] **Step 7: Manual fail-fast sanity check**

Run the proxy against a config whose `database.path` points at an unwritable location (e.g. a path under a non-existent read-only root) and confirm startup aborts with the "opening telemetry database" error rather than starting in a degraded mode. Document the observed error in the commit body if it differs from expectation.

- [ ] **Step 8: Commit**

```bash
git add config.yaml README.md cmd/jo-ei/main.go
git commit -m "docs+feat: telemetry requires database.path, fail fast on db error"
```

---

## Self-Review Notes (for the implementer)

- **Spec coverage:** synchronous `Record` (Task 2), reads from SQLite (Task 2), `Repo` interface change (Task 2 Step 1), index migration (Task 2 Step 2), hourly prune (Task 2 Step 3), fail-fast + required path (Tasks 3 & 4), docs (Task 4). All spec sections map to a task.
- **Atomicity:** Removing `telemetry.NewStore`/`NewPersistentStore` breaks `cmd/jo-ei/main.go` and every test caller at once. Task 2 Step 11 calls this out explicitly and folds the `main.go` source change into the same commit. Treat the green-build check as the gate for that commit.
- **Type consistency:** the façade keeps `Snapshot() Snapshot`, `Recent(int) []proxy.Event`, `Quarantine(time.Time) []proxy.Event` (non-erroring) and `DailyMetrics(int) ([]DailyMetric, error)` — identical to today, so `internal/console/server.go` needs **no** changes. New surface: `telemetry.New(repo, logger)`, `telemetry.Open(db, evtRet, dayRet, logger)`, and `Repo` methods `RecordEvent`/`Snapshot`/`Recent`/`Quarantine`.
- **No leftover references:** after Task 2, grep the repo for `NewStore`, `NewPersistentStore`, `LoadState`, `AppendEvents`, `Flush(`, and `eventHistorySize` — there should be no remaining references outside `docs/`.
