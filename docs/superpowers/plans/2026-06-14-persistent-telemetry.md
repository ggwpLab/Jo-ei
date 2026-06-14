# Persistent Telemetry (SQLite) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist telemetry (event history, lifetime counters, per-UTC-day metrics) across restarts using an embedded SQLite database, and expose a new `GET /api/metrics/daily` endpoint.

**Architecture:** A generic `internal/storage` layer wraps a pure-Go SQLite `*sql.DB` (`modernc.org/sqlite`, already a project dependency, used by `internal/cache`) with WAL + a per-component migration helper. The in-memory `telemetry.Store` stays the authoritative read/write model; persistence is added behind a `Repo` interface — `Repo == nil` keeps today's in-memory-only behavior. The proxy hot path does no synchronous DB I/O: counters/daily update in memory, events are written async by a single batching goroutine, and aggregates flush periodically + on shutdown. DB failure degrades to in-memory (never blocks the proxy).

**Tech Stack:** Go 1.25 stdlib (`database/sql`, `encoding/json`, `sort`, `time`, `sync`), `modernc.org/sqlite` (already in go.mod), zerolog, testify.

**Spec:** `docs/superpowers/specs/2026-06-14-persistent-telemetry-design.md`

> **Deviation from spec, noted:** the spec sketched `PRAGMA user_version` migrations. To match the established project convention (`internal/cache/index.go` uses `CREATE TABLE IF NOT EXISTS`) while still supporting the multi-component shared DB the user wants, `storage` provides a small **per-component** migration helper backed by a `schema_migrations(component, version)` table (so telemetry and a future settings component version independently on the same file). Idempotent and forward-only.

---

## File Structure

**Create:**
- `internal/storage/storage.go` — `Open`, PRAGMAs, `SQL()`, `Close()`, `ApplyMigrations(component, steps)`.
- `internal/storage/storage_test.go`
- `internal/telemetry/repo.go` — `Repo` interface, `State`, `DailyMetric` types (DailyMetric also used by the in-memory accessor).
- `internal/telemetry/sqlite.go` — `sqliteRepo` (schema migrations, LoadState/AppendEvents/Flush/Prune/DailyMetrics).
- `internal/telemetry/sqlite_test.go`
- `integration/telemetry_persistence_test.go` — restart simulation.

**Modify:**
- `internal/telemetry/store.go` — refactor counters into an `aggregate` struct; add in-memory daily tracking; add `DailyMetrics()`; add optional `Repo` + async writer + `NewPersistentStore` + `Close`.
- `internal/telemetry/store_test.go` — daily aggregation tests (existing tests stay green).
- `internal/config/config.go` — `DatabaseConfig` + `Config.Database` + validation.
- `internal/config/config_test.go`
- `internal/console/server.go` — `GET /api/metrics/daily` handler.
- `internal/console/server_test.go`
- `cmd/jo-ei/main.go` — open storage, build repo, `NewPersistentStore`, defer flush/close, degrade on error.
- `config.yaml`, `README.md`

---

## Task 1: storage package

**Files:**
- Create: `internal/storage/storage.go`
- Test: `internal/storage/storage_test.go`

- [ ] **Step 1: Write the failing test**

```go
package storage_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/storage"
)

func TestOpen_CreatesDirAndDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "jo-ei.db")
	db, err := storage.Open(path)
	require.NoError(t, err)
	defer db.Close()
	// WAL pragma should be set.
	var mode string
	require.NoError(t, db.SQL().QueryRow("PRAGMA journal_mode").Scan(&mode))
	assert.Equal(t, "wal", mode)
}

func TestApplyMigrations_IdempotentAndVersioned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jo-ei.db")
	db, err := storage.Open(path)
	require.NoError(t, err)
	defer db.Close()

	steps := []string{
		`CREATE TABLE t1 (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE t2 (id INTEGER PRIMARY KEY)`,
	}
	require.NoError(t, db.ApplyMigrations("demo", steps))
	// Second apply is a no-op (already at version 2) — must not error on re-CREATE.
	require.NoError(t, db.ApplyMigrations("demo", steps))

	// Both tables exist.
	for _, tbl := range []string{"t1", "t2"} {
		var name string
		err := db.SQL().QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&name)
		require.NoError(t, err, "table %s should exist", tbl)
	}

	// Appending a step bumps version and applies only the new one.
	steps = append(steps, `CREATE TABLE t3 (id INTEGER PRIMARY KEY)`)
	require.NoError(t, db.ApplyMigrations("demo", steps))
	var n int
	require.NoError(t, db.SQL().QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='t3'`).Scan(&n))
	assert.Equal(t, 1, n)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/storage/ -v`
Expected: compile failure — `undefined: storage.Open`.

- [ ] **Step 3: Write the implementation**

Create `internal/storage/storage.go`:

```go
// Package storage is the embedded-database foundation for Jōei's persistent
// state. It wraps a pure-Go SQLite *sql.DB (modernc.org/sqlite, no cgo) with
// sensible PRAGMAs and a small per-component migration helper, so several
// subsystems (telemetry now, runtime settings later) can share one file and
// version their schema independently.
package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite connection pool configured for Jōei's persistence needs.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path, creating the parent
// directory if needed, and applies the baseline PRAGMAs (WAL for non-blocking
// reads, a busy timeout to tolerate brief contention). A single open connection
// keeps writes serialized, matching internal/cache.
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("creating db dir %q: %w", dir, err)
		}
	}
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db at %q: %w", path, err)
	}
	sqlDB.SetMaxOpenConns(1) // SQLite: single writer
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := sqlDB.Exec(pragma); err != nil {
			_ = sqlDB.Close()
			return nil, fmt.Errorf("applying %q: %w", pragma, err)
		}
	}
	return &DB{db: sqlDB}, nil
}

// SQL returns the underlying *sql.DB for components to run their queries.
func (d *DB) SQL() *sql.DB { return d.db }

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// ApplyMigrations runs the ordered migration steps for a named component,
// tracking how many have been applied in a schema_migrations table so each
// component versions independently on the shared file. Forward-only and
// idempotent: steps already applied (index < stored version) are skipped.
func (d *DB) ApplyMigrations(component string, steps []string) error {
	if _, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			component TEXT PRIMARY KEY,
			version   INTEGER NOT NULL
		)`); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	var current int
	err := d.db.QueryRow(
		`SELECT version FROM schema_migrations WHERE component=?`, component).Scan(&current)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("reading migration version for %q: %w", component, err)
	}

	for i := current; i < len(steps); i++ {
		if _, err := d.db.Exec(steps[i]); err != nil {
			return fmt.Errorf("applying migration %d for %q: %w", i, component, err)
		}
	}

	if _, err := d.db.Exec(`
		INSERT INTO schema_migrations (component, version) VALUES (?, ?)
		ON CONFLICT(component) DO UPDATE SET version=excluded.version`,
		component, len(steps)); err != nil {
		return fmt.Errorf("recording migration version for %q: %w", component, err)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/storage/ -v`
Expected: PASS. Also `go build ./...` and `go vet ./internal/storage/` clean.

- [ ] **Step 5: Commit**

```bash
git add internal/storage/storage.go internal/storage/storage_test.go
git commit -m "feat(storage): sqlite foundation with per-component migrations"
```

---

## Task 2: telemetry aggregate refactor + in-memory daily

Refactor the Store's counters into a reusable `aggregate` (DRY for lifetime + per-day) and track per-UTC-day buckets in memory. No persistence yet. Public API (Snapshot/Recent/Quarantine) is unchanged so existing tests stay green.

**Files:**
- Modify: `internal/telemetry/store.go`
- Test: `internal/telemetry/store_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/telemetry/store_test.go` (it is `package telemetry` or `telemetry_test` — match the existing file; these tests use the exported API so either works, but if it's an internal test add nothing special):

```go
func TestDailyMetrics_BucketsByUTCDay(t *testing.T) {
	s := telemetry.NewStore(100)
	day1 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	s.Record(proxy.Event{Time: day1, Verdict: proxy.VerdictCache, Gate: proxy.GateCache})
	s.Record(proxy.Event{Time: day1, Verdict: proxy.VerdictPass, Gate: proxy.GateMalware})
	s.Record(proxy.Event{Time: day2, Verdict: proxy.VerdictCache, Gate: proxy.GateCache})

	daily, err := s.DailyMetrics(0)
	require.NoError(t, err)
	require.Len(t, daily, 2)
	// newest first
	assert.Equal(t, "2026-01-02", daily[0].Day)
	assert.Equal(t, uint64(1), daily[0].Requests)
	assert.Equal(t, "2026-01-01", daily[1].Day)
	assert.Equal(t, uint64(2), daily[1].Requests)
	assert.Equal(t, uint64(1), daily[1].CacheHits)

	// limit honored
	limited, err := s.DailyMetrics(1)
	require.NoError(t, err)
	require.Len(t, limited, 1)
	assert.Equal(t, "2026-01-02", limited[0].Day)
}
```

(Ensure the test file imports `time`, `proxy`, testify `assert`/`require`. If `store_test.go` is `package telemetry_test`, reference exported names as `telemetry.NewStore`; if `package telemetry`, drop the `telemetry.` qualifier. Check the file's first line and match it.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/telemetry/ -run TestDailyMetrics -v`
Expected: compile failure — `s.DailyMetrics undefined` / `DailyMetric` unknown.

- [ ] **Step 3: Refactor and implement**

In `internal/telemetry/store.go`:

3a. Add `"sort"` to the imports.

3b. Add the `DailyMetric` type and the `aggregate` type with the counting logic moved out of `Record`. Place after the `Snapshot` type:

```go
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

// aggregate holds the counter tallies shared by lifetime totals and per-day
// buckets. Not safe for concurrent use; callers hold Store.mu.
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

// record applies one event to the tallies. This is the counting logic formerly
// inline in Store.Record.
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
		a.errors++
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

3c. Change the `Store` struct: replace the individual counter fields and `gates` with the aggregate-based fields. The struct becomes:

```go
type Store struct {
	mu      sync.RWMutex
	buf     []proxy.Event
	next    int
	count   int
	started time.Time

	lifetime *aggregate
	daily    map[string]*aggregate // key: UTC YYYY-MM-DD
}
```

3d. Update `NewStore` to initialize the new fields:

```go
func NewStore(capacity int) *Store {
	if capacity < 1 {
		capacity = 1
	}
	return &Store{
		buf:      make([]proxy.Event, capacity),
		started:  time.Now(),
		lifetime: newAggregate(),
		daily:    map[string]*aggregate{},
	}
}
```

3e. Replace the body of `Record` (keep the signature). The ring-buffer write stays; the counter logic delegates to the aggregates:

```go
func (s *Store) Record(ev proxy.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.buf[s.next] = ev
	s.next = (s.next + 1) % len(s.buf)
	if s.count < len(s.buf) {
		s.count++
	}

	s.lifetime.record(ev)
	day := dayKey(ev)
	d := s.daily[day]
	if d == nil {
		d = newAggregate()
		s.daily[day] = d
	}
	d.record(ev)
}
```

3f. Replace `Snapshot` to build from the lifetime aggregate:

```go
func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lifetime.snapshot(s.started)
}
```

3g. Add the `DailyMetrics` accessor (in-memory; the repo branch is added in Task 5):

```go
// DailyMetrics returns per-UTC-day tallies, newest day first. days<=0 returns
// all known days; otherwise the most recent days.
func (s *Store) DailyMetrics(days int) ([]DailyMetric, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DailyMetric, 0, len(s.daily))
	for day, a := range s.daily {
		out = append(out, a.dailyMetric(day))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day > out[j].Day })
	if days > 0 && len(out) > days {
		out = out[:days]
	}
	return out, nil
}
```

3h. Leave `Recent` and `Quarantine` unchanged (they read `s.buf`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/telemetry/ -v`
Expected: PASS — the new daily test plus all existing Store tests (Snapshot/Recent/Quarantine behavior is unchanged).
Then `go build ./...` and `go vet ./internal/telemetry/` clean.

- [ ] **Step 5: Commit**

```bash
git add internal/telemetry/store.go internal/telemetry/store_test.go
git commit -m "refactor(telemetry): aggregate counters + in-memory daily metrics"
```

---

## Task 3: Repo interface + State/DailyMetric wiring types

Define the persistence contract the Store will use and the SQLite repo will implement.

**Files:**
- Create: `internal/telemetry/repo.go`

- [ ] **Step 1: Write the file (no test — pure interface/types; exercised by Tasks 4-5)**

Create `internal/telemetry/repo.go`:

```go
package telemetry

import "github.com/ggwpLab/Jo-ei/internal/proxy"

// State is the persisted telemetry restored at startup.
type State struct {
	// Lifetime holds the cumulative counters. Its StartedAt is ignored on load
	// (uptime tracks the current process, not stored time).
	Lifetime Snapshot
	// HasLifetime is false when no counters row existed yet (fresh DB).
	HasLifetime bool
	// Today is the current UTC day's row if one was already persisted, else nil.
	Today *DailyMetric
	// Events are the most recent events, oldest first, to reseed the ring buffer.
	Events []proxy.Event
}

// Repo persists and restores telemetry. A nil Repo means in-memory only.
// Implementations must be safe for use from the Store's single writer goroutine
// and concurrent DailyMetrics reads from HTTP handlers.
type Repo interface {
	// LoadState restores counters, today's daily row, and up to eventLimit recent
	// events (oldest first).
	LoadState(eventLimit int) (State, error)
	// AppendEvents persists a batch of events.
	AppendEvents(evs []proxy.Event) error
	// Flush upserts the cumulative counters row and the given daily rows.
	Flush(lifetime Snapshot, daily []DailyMetric) error
	// Prune deletes events and daily rows older than the configured retention.
	Prune() error
	// DailyMetrics returns per-UTC-day rows, newest first (days<=0 → all).
	DailyMetrics(days int) ([]DailyMetric, error)
}
```

- [ ] **Step 2: Verify it builds**

Run: `go build ./internal/telemetry/` and `go vet ./internal/telemetry/`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add internal/telemetry/repo.go
git commit -m "feat(telemetry): Repo persistence interface and State type"
```

---

## Task 4: SQLite Repo implementation

**Files:**
- Create: `internal/telemetry/sqlite.go`
- Test: `internal/telemetry/sqlite_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/telemetry/sqlite_test.go`:

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

func TestSQLiteRepo_AppendAndLoadEvents(t *testing.T) {
	repo := newRepo(t)
	ev := proxy.Event{
		RequestID: "r1", Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Ecosystem: "npm", Package: "left-pad", Version: "1.0.0",
		Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply, Reason: "package_younger_than_min_age",
		HTTPStatus: 423, BlockedBy: []string{"supply_chain"},
		PublishedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		BlockUntil:  time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC),
	}
	require.NoError(t, repo.AppendEvents([]proxy.Event{ev}))

	st, err := repo.LoadState(100)
	require.NoError(t, err)
	require.Len(t, st.Events, 1)
	got := st.Events[0]
	assert.Equal(t, "r1", got.RequestID)
	assert.Equal(t, "left-pad", got.Package)
	assert.Equal(t, proxy.VerdictBlock, got.Verdict)
	assert.Equal(t, []string{"supply_chain"}, got.BlockedBy)
	assert.True(t, got.Time.Equal(ev.Time))
	assert.True(t, got.BlockUntil.Equal(ev.BlockUntil))
}

func TestSQLiteRepo_FlushAndLoadCountersAndDaily(t *testing.T) {
	repo := newRepo(t)
	lifetime := telemetry.Snapshot{
		Requests: 10, CacheHits: 4, Blocked: 3, Errors: 1,
		SupplyBlocked: 2, CVEBlocked: 1,
		Gates: map[string]telemetry.GateCounts{
			proxy.GateSupply: {Pass: 7, Block: 2},
			proxy.GateCVE:    {Pass: 5, Block: 1},
		},
	}
	today := time.Now().UTC().Format("2006-01-02")
	daily := []telemetry.DailyMetric{{
		Day: today, Requests: 10, CacheHits: 4, Blocked: 3,
		Gates: map[string]telemetry.GateCounts{proxy.GateSupply: {Pass: 7, Block: 2}},
	}}
	require.NoError(t, repo.Flush(lifetime, daily))

	st, err := repo.LoadState(100)
	require.NoError(t, err)
	require.True(t, st.HasLifetime)
	assert.Equal(t, uint64(10), st.Lifetime.Requests)
	assert.Equal(t, uint64(2), st.Lifetime.SupplyBlocked)
	assert.Equal(t, telemetry.GateCounts{Pass: 7, Block: 2}, st.Lifetime.Gates[proxy.GateSupply])
	require.NotNil(t, st.Today)
	assert.Equal(t, today, st.Today.Day)
	assert.Equal(t, uint64(10), st.Today.Requests)

	// Flush again with higher values → upsert, not duplicate.
	lifetime.Requests = 20
	daily[0].Requests = 20
	require.NoError(t, repo.Flush(lifetime, daily))
	rows, err := repo.DailyMetrics(0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, uint64(20), rows[0].Requests)

	st, err = repo.LoadState(100)
	require.NoError(t, err)
	assert.Equal(t, uint64(20), st.Lifetime.Requests)
}

func TestSQLiteRepo_LoadEmptyIsZeroValue(t *testing.T) {
	repo := newRepo(t)
	st, err := repo.LoadState(100)
	require.NoError(t, err)
	assert.False(t, st.HasLifetime)
	assert.Nil(t, st.Today)
	assert.Empty(t, st.Events)
}

func TestSQLiteRepo_DailyMetricsLimit(t *testing.T) {
	repo := newRepo(t)
	d := []telemetry.DailyMetric{
		{Day: "2026-01-01", Requests: 1},
		{Day: "2026-01-02", Requests: 2},
		{Day: "2026-01-03", Requests: 3},
	}
	require.NoError(t, repo.Flush(telemetry.Snapshot{}, d))
	rows, err := repo.DailyMetrics(2)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "2026-01-03", rows[0].Day) // newest first
	assert.Equal(t, "2026-01-02", rows[1].Day)
}

func TestSQLiteRepo_PruneRemovesOldEvents(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo, err := telemetry.NewSQLiteRepo(db, 1, 1) // 1-day retention
	require.NoError(t, err)

	old := proxy.Event{RequestID: "old", Time: time.Now().Add(-72 * time.Hour), Verdict: proxy.VerdictPass, Gate: proxy.GateMalware}
	fresh := proxy.Event{RequestID: "fresh", Time: time.Now(), Verdict: proxy.VerdictPass, Gate: proxy.GateMalware}
	require.NoError(t, repo.AppendEvents([]proxy.Event{old, fresh}))
	require.NoError(t, repo.Prune())

	st, err := repo.LoadState(100)
	require.NoError(t, err)
	require.Len(t, st.Events, 1)
	assert.Equal(t, "fresh", st.Events[0].RequestID)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/telemetry/ -run TestSQLiteRepo -v`
Expected: compile failure — `undefined: telemetry.NewSQLiteRepo`.

- [ ] **Step 3: Write the implementation**

Create `internal/telemetry/sqlite.go`:

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

func unixNanoOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func (r *sqliteRepo) AppendEvents(evs []proxy.Event) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`
		INSERT INTO events
			(ts, request_id, ecosystem, package, version, verdict, gate, reason,
			 http_status, published_at, block_until, detail_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, ev := range evs {
		blob, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("marshalling event: %w", err)
		}
		if _, err := stmt.Exec(
			unixNanoOrZero(ev.Time), ev.RequestID, ev.Ecosystem, ev.Package, ev.Version,
			ev.Verdict, ev.Gate, ev.Reason, ev.HTTPStatus,
			unixNanoOrZero(ev.PublishedAt), unixNanoOrZero(ev.BlockUntil), string(blob),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *sqliteRepo) Flush(lifetime Snapshot, daily []DailyMetric) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	gatesBlob, err := json.Marshal(lifetime.Gates)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`
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
		lifetime.Requests, lifetime.CacheHits, lifetime.Blocked, lifetime.Errors,
		lifetime.SupplyBlocked, lifetime.CVEBlocked, lifetime.MalwareBlocked,
		lifetime.Denylisted, string(gatesBlob),
	); err != nil {
		return err
	}

	dstmt, err := tx.Prepare(`
		INSERT INTO daily_metrics
			(day, requests, cache_hits, blocked, errors, supply_blocked,
			 cve_blocked, malware_blocked, denylisted, gates_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(day) DO UPDATE SET
			requests=excluded.requests, cache_hits=excluded.cache_hits,
			blocked=excluded.blocked, errors=excluded.errors,
			supply_blocked=excluded.supply_blocked, cve_blocked=excluded.cve_blocked,
			malware_blocked=excluded.malware_blocked, denylisted=excluded.denylisted,
			gates_json=excluded.gates_json`)
	if err != nil {
		return err
	}
	defer dstmt.Close()
	for _, d := range daily {
		gb, err := json.Marshal(d.Gates)
		if err != nil {
			return err
		}
		if _, err := dstmt.Exec(
			d.Day, d.Requests, d.CacheHits, d.Blocked, d.Errors,
			d.SupplyBlocked, d.CVEBlocked, d.MalwareBlocked, d.Denylisted, string(gb),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
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

func (r *sqliteRepo) LoadState(eventLimit int) (State, error) {
	var st State

	// counters (single row)
	var gatesJSON string
	var snap Snapshot
	err := r.db.QueryRow(`
		SELECT requests, cache_hits, blocked, errors, supply_blocked,
		       cve_blocked, malware_blocked, denylisted, gates_json
		FROM counters WHERE id = 1`).Scan(
		&snap.Requests, &snap.CacheHits, &snap.Blocked, &snap.Errors,
		&snap.SupplyBlocked, &snap.CVEBlocked, &snap.MalwareBlocked,
		&snap.Denylisted, &gatesJSON)
	switch {
	case err == sql.ErrNoRows:
		// fresh DB — leave HasLifetime false
	case err != nil:
		return st, fmt.Errorf("loading counters: %w", err)
	default:
		snap.Gates = parseGates(gatesJSON)
		st.Lifetime = snap
		st.HasLifetime = true
	}

	// today's daily row
	today := time.Now().UTC().Format("2006-01-02")
	d, err := r.dailyRow(today)
	if err != nil {
		return st, err
	}
	st.Today = d

	// recent events, oldest first
	if eventLimit < 1 {
		eventLimit = 1
	}
	rows, err := r.db.Query(`SELECT detail_json FROM events ORDER BY ts DESC, id DESC LIMIT ?`, eventLimit)
	if err != nil {
		return st, fmt.Errorf("loading events: %w", err)
	}
	defer rows.Close()
	var newestFirst []proxy.Event
	for rows.Next() {
		var blob string
		if err := rows.Scan(&blob); err != nil {
			return st, err
		}
		var ev proxy.Event
		if err := json.Unmarshal([]byte(blob), &ev); err != nil {
			continue // skip a corrupt row rather than fail the whole load
		}
		newestFirst = append(newestFirst, ev)
	}
	if err := rows.Err(); err != nil {
		return st, err
	}
	// reverse to oldest-first for ring-buffer replay
	st.Events = make([]proxy.Event, 0, len(newestFirst))
	for i := len(newestFirst) - 1; i >= 0; i-- {
		st.Events = append(st.Events, newestFirst[i])
	}
	return st, nil
}

func (r *sqliteRepo) dailyRow(day string) (*DailyMetric, error) {
	var d DailyMetric
	var gatesJSON string
	err := r.db.QueryRow(`
		SELECT day, requests, cache_hits, blocked, errors, supply_blocked,
		       cve_blocked, malware_blocked, denylisted, gates_json
		FROM daily_metrics WHERE day = ?`, day).Scan(
		&d.Day, &d.Requests, &d.CacheHits, &d.Blocked, &d.Errors,
		&d.SupplyBlocked, &d.CVEBlocked, &d.MalwareBlocked, &d.Denylisted, &gatesJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d.Gates = parseGates(gatesJSON)
	return &d, nil
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/telemetry/ -run TestSQLiteRepo -v`
Expected: PASS. Then `go test ./internal/telemetry/`, `go build ./...`, `go vet ./internal/telemetry/` clean.

- [ ] **Step 5: Commit**

```bash
git add internal/telemetry/sqlite.go internal/telemetry/sqlite_test.go
git commit -m "feat(telemetry): SQLite repo (events, counters, daily metrics)"
```

---

## Task 5: persist the Store (load on start, async writer, flush, close)

**Files:**
- Modify: `internal/telemetry/store.go`
- Test: `internal/telemetry/store_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/telemetry/store_test.go` (package `telemetry_test` form shown; adapt qualifier if internal):

```go
func TestPersistentStore_SeedsFromRepoAndPersists(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo, err := telemetry.NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)

	// First store: record, then close (final flush).
	s1, err := telemetry.NewPersistentStore(100, repo, zerolog.Nop())
	require.NoError(t, err)
	now := time.Now().UTC()
	s1.Record(proxy.Event{Time: now, Verdict: proxy.VerdictCache, Gate: proxy.GateCache})
	s1.Record(proxy.Event{Time: now, Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply, Reason: "x",
		Ecosystem: "npm", Package: "p", Version: "1", BlockUntil: now.Add(time.Hour)})
	require.NoError(t, s1.Close())

	// Second store on the SAME db: counters, daily, events, quarantine restored.
	s2, err := telemetry.NewPersistentStore(100, repo, zerolog.Nop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s2.Close() })

	snap := s2.Snapshot()
	assert.Equal(t, uint64(2), snap.Requests)
	assert.Equal(t, uint64(1), snap.CacheHits)
	assert.Equal(t, uint64(1), snap.Blocked)

	require.Len(t, s2.Recent(0), 2)

	q := s2.Quarantine(now)
	require.Len(t, q, 1)
	assert.Equal(t, "p", q[0].Package)

	daily, err := s2.DailyMetrics(0)
	require.NoError(t, err)
	require.Len(t, daily, 1)
	assert.Equal(t, uint64(2), daily[0].Requests)
}

func TestPersistentStore_CloseIdempotent(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo, err := telemetry.NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)
	s, err := telemetry.NewPersistentStore(10, repo, zerolog.Nop())
	require.NoError(t, err)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close()) // second close is a no-op
}
```

Add imports to the test file as needed: `path/filepath`, `github.com/rs/zerolog`, `github.com/ggwpLab/Jo-ei/internal/storage`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/telemetry/ -run TestPersistentStore -v`
Expected: compile failure — `undefined: telemetry.NewPersistentStore`.

- [ ] **Step 3: Implement**

In `internal/telemetry/store.go`:

3a. Add imports: `"github.com/rs/zerolog"`. (Keep `sort`, `sync`, `time`, `proxy`.)

3b. Add fields to the `Store` struct (after `daily`):

```go
	// Persistence (nil repo ⇒ in-memory only).
	repo      Repo
	logger    zerolog.Logger
	eventCh   chan proxy.Event
	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	flushEvery time.Duration
```

3c. Add the constructor and constants after `NewStore`:

```go
const (
	persistFlushInterval = 10 * time.Second
	persistEventBuffer   = 1024
)

// NewPersistentStore creates a Store backed by repo: it seeds in-memory state
// from repo.LoadState, then runs a background writer that batches event inserts
// and periodically flushes counters + daily rows. Close performs a final flush.
func NewPersistentStore(capacity int, repo Repo, logger zerolog.Logger) (*Store, error) {
	s := NewStore(capacity)
	s.repo = repo
	s.logger = logger
	s.eventCh = make(chan proxy.Event, persistEventBuffer)
	s.stop = make(chan struct{})
	s.flushEvery = persistFlushInterval

	state, err := repo.LoadState(capacity)
	if err != nil {
		return nil, fmt.Errorf("loading telemetry state: %w", err)
	}
	s.seed(state)

	s.wg.Add(1)
	go s.writer()
	return s, nil
}

// seed loads persisted state into the in-memory model without re-counting.
func (s *Store) seed(state State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.HasLifetime {
		s.lifetime = aggregateFromSnapshot(state.Lifetime)
	}
	if state.Today != nil {
		s.daily[state.Today.Day] = aggregateFromDaily(*state.Today)
	}
	for _, ev := range state.Events { // oldest first
		s.buf[s.next] = ev
		s.next = (s.next + 1) % len(s.buf)
		if s.count < len(s.buf) {
			s.count++
		}
	}
}
```

3d. Add `fmt` to imports (used by NewPersistentStore). Add the aggregate-from-persisted helpers (after the `aggregate` methods):

```go
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
```

3e. In `Record`, after the in-memory update (still inside the method but AFTER `s.mu.Unlock()` — so change `defer s.mu.Unlock()` to an explicit unlock), enqueue for persistence. Replace the `Record` body from Task 2 with:

```go
func (s *Store) Record(ev proxy.Event) {
	s.mu.Lock()
	s.buf[s.next] = ev
	s.next = (s.next + 1) % len(s.buf)
	if s.count < len(s.buf) {
		s.count++
	}
	s.lifetime.record(ev)
	day := dayKey(ev)
	d := s.daily[day]
	if d == nil {
		d = newAggregate()
		s.daily[day] = d
	}
	d.record(ev)
	s.mu.Unlock()

	if s.repo != nil {
		select {
		case s.eventCh <- ev:
		default: // queue full: event is counted in memory; skip persistence
		}
	}
}
```

3f. Update `DailyMetrics` to prefer the repo (full history from DB):

```go
func (s *Store) DailyMetrics(days int) ([]DailyMetric, error) {
	if s.repo != nil {
		return s.repo.DailyMetrics(days)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DailyMetric, 0, len(s.daily))
	for day, a := range s.daily {
		out = append(out, a.dailyMetric(day))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day > out[j].Day })
	if days > 0 && len(out) > days {
		out = out[:days]
	}
	return out, nil
}
```

3g. Add the writer loop and Close at the end of the file:

```go
// inMemoryDaily returns all in-memory day buckets as DailyMetric (for flushing).
func (s *Store) inMemoryDaily() []DailyMetric {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DailyMetric, 0, len(s.daily))
	for day, a := range s.daily {
		out = append(out, a.dailyMetric(day))
	}
	return out
}

// evictOldDaily drops in-memory day buckets other than today after they are
// durably flushed, bounding memory for long-running processes.
func (s *Store) evictOldDaily() {
	today := time.Now().UTC().Format("2006-01-02")
	s.mu.Lock()
	defer s.mu.Unlock()
	for day := range s.daily {
		if day != today {
			delete(s.daily, day)
		}
	}
}

func (s *Store) flush(pending []proxy.Event) {
	if len(pending) > 0 {
		if err := s.repo.AppendEvents(pending); err != nil {
			s.logger.Warn().Err(err).Msg("telemetry: persisting events")
		}
	}
	if err := s.repo.Flush(s.Snapshot(), s.inMemoryDaily()); err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: flushing counters/daily")
	}
	if err := s.repo.Prune(); err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: pruning")
	}
	s.evictOldDaily()
}

func (s *Store) writer() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.flushEvery)
	defer ticker.Stop()
	var pending []proxy.Event
	for {
		select {
		case <-s.stop:
			// drain queued events, then final flush
			for {
				select {
				case ev := <-s.eventCh:
					pending = append(pending, ev)
					continue
				default:
				}
				break
			}
			s.flush(pending)
			return
		case ev := <-s.eventCh:
			pending = append(pending, ev)
		case <-ticker.C:
			s.flush(pending)
			pending = pending[:0]
		}
	}
}

// Close stops the writer after a final flush. Safe to call once; extra calls are
// no-ops. In-memory-only stores (no repo) need no Close, but calling it is safe.
func (s *Store) Close() error {
	if s.repo == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
	})
	return nil
}
```

> Note: after a `ticker.C` flush, `pending` is reset; after the `stop` drain flush, the goroutine returns. The `flush` reads `Snapshot()`/`inMemoryDaily()` which take their own locks — do not hold `s.mu` across `flush`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/telemetry/ -v`
Expected: PASS (all: existing, daily, sqlite repo, persistent store). `go build ./...`, `go vet ./internal/telemetry/` clean. (`-race` only on CI/Linux.)

- [ ] **Step 5: Commit**

```bash
git add internal/telemetry/store.go internal/telemetry/store_test.go
git commit -m "feat(telemetry): persistent store with async writer and flush"
```

---

## Task 6: config DatabaseConfig

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/config/config_test.go`:

```go
func TestValidate_RejectsNegativeRetention(t *testing.T) {
	c := &config.Config{}
	c.Database.EventRetentionDays = -1
	require.Error(t, c.Validate())

	c2 := &config.Config{}
	c2.Database.DailyRetentionDays = -5
	require.Error(t, c2.Validate())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestValidate_RejectsNegativeRetention -v`
Expected: compile failure — `c.Database undefined`.

- [ ] **Step 3: Implement**

In `internal/config/config.go`:

3a. Add field to `Config`:
```go
	Database    DatabaseConfig    `mapstructure:"database"`
```

3b. Add the type near the other config structs:
```go
// DatabaseConfig configures the embedded SQLite persistence layer. An empty Path
// disables persistence (telemetry runs in-memory only). Retention values ≤ 0 use
// defaults (events 30 days, daily metrics 365 days).
type DatabaseConfig struct {
	Path               string `mapstructure:"path"`
	EventRetentionDays int    `mapstructure:"event_retention_days"`
	DailyRetentionDays int    `mapstructure:"daily_retention_days"`
}
```

3c. In `Validate()`, before the final `return nil`:
```go
	if c.Database.EventRetentionDays < 0 {
		return fmt.Errorf("database.event_retention_days must not be negative")
	}
	if c.Database.DailyRetentionDays < 0 {
		return fmt.Errorf("database.daily_retention_days must not be negative")
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS. `go build ./...`, `go vet ./internal/config/` clean.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): database path and retention settings"
```

---

## Task 7: console GET /api/metrics/daily

**Files:**
- Modify: `internal/console/server.go`
- Test: `internal/console/server_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/console/server_test.go`:

```go
func TestDailyMetrics(t *testing.T) {
	f := newFixture(t)
	// seed two days via the store
	f.store.Record(proxy.Event{Time: time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC), Verdict: proxy.VerdictCache, Gate: proxy.GateCache})
	f.store.Record(proxy.Event{Time: time.Date(2026, 1, 2, 1, 0, 0, 0, time.UTC), Verdict: proxy.VerdictCache, Gate: proxy.GateCache})

	var body struct {
		Daily []telemetry.DailyMetric `json:"daily"`
	}
	code := getJSON(t, f.srv.URL+"/api/metrics/daily?days=1", &body)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, body.Daily, 1)
	assert.Equal(t, "2026-01-02", body.Daily[0].Day) // newest first, limited to 1
}

func TestDailyMetrics_InvalidDays(t *testing.T) {
	f := newFixture(t)
	var body map[string]any
	code := getJSON(t, f.srv.URL+"/api/metrics/daily?days=abc", &body)
	assert.Equal(t, http.StatusBadRequest, code)
}
```

(The fixture's `f.store` is the `*telemetry.Store` used to build the handler. If `newFixture` does not currently expose `store`, it already constructs one for `Store:` — capture it on the fixture struct. Match the existing fixture pattern; the `telemetry` import already exists in this test file.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/console/ -run TestDailyMetrics -v`
Expected: 404/route-missing failure (or compile error if `f.store` isn't exposed — expose it).

- [ ] **Step 3: Implement**

In `internal/console/server.go`:

3a. Register the route in `NewHandler` (next to the other `GET /api/...` routes):
```go
	mux.HandleFunc("GET /api/metrics/daily", s.dailyMetrics)
```

3b. Add the handler (place near `overview`):
```go
// dailyMetrics serves per-UTC-day telemetry tallies. ?days=N (default 30) limits
// the window; the store reads from persistent storage when configured.
func (s *server) dailyMetrics(w http.ResponseWriter, r *http.Request) {
	days := 30
	if q := r.URL.Query().Get("days"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 {
			s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_days"})
			return
		}
		if n > 365 {
			n = 365
		}
		days = n
	}
	daily, err := s.cfg.Store.DailyMetrics(days)
	if err != nil {
		s.cfg.Logger.Error().Err(err).Msg("console: daily metrics")
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "metrics_unavailable"})
		return
	}
	if daily == nil {
		daily = []telemetry.DailyMetric{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"daily": daily})
}
```

(`strconv` and `telemetry` are already imported in server.go — verify; the overview/requests handlers use both.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/console/ -v`
Expected: PASS (all). `go build ./...`, `go vet ./internal/console/` clean.

- [ ] **Step 5: Commit**

```bash
git add internal/console/server.go internal/console/server_test.go
git commit -m "feat(console): GET /api/metrics/daily endpoint"
```

---

## Task 8: wire persistence into main

**Files:**
- Modify: `cmd/jo-ei/main.go`

Wiring code verified by Task 9's integration test.

- [ ] **Step 1: Read `cmd/jo-ei/main.go`** to confirm current shape: the imports block, `store := telemetry.NewStore(eventHistorySize)` (~line 124), and the deferred-cleanup style (e.g. `defer func() { _ = artifactCache.Close() }()`).

- [ ] **Step 2: Add imports**

Add to the import block:
```go
	"github.com/ggwpLab/Jo-ei/internal/storage"
```
(`telemetry` and `zerolog`/`logger` are already present.)

- [ ] **Step 3: Replace store construction with persistence + degrade-on-error**

Replace:
```go
	store := telemetry.NewStore(eventHistorySize)
```
with:
```go
	store := buildTelemetryStore(cfg, logger)
```

- [ ] **Step 4: Add the helper**

Add near the other helpers at the bottom of `main.go`:
```go
// buildTelemetryStore returns a persistent telemetry Store when a database path
// is configured, falling back to in-memory on any error (telemetry must never
// block the proxy). A persistent store's Close (final flush) is deferred here.
func buildTelemetryStore(cfg *config.Config, logger zerolog.Logger) *telemetry.Store {
	if cfg.Database.Path == "" {
		return telemetry.NewStore(eventHistorySize)
	}
	sdb, err := storage.Open(cfg.Database.Path)
	if err != nil {
		logger.Warn().Err(err).Str("path", cfg.Database.Path).
			Msg("telemetry persistence disabled — could not open database; running in-memory")
		return telemetry.NewStore(eventHistorySize)
	}
	repo, err := telemetry.NewSQLiteRepo(sdb, cfg.Database.EventRetentionDays, cfg.Database.DailyRetentionDays)
	if err != nil {
		logger.Warn().Err(err).Msg("telemetry persistence disabled — schema init failed; running in-memory")
		_ = sdb.Close()
		return telemetry.NewStore(eventHistorySize)
	}
	store, err := telemetry.NewPersistentStore(eventHistorySize, repo, logger)
	if err != nil {
		logger.Warn().Err(err).Msg("telemetry persistence disabled — state load failed; running in-memory")
		_ = sdb.Close()
		return telemetry.NewStore(eventHistorySize)
	}
	logger.Info().Str("path", cfg.Database.Path).Msg("telemetry persistence enabled")
	return store
}
```

> **Shutdown flush:** `buildTelemetryStore` can't `defer` across `run`'s scope. Instead, in `run`, right after the assignment `store := buildTelemetryStore(cfg, logger)`, add:
> ```go
> 	defer func() { _ = store.Close() }()
> ```
> `Store.Close()` is a no-op for in-memory stores and performs the final flush for persistent ones. The underlying `*storage.DB` is closed by the OS on exit; since `SetMaxOpenConns(1)` + WAL checkpoint on close is handled by the driver, an explicit DB close is not required for correctness, but if you prefer symmetry you may keep a reference and close it after `store.Close()`. Keep it simple: rely on `store.Close()` for the flush.

(Confirm `config` is imported in main.go — it is, used throughout.)

- [ ] **Step 5: Verify**

Run: `go build ./...`, `go vet ./...`, `go test ./...`
Expected: all clean/pass. Do NOT run `-race` (cgo unavailable on Windows; CI runs it).

- [ ] **Step 6: Commit**

```bash
git add cmd/jo-ei/main.go
git commit -m "feat(cmd): wire persistent telemetry store with in-memory fallback"
```

---

## Task 9: integration — restart restores telemetry

**Files:**
- Create: `integration/telemetry_persistence_test.go`

- [ ] **Step 1: Write the test**

Create `integration/telemetry_persistence_test.go`:

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

	// First "process": record and close (final flush).
	{
		db, err := storage.Open(path)
		require.NoError(t, err)
		repo, err := telemetry.NewSQLiteRepo(db, 30, 365)
		require.NoError(t, err)
		s, err := telemetry.NewPersistentStore(500, repo, zerolog.Nop())
		require.NoError(t, err)
		s.Record(proxy.Event{Time: now, Verdict: proxy.VerdictCache, Gate: proxy.GateCache})
		s.Record(proxy.Event{Time: now, Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply,
			Reason: "package_younger_than_min_age", Ecosystem: "npm", Package: "p", Version: "1",
			BlockUntil: now.Add(time.Hour)})
		require.NoError(t, s.Close())
		require.NoError(t, db.Close())
	}

	// Second "process": reopen the same file, state restored.
	db, err := storage.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo, err := telemetry.NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)
	s, err := telemetry.NewPersistentStore(500, repo, zerolog.Nop())
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

- [ ] **Step 2: Run the test**

Run: `go test -tags integration ./integration/ -run TestTelemetryPersistsAcrossRestart -v`
Expected: PASS. Then the whole integration suite: `go test -tags integration ./integration/` → all PASS.

- [ ] **Step 3: Commit**

```bash
git add integration/telemetry_persistence_test.go
git commit -m "test(integration): telemetry persists across restart"
```

---

## Task 10: documentation

**Files:**
- Modify: `config.yaml`
- Modify: `README.md`

- [ ] **Step 1: Add the database block to config.yaml**

Add after the `cache:` block (or near other storage config), matching the file's comment style:
```yaml
# Persistent state (optional). Stores telemetry — event history, lifetime
# counters and per-day metrics — in an embedded SQLite database so they survive
# restarts. Empty path (the default) keeps telemetry in memory only.
database:
  path: "/var/lib/jo-ei/jo-ei.db"
  # event_retention_days: 30    # prune persisted events older than this
  # daily_retention_days: 365   # prune per-day metric rows older than this
```

> Decide whether to ship `path` set or commented. To keep existing deployments
> in-memory by default, COMMENT the whole block (prefix each line with `# `)
> except keep it discoverable. Match how `cache`/`console` optional blocks are
> presented in this file — if those ship active, ship `database:` active with
> the default path; if they ship commented, comment it. Pick one consistently
> and note which in the commit message.

- [ ] **Step 2: Document in README.md**

In the Admin Console / telemetry area, add a subsection (heading level matching siblings, e.g. `###`):
```markdown
### Persistent telemetry

By default the request feed, KPI counters and quarantine list live in memory and
reset on restart. Set `database.path` to an embedded SQLite file to persist them
across restarts, along with **per-calendar-day metrics** exposed at
`GET /api/metrics/daily?days=N` (default 30, max 365, newest first).

The proxy hot path never does synchronous database I/O: counters update in
memory, events are written asynchronously, and aggregates flush every 10s and on
graceful shutdown. If the database cannot be opened, Jōei logs a warning and runs
in-memory only — persistence never blocks the proxy.

Retention is configurable via `database.event_retention_days` (default 30) and
`database.daily_retention_days` (default 365).
```

- [ ] **Step 3: Verify build (sanity)**

Run: `go build ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add config.yaml README.md
git commit -m "docs: document persistent telemetry and database config"
```

---

## Final verification

- [ ] `go build ./...` — clean
- [ ] `go vet ./...` — clean
- [ ] `go test ./...` — all green
- [ ] `go test -tags integration ./integration/` — all green
- [ ] `gofmt -w` on every touched `.go` file (Windows CRLF masks gofmt locally; CI on Linux/LF is authoritative — run `gofmt -w` on changed files and commit any reformatting BEFORE pushing). golangci-lint v2 errcheck flags unchecked `tx.Rollback`/`stmt.Close`/`Fprintln`/`Write`/`db.Exec` returns — the code above wraps or `_ =`-discards them deliberately; verify no new unchecked returns slipped in.
- [ ] Push branch, open PR into **develop** (not main).
```
