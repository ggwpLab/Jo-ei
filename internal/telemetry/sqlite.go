package telemetry

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
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
`, `
CREATE INDEX IF NOT EXISTS idx_events_verdict_ts_id ON events(verdict, ts, id);
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

func (r *sqliteRepo) Page(verdict string, cursor Cursor, limit int) ([]proxy.Event, Cursor, error) {
	var (
		conds []string
		args  []any
	)
	if verdict != "" {
		conds = append(conds, "verdict = ?")
		args = append(args, verdict)
	}
	if !cursor.Zero() {
		// Keyset: rows strictly older than the cursor under (ts DESC, id DESC).
		conds = append(conds, "(ts < ? OR (ts = ? AND id < ?))")
		args = append(args, cursor.TS.UnixNano(), cursor.TS.UnixNano(), cursor.ID)
	}
	query := "SELECT id, ts, detail_json FROM events"
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += " ORDER BY ts DESC, id DESC"
	if limit > 0 {
		// Fetch one extra row (the sentinel) to detect whether a next page
		// exists, without requiring a second COUNT query.
		query += " LIMIT ?"
		args = append(args, limit+1)
	}

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, Cursor{}, err
	}
	defer rows.Close()

	var (
		out     []proxy.Event
		next    Cursor
		scanned int
	)
	for rows.Next() {
		var (
			id     int64
			tsNano int64
			blob   string
		)
		if err := rows.Scan(&id, &tsNano, &blob); err != nil {
			return nil, Cursor{}, err
		}
		scanned++
		// The (limit+1)th row is the look-ahead sentinel: it confirms there is
		// a next page but must not be included in the output.
		if limit > 0 && scanned > limit {
			break
		}
		// Advance the cursor for every scanned row (even one that fails to
		// unmarshal) so paging never stalls on a single bad blob.
		next = Cursor{TS: time.Unix(0, tsNano), ID: id}
		var ev proxy.Event
		if err := json.Unmarshal([]byte(blob), &ev); err != nil {
			continue
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, Cursor{}, err
	}
	// If we saw fewer rows than the look-ahead limit, we reached the end.
	if limit > 0 && scanned <= limit {
		next = Cursor{}
	}
	return out, next, nil
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
