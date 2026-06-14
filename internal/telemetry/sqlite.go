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

	today := time.Now().UTC().Format("2006-01-02")
	d, err := r.dailyRow(today)
	if err != nil {
		return st, err
	}
	st.Today = d

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
			continue
		}
		newestFirst = append(newestFirst, ev)
	}
	if err := rows.Err(); err != nil {
		return st, err
	}
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
