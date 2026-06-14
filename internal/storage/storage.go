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
