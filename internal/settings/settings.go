// Package settings persists small, runtime-editable config groups (policy,
// registries) as key→JSON blobs in the shared SQLite database. The DB is the
// source of truth after first seed; callers own their JSON shapes so policy and
// config never import this package's storage dependency.
package settings

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/storage"
)

// Store reads and writes opaque JSON values keyed by name.
type Store struct {
	db *storage.DB
}

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS settings (
		key        TEXT PRIMARY KEY,
		value      TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	)`,
}

// New runs the settings migration on db and returns a Store.
func New(db *storage.DB) (*Store, error) {
	if err := db.ApplyMigrations("settings", migrations); err != nil {
		return nil, fmt.Errorf("settings migrations: %w", err)
	}
	return &Store{db: db}, nil
}

// Get returns the stored value for key. ok is false when the key is absent.
func (s *Store) Get(key string) ([]byte, bool, error) {
	var v string
	err := s.db.SQL().QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading setting %q: %w", key, err)
	}
	return []byte(v), true, nil
}

// Put writes value for key, overwriting any existing value.
func (s *Store) Put(key string, value []byte) error {
	_, err := s.db.SQL().Exec(
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, string(value), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("writing setting %q: %w", key, err)
	}
	return nil
}
