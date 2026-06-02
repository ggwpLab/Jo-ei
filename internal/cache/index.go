package cache

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS artifacts (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	ecosystem    TEXT    NOT NULL,
	name         TEXT    NOT NULL,
	version      TEXT    NOT NULL,
	file_path    TEXT    NOT NULL,
	scan_clean   INTEGER NOT NULL DEFAULT 0,
	scan_json    TEXT    NOT NULL DEFAULT '',
	stored_at    INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	last_hit     INTEGER NOT NULL DEFAULT 0,
	hit_count    INTEGER NOT NULL DEFAULT 0,
	size_bytes   INTEGER NOT NULL DEFAULT 0,
	UNIQUE(ecosystem, name, version)
);
CREATE INDEX IF NOT EXISTS idx_last_hit ON artifacts(last_hit);
`

// Index manages the SQLite-backed metadata index for the local cache.
type Index struct {
	db *sql.DB
}

// NewIndex opens (or creates) a SQLite database at path and applies the schema.
func NewIndex(path string) (*Index, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db at %q: %w", path, err)
	}
	db.SetMaxOpenConns(1) // SQLite: single writer
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("running schema: %w", err)
	}
	return &Index{db: db}, nil
}

// Close releases the database connection.
func (idx *Index) Close() error {
	return idx.db.Close()
}

// Insert adds or updates a cache entry (UPSERT semantics).
func (idx *Index) Insert(ref *proxy.PackageRef, entry *CacheEntry) error {
	_, err := idx.db.Exec(`
		INSERT INTO artifacts
			(ecosystem, name, version, file_path, scan_clean, scan_json,
			 stored_at, expires_at, last_hit, hit_count, size_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ecosystem, name, version) DO UPDATE SET
			file_path  = excluded.file_path,
			scan_clean = excluded.scan_clean,
			scan_json  = excluded.scan_json,
			stored_at  = excluded.stored_at,
			expires_at = excluded.expires_at,
			last_hit   = excluded.last_hit,
			size_bytes = excluded.size_bytes`,
		ref.Ecosystem, ref.Name, ref.Version,
		entry.ArtifactPath, boolToInt(entry.ScanClean), entry.ScanJSON,
		entry.StoredAt.Unix(), entry.ExpiresAt.Unix(),
		entry.StoredAt.Unix(), 0, entry.SizeBytes,
	)
	return err
}

// Get retrieves a cache entry. Returns (nil, false) if not found or expired.
func (idx *Index) Get(ref *proxy.PackageRef) (*CacheEntry, bool) {
	row := idx.db.QueryRow(`
		SELECT file_path, scan_clean, scan_json, stored_at, expires_at, hit_count, size_bytes
		FROM artifacts
		WHERE ecosystem=? AND name=? AND version=?`,
		ref.Ecosystem, ref.Name, ref.Version,
	)

	var (
		entry         CacheEntry
		scanCleanInt  int
		storedAtUnix  int64
		expiresAtUnix int64
	)
	err := row.Scan(
		&entry.ArtifactPath, &scanCleanInt, &entry.ScanJSON,
		&storedAtUnix, &expiresAtUnix,
		&entry.HitCount, &entry.SizeBytes,
	)
	if err == sql.ErrNoRows {
		return nil, false
	}
	if err != nil {
		return nil, false
	}

	entry.ScanClean = scanCleanInt == 1
	entry.StoredAt = time.Unix(storedAtUnix, 0).UTC()
	entry.ExpiresAt = time.Unix(expiresAtUnix, 0).UTC()

	if entry.IsExpired() {
		return nil, false
	}
	return &entry, true
}

// IncrementHit bumps the hit counter and updates last_hit timestamp.
func (idx *Index) IncrementHit(ref *proxy.PackageRef) error {
	_, err := idx.db.Exec(`
		UPDATE artifacts SET hit_count=hit_count+1, last_hit=?
		WHERE ecosystem=? AND name=? AND version=?`,
		time.Now().Unix(), ref.Ecosystem, ref.Name, ref.Version,
	)
	return err
}

// Delete removes an entry from the index.
func (idx *Index) Delete(ref *proxy.PackageRef) error {
	_, err := idx.db.Exec(
		`DELETE FROM artifacts WHERE ecosystem=? AND name=? AND version=?`,
		ref.Ecosystem, ref.Name, ref.Version,
	)
	return err
}

// LRUCandidates returns up to n entries sorted by last_hit ascending (LRU first).
func (idx *Index) LRUCandidates(n int) ([]proxy.PackageRef, error) {
	rows, err := idx.db.Query(
		`SELECT ecosystem, name, version FROM artifacts ORDER BY last_hit ASC LIMIT ?`, n,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []proxy.PackageRef
	for rows.Next() {
		var ref proxy.PackageRef
		if err := rows.Scan(&ref.Ecosystem, &ref.Name, &ref.Version); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

// TotalSizeBytes returns the sum of size_bytes for all entries.
func (idx *Index) TotalSizeBytes() (int64, error) {
	var total int64
	err := idx.db.QueryRow(`SELECT COALESCE(SUM(size_bytes),0) FROM artifacts`).Scan(&total)
	return total, err
}

// Count returns the total number of entries in the index.
func (idx *Index) Count() (int64, error) {
	var n int64
	err := idx.db.QueryRow(`SELECT COUNT(*) FROM artifacts`).Scan(&n)
	return n, err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
