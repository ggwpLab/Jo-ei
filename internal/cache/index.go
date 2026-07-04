package cache

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// classifier distinguishes secondary artifacts (Maven sources/javadoc jars)
// that share the same coordinates. It is part of the uniqueness key so the main
// jar and its classifier siblings get separate cache rows instead of colliding.
const schema = `
CREATE TABLE IF NOT EXISTS artifacts (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	ecosystem    TEXT    NOT NULL,
	name         TEXT    NOT NULL,
	version      TEXT    NOT NULL,
	classifier   TEXT    NOT NULL DEFAULT '',
	file_path    TEXT    NOT NULL,
	scan_clean   INTEGER NOT NULL DEFAULT 0,
	scan_json    TEXT    NOT NULL DEFAULT '',
	stored_at    INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	last_hit     INTEGER NOT NULL DEFAULT 0,
	hit_count    INTEGER NOT NULL DEFAULT 0,
	size_bytes   INTEGER NOT NULL DEFAULT 0,
	last_validated INTEGER NOT NULL DEFAULT 0,
	UNIQUE(ecosystem, name, version, classifier)
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
	if err := migrateClassifier(db); err != nil {
		return nil, fmt.Errorf("migrating schema: %w", err)
	}
	if err := migrateLastValidated(db); err != nil {
		return nil, fmt.Errorf("migrating last_validated: %w", err)
	}
	return &Index{db: db}, nil
}

// migrateClassifier upgrades a pre-classifier database in place. Older tables
// were UNIQUE(ecosystem, name, version), which made Maven classifier jars
// collide with the main artifact. SQLite cannot widen a UNIQUE constraint via
// ALTER, so the table is rebuilt. No-op once the classifier column exists.
func migrateClassifier(db *sql.DB) error {
	has, err := hasColumn(db, "artifacts", "classifier")
	if err != nil {
		return err
	}
	if has {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rolled back unless Commit succeeds

	steps := []string{
		`ALTER TABLE artifacts RENAME TO artifacts_legacy`,
		`DROP INDEX IF EXISTS idx_last_hit`,
		// Re-create the current table + index from the canonical schema.
		schema,
		`INSERT INTO artifacts
			(ecosystem, name, version, classifier, file_path, scan_clean,
			 scan_json, stored_at, expires_at, last_hit, hit_count, size_bytes)
		 SELECT ecosystem, name, version, '', file_path, scan_clean,
			 scan_json, stored_at, expires_at, last_hit, hit_count, size_bytes
		 FROM artifacts_legacy`,
		`DROP TABLE artifacts_legacy`,
	}
	for _, stmt := range steps {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("migration step failed: %w", err)
		}
	}
	return tx.Commit()
}

// migrateLastValidated adds the re-validation timestamp column to a pre-existing
// database and backfills it from stored_at so old rows are treated as validated
// at store time rather than all immediately due. No-op once present and backfilled.
func migrateLastValidated(db *sql.DB) error {
	has, err := hasColumn(db, "artifacts", "last_validated")
	if err != nil {
		return err
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE artifacts ADD COLUMN last_validated INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	// Backfill rows that predate the column (last_validated == 0 is never a real
	// timestamp). Idempotent: a no-op once every row has a real value.
	if _, err := db.Exec(`UPDATE artifacts SET last_validated = stored_at WHERE last_validated = 0`); err != nil {
		return err
	}
	return nil
}

// hasColumn reports whether table has a column with the given name.
func hasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name, ctyp string
			notnull    int
			dfltValue  sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &ctyp, &notnull, &dfltValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// Close releases the database connection.
func (idx *Index) Close() error {
	return idx.db.Close()
}

// Insert adds or updates a cache entry (UPSERT semantics).
func (idx *Index) Insert(ref *gate.PackageRef, entry *CacheEntry) error {
	_, err := idx.db.Exec(`
		INSERT INTO artifacts
			(ecosystem, name, version, classifier, file_path, scan_clean, scan_json,
			 stored_at, expires_at, last_hit, hit_count, size_bytes, last_validated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ecosystem, name, version, classifier) DO UPDATE SET
			file_path      = excluded.file_path,
			scan_clean     = excluded.scan_clean,
			scan_json      = excluded.scan_json,
			stored_at      = excluded.stored_at,
			expires_at     = excluded.expires_at,
			last_hit       = excluded.last_hit,
			size_bytes     = excluded.size_bytes,
			last_validated = excluded.last_validated`,
		ref.Ecosystem, ref.Name, ref.Version, ref.Classifier,
		entry.ArtifactPath, boolToInt(entry.ScanClean), entry.ScanJSON,
		entry.StoredAt.Unix(), entry.ExpiresAt.Unix(),
		entry.StoredAt.Unix(), 0, entry.SizeBytes, entry.StoredAt.Unix(),
	)
	return err
}

// Get retrieves a cache entry. Returns (nil, false) if not found or expired.
func (idx *Index) Get(ref *gate.PackageRef) (*CacheEntry, bool) {
	row := idx.db.QueryRow(`
		SELECT file_path, scan_clean, scan_json, stored_at, expires_at, hit_count, size_bytes
		FROM artifacts
		WHERE ecosystem=? AND name=? AND version=? AND classifier=?`,
		ref.Ecosystem, ref.Name, ref.Version, ref.Classifier,
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
func (idx *Index) IncrementHit(ref *gate.PackageRef) error {
	_, err := idx.db.Exec(`
		UPDATE artifacts SET hit_count=hit_count+1, last_hit=?
		WHERE ecosystem=? AND name=? AND version=? AND classifier=?`,
		time.Now().Unix(), ref.Ecosystem, ref.Name, ref.Version, ref.Classifier,
	)
	return err
}

// Delete removes an entry from the index.
func (idx *Index) Delete(ref *gate.PackageRef) error {
	_, err := idx.db.Exec(
		`DELETE FROM artifacts WHERE ecosystem=? AND name=? AND version=? AND classifier=?`,
		ref.Ecosystem, ref.Name, ref.Version, ref.Classifier,
	)
	return err
}

// LRUCandidates returns up to n entries sorted by last_hit ascending (LRU first).
func (idx *Index) LRUCandidates(n int) ([]gate.PackageRef, error) {
	rows, err := idx.db.Query(
		`SELECT ecosystem, name, version, classifier FROM artifacts ORDER BY last_hit ASC LIMIT ?`, n,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []gate.PackageRef
	for rows.Next() {
		var ref gate.PackageRef
		if err := rows.Scan(&ref.Ecosystem, &ref.Name, &ref.Version, &ref.Classifier); err != nil {
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

// DueForRevalidation returns up to limit non-expired entries whose last_validated
// is older than `before` (a unix timestamp), oldest-first. Expired entries are
// excluded — they are dropped on access anyway.
func (idx *Index) DueForRevalidation(before int64, limit int) ([]RevalEntry, error) {
	now := time.Now().Unix()
	rows, err := idx.db.Query(`
		SELECT ecosystem, name, version, classifier, file_path, scan_clean, scan_json
		FROM artifacts
		WHERE last_validated < ? AND expires_at > ?
		ORDER BY last_validated ASC
		LIMIT ?`, before, now, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RevalEntry
	for rows.Next() {
		var (
			e            RevalEntry
			scanCleanInt int
		)
		if err := rows.Scan(
			&e.Ref.Ecosystem, &e.Ref.Name, &e.Ref.Version, &e.Ref.Classifier,
			&e.FilePath, &scanCleanInt, &e.ScanJSON,
		); err != nil {
			return nil, err
		}
		e.ScanClean = scanCleanInt == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// MarkValidated sets last_validated for ref to ts (a unix timestamp).
func (idx *Index) MarkValidated(ref *gate.PackageRef, ts int64) error {
	_, err := idx.db.Exec(
		`UPDATE artifacts SET last_validated = ? WHERE ecosystem=? AND name=? AND version=? AND classifier=?`,
		ts, ref.Ecosystem, ref.Name, ref.Version, ref.Classifier,
	)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
