package cache

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

func TestMigrateCheckTimestampsFromLastValidated(t *testing.T) {
	// Build a pre-migration DB by hand: old schema with last_validated.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "index.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE artifacts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
		classifier TEXT NOT NULL DEFAULT '', file_path TEXT NOT NULL,
		scan_clean INTEGER NOT NULL DEFAULT 0, scan_json TEXT NOT NULL DEFAULT '',
		stored_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
		last_hit INTEGER NOT NULL DEFAULT 0, hit_count INTEGER NOT NULL DEFAULT 0,
		size_bytes INTEGER NOT NULL DEFAULT 0,
		last_validated INTEGER NOT NULL DEFAULT 0,
		UNIQUE(ecosystem, name, version, classifier))`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO artifacts
		(ecosystem, name, version, file_path, stored_at, expires_at, last_validated)
		VALUES ('pypi','a','1','/a',100,0,500), ('pypi','b','1','/b',200,0,0)`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	idx, err := NewIndex(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = idx.Close() })

	// Row a: backfilled from last_validated. Row b: last_validated was 0 → stored_at.
	ea, _ := idx.Get(&gate.PackageRef{Ecosystem: "pypi", Name: "a", Version: "1"})
	require.EqualValues(t, 500, ea.LastCVECheck.Unix())
	require.EqualValues(t, 500, ea.LastMalwareCheck.Unix())
	eb, _ := idx.Get(&gate.PackageRef{Ecosystem: "pypi", Name: "b", Version: "1"})
	require.EqualValues(t, 200, eb.LastCVECheck.Unix())

	// last_validated is gone.
	has, err := hasColumn(idx.db, "artifacts", "last_validated")
	require.NoError(t, err)
	require.False(t, has)
}
