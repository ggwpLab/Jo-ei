package storage_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/storage/storagetest"
)

func TestOpen_CreatesDirAndDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "jo-ei.db")
	db, err := storage.Open(path)
	require.NoError(t, err)
	defer db.Close()
	var mode string
	require.NoError(t, db.SQL().QueryRow("PRAGMA journal_mode").Scan(&mode))
	assert.Equal(t, "wal", mode)
}

func TestApplyMigrations_IdempotentAndVersioned(t *testing.T) {
	path := filepath.Join(storagetest.TempDir(t), "jo-ei.db")
	db, err := storage.Open(path)
	require.NoError(t, err)
	defer db.Close()

	steps := []string{
		`CREATE TABLE t1 (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE t2 (id INTEGER PRIMARY KEY)`,
	}
	require.NoError(t, db.ApplyMigrations("demo", steps))
	require.NoError(t, db.ApplyMigrations("demo", steps)) // second apply = no-op, must not error

	for _, tbl := range []string{"t1", "t2"} {
		var name string
		err := db.SQL().QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&name)
		require.NoError(t, err, "table %s should exist", tbl)
	}

	steps = append(steps, `CREATE TABLE t3 (id INTEGER PRIMARY KEY)`)
	require.NoError(t, db.ApplyMigrations("demo", steps))
	var n int
	require.NoError(t, db.SQL().QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='t3'`).Scan(&n))
	assert.Equal(t, 1, n)
}
