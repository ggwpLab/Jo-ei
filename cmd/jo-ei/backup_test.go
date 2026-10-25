package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

func seededDB(t *testing.T) (string, *storage.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jo-ei.db")
	db, err := storage.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	st, err := settings.New(db)
	require.NoError(t, err)
	require.NoError(t, st.Put("marker", []byte("before")))
	return path, db
}

func readSetting(t *testing.T, path, key string) string {
	t.Helper()
	db, err := storage.Open(path)
	require.NoError(t, err)
	defer db.Close()
	st, err := settings.New(db)
	require.NoError(t, err)
	v, ok, err := st.Get(key)
	require.NoError(t, err)
	require.True(t, ok, "key %q missing from backup", key)
	return string(v)
}

func TestBackup_CopiesData(t *testing.T) {
	path, _ := seededDB(t)
	out := filepath.Join(t.TempDir(), "backup.db")

	require.NoError(t, backupDatabase(path, out))

	assert.Equal(t, "before", readSetting(t, out, "marker"))
}

// The server keeps the database open and writing; the copy must still be
// consistent and include what was committed.
func TestBackup_WhileOpenElsewhere(t *testing.T) {
	path, live := seededDB(t)
	st, err := settings.New(live)
	require.NoError(t, err)
	require.NoError(t, st.Put("marker", []byte("committed-while-running")))
	out := filepath.Join(t.TempDir(), "backup.db")

	require.NoError(t, backupDatabase(path, out))

	assert.Equal(t, "committed-while-running", readSetting(t, out, "marker"))
}

func TestBackup_RefusesExistingOutput(t *testing.T) {
	path, _ := seededDB(t)
	out := filepath.Join(t.TempDir(), "backup.db")
	require.NoError(t, os.WriteFile(out, []byte("keep me"), 0o600))

	err := backupDatabase(path, out)

	require.Error(t, err)
	b, _ := os.ReadFile(out)
	assert.Equal(t, "keep me", string(b))
}

func TestBackup_MissingDatabase(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.db")
	err := backupDatabase(missing, filepath.Join(t.TempDir(), "out.db"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), missing)
	_, statErr := os.Stat(missing)
	assert.True(t, os.IsNotExist(statErr), "backup must not create the source database")
}

// The backup holds the console's password hashes and the session signing key.
func TestBackup_OwnerOnly(t *testing.T) {
	path, _ := seededDB(t)
	out := filepath.Join(t.TempDir(), "backup.db")

	require.NoError(t, backupDatabase(path, out))

	info, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestBackup_MissingOutputDirNamed(t *testing.T) {
	path, _ := seededDB(t)
	dir := filepath.Join(t.TempDir(), "no-such-dir")

	err := backupDatabase(path, filepath.Join(dir, "backup.db"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), dir)
}
