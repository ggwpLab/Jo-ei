package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/storage/storagetest"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// runResetAdmin runs `jo-ei reset-admin-password` against a fresh config whose
// database lives at dbPath.
func runResetAdmin(t *testing.T, dbPath string) (stdout, stderr string, err error) {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte("database:\n  path: \""+filepath.ToSlash(dbPath)+"\"\n"), 0o600))
	prev := cfgFile
	cfgFile = cfg
	t.Cleanup(func() { cfgFile = prev })

	cmd := newResetAdminPasswordCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(nil)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

// withStore opens the database at dbPath, runs fn on its users store and
// closes it, so the command under test sees committed state.
func withStore(t *testing.T, dbPath string, fn func(*users.Store)) {
	t.Helper()
	sdb, err := storage.Open(dbPath)
	require.NoError(t, err)
	defer func() { _ = sdb.Close() }()
	st, err := users.New(sdb)
	require.NoError(t, err)
	fn(st)
}

var onePasswordLine = regexp.MustCompile(`^[A-Za-z0-9]{20}\n$`)

func TestResetAdminPassword_ResetsExistingAdmin(t *testing.T) {
	db := filepath.Join(storagetest.TempDir(t), "t.db")
	var before users.User
	withStore(t, db, func(st *users.Store) {
		require.NoError(t, st.Create(users.User{Username: "alice", PasswordHash: "h", Role: users.RoleAdmin}))
		require.NoError(t, st.Create(users.User{Username: "admin", PasswordHash: "old", Role: users.RoleAdmin}))
		require.NoError(t, st.SetRole("admin", users.RoleOperator))
		require.NoError(t, st.SetDisabled("admin", true))
		var err error
		before, err = st.Get("admin")
		require.NoError(t, err)
	})

	out, errOut, err := runResetAdmin(t, db)
	require.NoError(t, err)
	require.Regexp(t, onePasswordLine, out, "stdout carries only the password")
	assert.NotContains(t, errOut, out[:20], "the password goes to stdout only")
	pw := out[:20]

	withStore(t, db, func(st *users.Store) {
		u, err := st.Get("admin")
		require.NoError(t, err)
		assert.True(t, users.CheckPassword(u.PasswordHash, pw))
		assert.Equal(t, users.RoleAdmin, u.Role)
		assert.False(t, u.Disabled)
		assert.True(t, u.MustChangePassword)
		assert.Greater(t, u.TokenVersion, before.TokenVersion)
	})
}

func TestResetAdminPassword_RecreatesDeletedAdmin(t *testing.T) {
	db := filepath.Join(storagetest.TempDir(t), "t.db")
	withStore(t, db, func(st *users.Store) {
		require.NoError(t, st.Create(users.User{Username: "alice", PasswordHash: "h", Role: users.RoleAdmin}))
	})

	out, errOut, err := runResetAdmin(t, db)
	require.NoError(t, err)
	require.Regexp(t, onePasswordLine, out)
	assert.Contains(t, errOut, "created")

	withStore(t, db, func(st *users.Store) {
		u, err := st.Get("admin")
		require.NoError(t, err)
		assert.True(t, users.CheckPassword(u.PasswordHash, out[:20]))
		assert.Equal(t, users.RoleAdmin, u.Role)
		assert.True(t, u.MustChangePassword)
	})
}

func TestResetAdminPassword_MissingDatabaseFailsClearly(t *testing.T) {
	db := filepath.Join(storagetest.TempDir(t), "t.db")
	out, _, err := runResetAdmin(t, db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
	assert.Contains(t, err.Error(), "--config")
	assert.Empty(t, out)
	_, statErr := os.Stat(db)
	assert.True(t, os.IsNotExist(statErr), "a missing database must not be created")
}
