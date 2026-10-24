package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/storage/storagetest"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// runUser runs `jo-ei user ...` against a fresh config whose database lives at dbPath.
func runUser(t *testing.T, dbPath, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte("database:\n  path: \""+filepath.ToSlash(dbPath)+"\"\n"), 0o600))
	prev := cfgFile
	cfgFile = cfg
	t.Cleanup(func() { cfgFile = prev })

	cmd := newUserCmd()
	var out, errb bytes.Buffer
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

func userDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(storagetest.TempDir(t), "t.db")
}

func getUser(t *testing.T, dbPath, name string) users.User {
	t.Helper()
	db, err := storage.Open(dbPath)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	st, err := users.New(db)
	require.NoError(t, err)
	u, err := st.Get(name)
	require.NoError(t, err)
	return u
}

func TestUserCreate_FromStdin(t *testing.T) {
	db := userDBPath(t)
	_, _, err := runUser(t, db, "correct horse battery\n", "create", "alice", "--role", "admin")
	require.NoError(t, err)
	u := getUser(t, db, "alice")
	assert.Equal(t, users.RoleAdmin, u.Role)
	assert.True(t, u.MustChangePassword)
	assert.True(t, users.CheckPassword(u.PasswordHash, "correct horse battery"))

	_, _, err = runUser(t, db, "correct horse battery\n", "create", "ALICE", "--role", "operator", "--no-force-change")
	require.EqualError(t, err, `user "ALICE" already exists`)

	_, _, err = runUser(t, db, "correct horse battery\n", "create", "bob", "--role", "root")
	require.ErrorContains(t, err, "admin")
}

func TestUserCreate_Generate(t *testing.T) {
	db := userDBPath(t)
	out, _, err := runUser(t, db, "", "create", "ops", "--role", "operator", "--generate", "--no-force-change")
	require.NoError(t, err)
	pw := strings.TrimSuffix(out, "\n")
	assert.Len(t, pw, 20)
	assert.NotContains(t, pw, "\n")
	u := getUser(t, db, "ops")
	assert.False(t, u.MustChangePassword)
	assert.True(t, users.CheckPassword(u.PasswordHash, pw))
}

func TestUserCreate_RejectsShortPassword(t *testing.T) {
	db := userDBPath(t)
	_, _, err := runUser(t, db, "short\n", "create", "alice", "--role", "admin")
	require.Error(t, err)
	out, _, err := runUser(t, db, "", "list")
	require.NoError(t, err)
	assert.NotContains(t, out, "alice")
}

func TestUserResetPassword_ReEnablesAndBumpsVersion(t *testing.T) {
	db := userDBPath(t)
	_, _, err := runUser(t, db, "first password 123\n", "create", "alice", "--role", "admin", "--no-force-change")
	require.NoError(t, err)
	_, _, err = runUser(t, db, "second password 456\n", "create", "bob", "--role", "operator")
	require.NoError(t, err)

	sdb, err := storage.Open(db)
	require.NoError(t, err)
	st, err := users.New(sdb)
	require.NoError(t, err)
	require.NoError(t, st.SetDisabled("bob", true))
	require.NoError(t, sdb.Close())
	before := getUser(t, db, "bob")

	_, _, err = runUser(t, db, "third password 789\n", "reset-password", "bob")
	require.NoError(t, err)
	after := getUser(t, db, "bob")
	assert.False(t, after.Disabled)
	assert.True(t, after.MustChangePassword)
	assert.Greater(t, after.TokenVersion, before.TokenVersion)
	assert.True(t, users.CheckPassword(after.PasswordHash, "third password 789"))

	_, _, err = runUser(t, db, "", "reset-password", "nobody", "--generate")
	require.ErrorContains(t, err, "not found")
}

func TestUserList_Output(t *testing.T) {
	db := userDBPath(t)
	_, _, err := runUser(t, db, "first password 123\n", "create", "alice", "--role", "admin", "--no-force-change")
	require.NoError(t, err)
	_, _, err = runUser(t, db, "second password 456\n", "create", "bob", "--role", "operator")
	require.NoError(t, err)

	out, _, err := runUser(t, db, "", "list")
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 3)
	assert.Equal(t, []string{"USERNAME", "ROLE", "STATUS", "LAST", "LOGIN"}, strings.Fields(lines[0]))
	assert.Equal(t, []string{"alice", "admin", "active", "never"}, strings.Fields(lines[1]))
	assert.Equal(t, []string{"bob", "operator", "must", "change", "password", "never"}, strings.Fields(lines[2]))
}
