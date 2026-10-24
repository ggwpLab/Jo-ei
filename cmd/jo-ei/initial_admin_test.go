package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/storage/storagetest"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

func newUserStore(t *testing.T) *users.Store {
	t.Helper()
	sdb, err := storage.Open(filepath.Join(storagetest.TempDir(t), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sdb.Close() })
	st, err := users.New(sdb)
	require.NoError(t, err)
	return st
}

// enableLogs lifts the process-wide zerolog level, which other tests in this
// package may have raised by running the real startup path.
func enableLogs(t *testing.T) {
	t.Helper()
	prev := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prev) })
}

func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m), line)
		out = append(out, m)
	}
	return out
}

func TestEnsureInitialAdmin_LogsPasswordOnceOnEmptyDB(t *testing.T) {
	enableLogs(t)
	st := newUserStore(t)

	var buf bytes.Buffer
	require.NoError(t, ensureInitialAdmin(st, zerolog.New(&buf)))
	lines := logLines(t, &buf)
	require.Len(t, lines, 1)
	l := lines[0]
	assert.Equal(t, "warn", l["level"])
	assert.Equal(t, "created initial admin user", l["message"])
	assert.Equal(t, "admin", l["user"])
	pw, _ := l["password"].(string)
	require.Len(t, pw, 20)
	assert.Contains(t, l["hint"], "jo-ei reset-admin-password")

	u, err := st.Get("admin")
	require.NoError(t, err)
	assert.True(t, users.CheckPassword(u.PasswordHash, pw))
	assert.True(t, u.MustChangePassword)

	// Second start: nothing created, and the password never appears again.
	buf.Reset()
	require.NoError(t, ensureInitialAdmin(st, zerolog.New(&buf)))
	assert.NotContains(t, buf.String(), pw)
	assert.NotContains(t, buf.String(), "password")
	after, err := st.Get("admin")
	require.NoError(t, err)
	assert.Equal(t, u.PasswordHash, after.PasswordHash)
}

func TestEnsureInitialAdmin_NonEmptyTableCreatesNothing(t *testing.T) {
	enableLogs(t)
	st := newUserStore(t)
	require.NoError(t, st.Create(users.User{Username: "ops", PasswordHash: "h", Role: users.RoleOperator, Disabled: true}))
	var buf bytes.Buffer
	require.NoError(t, ensureInitialAdmin(st, zerolog.New(&buf)))
	assert.Empty(t, buf.String())
	_, err := st.Get("admin")
	assert.ErrorIs(t, err, users.ErrNotFound)
}
