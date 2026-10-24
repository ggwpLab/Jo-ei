package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/storage/storagetest"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

func newBootstrapStore(t *testing.T) *users.Store {
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

func bootstrapHash(t *testing.T) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("a-long-enough-password"), bcrypt.MinCost)
	require.NoError(t, err)
	return string(h)
}

func TestBootstrapUsers_ImportsOnce(t *testing.T) {
	enableLogs(t)
	st := newBootstrapStore(t)
	h := bootstrapHash(t)

	var buf bytes.Buffer
	log := zerolog.New(&buf)
	require.NoError(t, bootstrapUsers(st, nil, "ops:"+h, log))
	all, err := st.List()
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "ops", all[0].Username)
	assert.Equal(t, users.RoleAdmin, all[0].Role)
	assert.False(t, all[0].MustChangePassword)
	assert.Contains(t, buf.String(), "imported 1 console users from config")

	require.NoError(t, bootstrapUsers(st, nil, "other:"+h, log))
	all, err = st.List()
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "ops", all[0].Username)
}

func TestBootstrapUsers_WarnsWhenIgnored(t *testing.T) {
	enableLogs(t)
	st := newBootstrapStore(t)
	h := bootstrapHash(t)
	require.NoError(t, bootstrapUsers(st, nil, "ops:"+h, zerolog.Nop()))

	var buf bytes.Buffer
	require.NoError(t, bootstrapUsers(st, []auth.User{{Username: "x", PasswordHash: h}}, "", zerolog.New(&buf)))
	assert.Contains(t, buf.String(), "console.auth.users / JOEI_CONSOLE_AUTH_USERS are ignored: users are managed in the database (console Users page or jo-ei user)")
}

func TestBootstrapUsers_InvalidName(t *testing.T) {
	st := newBootstrapStore(t)
	err := bootstrapUsers(st, nil, "ops+ci:"+bootstrapHash(t), zerolog.Nop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ops+ci")
	all, err := st.List()
	require.NoError(t, err)
	assert.Empty(t, all)
}

func TestBootstrapUsers_NothingToImport(t *testing.T) {
	st := newBootstrapStore(t)
	var buf bytes.Buffer
	require.NoError(t, bootstrapUsers(st, nil, "", zerolog.New(&buf)))
	all, err := st.List()
	require.NoError(t, err)
	assert.Empty(t, all)
	assert.Empty(t, buf.String())
}

func TestBootstrapUsers_NonEmptyTableIgnoresInvalidEntries(t *testing.T) {
	enableLogs(t)
	st := newBootstrapStore(t)
	h := bootstrapHash(t)
	require.NoError(t, bootstrapUsers(st, nil, "ops:"+h, zerolog.Nop()))

	cases := map[string]struct {
		file []auth.User
		env  string
	}{
		"malformed env hash":    {env: "ops:not-a-bcrypt-hash"},
		"invalid env name":      {env: "ops+ci:" + h},
		"malformed env entry":   {env: "no-colon-here"},
		"invalid config name":   {file: []auth.User{{Username: "ivan petrov", PasswordHash: h}}},
		"malformed config hash": {file: []auth.User{{Username: "x", PasswordHash: "nope"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, bootstrapUsers(st, tc.file, tc.env, zerolog.New(&buf)),
				"once users exist, config/env users must not stop startup")
			assert.Contains(t, buf.String(), "console.auth.users / JOEI_CONSOLE_AUTH_USERS are ignored")
		})
	}
	all, err := st.List()
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "ops", all[0].Username)
}

func TestBootstrapUsers_DisabledOnlyTableStillCountsAsNonEmpty(t *testing.T) {
	enableLogs(t)
	st := newBootstrapStore(t)
	require.NoError(t, st.Create(users.User{Username: "gone", PasswordHash: bootstrapHash(t), Role: users.RoleAdmin, Disabled: true}))

	var buf bytes.Buffer
	require.NoError(t, bootstrapUsers(st, nil, "ops+ci:bad", zerolog.New(&buf)))
	assert.Contains(t, buf.String(), "are ignored")
	all, err := st.List()
	require.NoError(t, err)
	assert.Len(t, all, 1)
}
