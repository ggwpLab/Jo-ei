package auth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/ggwpLab/Jo-ei/internal/auth"
)

// hash returns a low-cost bcrypt hash of pw, for fast tests.
func hash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	require.NoError(t, err)
	return string(h)
}

func TestParseBootstrapUsers(t *testing.T) {
	t.Run("file only", func(t *testing.T) {
		h := hash(t, "secret")
		got, err := auth.ParseBootstrapUsers([]auth.User{{Username: " admin ", PasswordHash: h}}, "")
		require.NoError(t, err)
		assert.Equal(t, []auth.User{{Username: "admin", PasswordHash: h}}, got)
	})

	t.Run("env only", func(t *testing.T) {
		h1, h2 := hash(t, "pw1"), hash(t, "pw2")
		got, err := auth.ParseBootstrapUsers(nil, "alice:"+h1+" ; bob:"+h2)
		require.NoError(t, err)
		assert.Equal(t, []auth.User{{Username: "alice", PasswordHash: h1}, {Username: "bob", PasswordHash: h2}}, got)
	})

	t.Run("env overrides file", func(t *testing.T) {
		oldH, newH, otherH := hash(t, "oldpw"), hash(t, "newpw"), hash(t, "other")
		file := []auth.User{{Username: "admin", PasswordHash: oldH}, {Username: "ops", PasswordHash: otherH}}
		got, err := auth.ParseBootstrapUsers(file, "admin:"+newH)
		require.NoError(t, err)
		assert.Equal(t, []auth.User{{Username: "admin", PasswordHash: newH}, {Username: "ops", PasswordHash: otherH}}, got)
	})

	t.Run("override is case-insensitive", func(t *testing.T) {
		oldH, newH := hash(t, "oldpw"), hash(t, "newpw")
		got, err := auth.ParseBootstrapUsers([]auth.User{{Username: "Admin", PasswordHash: oldH}}, "admin:"+newH)
		require.NoError(t, err)
		assert.Equal(t, []auth.User{{Username: "admin", PasswordHash: newH}}, got,
			"usernames are case-insensitive, so the env entry replaces the file entry")
	})

	t.Run("empty", func(t *testing.T) {
		got, err := auth.ParseBootstrapUsers(nil, "")
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("validation errors", func(t *testing.T) {
		good := hash(t, "secret")

		_, err := auth.ParseBootstrapUsers([]auth.User{{Username: "  ", PasswordHash: good}}, "")
		require.Error(t, err, "blank username")

		_, err = auth.ParseBootstrapUsers([]auth.User{{Username: "admin", PasswordHash: "not-a-bcrypt-hash"}}, "")
		require.Error(t, err, "non-bcrypt hash")

		_, err = auth.ParseBootstrapUsers(nil, "no-colon-entry")
		require.Error(t, err, "env entry without ':'")

		_, err = auth.ParseBootstrapUsers(nil, "admin:")
		require.Error(t, err, "env entry with empty hash")
	})
}
