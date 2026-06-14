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

func TestNewUsersFileOnly(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: hash(t, "secret")}}, "")
	require.NoError(t, err)
	assert.False(t, u.Locked())
	assert.True(t, u.Verify("admin", "secret"))
	assert.False(t, u.Verify("admin", "wrong"))
}

func TestNewUsersEnvOnly(t *testing.T) {
	env := "alice:" + hash(t, "pw1") + " ; bob:" + hash(t, "pw2")
	u, err := auth.NewUsers(nil, env)
	require.NoError(t, err)
	assert.True(t, u.Verify("alice", "pw1"))
	assert.True(t, u.Verify("bob", "pw2"))
	assert.False(t, u.Verify("alice", "pw2"))
}

func TestNewUsersEnvOverridesFile(t *testing.T) {
	file := []auth.User{{Username: "admin", PasswordHash: hash(t, "oldpw")}}
	env := "admin:" + hash(t, "newpw")
	u, err := auth.NewUsers(file, env)
	require.NoError(t, err)
	assert.False(t, u.Verify("admin", "oldpw"), "env entry overrides the file entry")
	assert.True(t, u.Verify("admin", "newpw"))
}

func TestNewUsersEmptyIsLocked(t *testing.T) {
	u, err := auth.NewUsers(nil, "")
	require.NoError(t, err)
	assert.True(t, u.Locked())
	assert.False(t, u.Verify("admin", "secret"))
}

func TestNewUsersValidationErrors(t *testing.T) {
	good := hash(t, "secret")

	_, err := auth.NewUsers([]auth.User{{Username: "  ", PasswordHash: good}}, "")
	require.Error(t, err, "blank username")

	_, err = auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: "not-a-bcrypt-hash"}}, "")
	require.Error(t, err, "non-bcrypt hash")

	_, err = auth.NewUsers(nil, "no-colon-entry")
	require.Error(t, err, "env entry without ':'")

	_, err = auth.NewUsers(nil, "admin:")
	require.Error(t, err, "env entry with empty hash")
}

func TestVerifyUnknownUser(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: hash(t, "secret")}}, "")
	require.NoError(t, err)
	assert.False(t, u.Verify("nobody", "secret"))
}
