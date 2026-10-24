package users_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

func newStore(t *testing.T) *users.Store {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := users.New(db)
	require.NoError(t, err)
	return s
}

func mk(name string, r users.Role) users.User {
	return users.User{Username: name, PasswordHash: "h-" + name, Role: r}
}

func TestStore_CreateGetList(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.Create(mk("bob", users.RoleOperator)))
	require.NoError(t, s.Create(users.User{Username: "Alice", PasswordHash: "h", Role: users.RoleAdmin, MustChangePassword: true}))

	got, err := s.Get("bob")
	require.NoError(t, err)
	assert.Equal(t, "bob", got.Username)
	assert.Equal(t, "h-bob", got.PasswordHash)
	assert.Equal(t, users.RoleOperator, got.Role)
	assert.False(t, got.Disabled)
	assert.False(t, got.MustChangePassword)
	assert.Nil(t, got.LastLoginAt)
	assert.WithinDuration(t, time.Now(), got.CreatedAt, 5*time.Second)

	list, err := s.List()
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "Alice", list[0].Username)
	assert.True(t, list[0].MustChangePassword)
	assert.Equal(t, "bob", list[1].Username)
}

func TestStore_CreateValidates(t *testing.T) {
	s := newStore(t)
	var ve *users.ValidationError
	assert.ErrorAs(t, s.Create(mk("ops+ci", users.RoleAdmin)), &ve)
	assert.ErrorAs(t, s.Create(mk("ok", users.Role("root"))), &ve)
}

func TestStore_CaseInsensitive(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.Create(mk("anna", users.RoleOperator)))
	assert.ErrorIs(t, s.Create(mk("Anna", users.RoleOperator)), users.ErrExists)
	got, err := s.Get("ANNA")
	require.NoError(t, err)
	assert.Equal(t, "anna", got.Username)
}

func TestStore_LastAdminGuard(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.Create(mk("a1", users.RoleAdmin)))
	assert.ErrorIs(t, s.SetRole("a1", users.RoleOperator), users.ErrLastAdmin)
	assert.ErrorIs(t, s.SetDisabled("a1", true), users.ErrLastAdmin)
	assert.ErrorIs(t, s.Delete("a1"), users.ErrLastAdmin)

	// A disabled second admin does not count.
	require.NoError(t, s.Create(users.User{Username: "a2", PasswordHash: "h", Role: users.RoleAdmin, Disabled: true}))
	assert.ErrorIs(t, s.SetRole("a1", users.RoleOperator), users.ErrLastAdmin)
	assert.ErrorIs(t, s.Delete("a1"), users.ErrLastAdmin)

	require.NoError(t, s.SetDisabled("a2", false))
	require.NoError(t, s.SetRole("a1", users.RoleOperator))
	assert.ErrorIs(t, s.SetDisabled("a2", true), users.ErrLastAdmin)
	require.NoError(t, s.SetRole("a1", users.RoleAdmin))
	require.NoError(t, s.SetDisabled("a1", true))
	require.NoError(t, s.SetDisabled("a1", false))
	require.NoError(t, s.Delete("a1"))
	assert.ErrorIs(t, s.Delete("a2"), users.ErrLastAdmin)
}

func TestStore_TokenVersionBumps(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.Create(mk("u", users.RoleOperator)))
	first, err := s.Get("u")
	require.NoError(t, err)
	start := first.TokenVersion
	assert.Positive(t, start, "a new row starts at a time-derived version, not 0")
	ver := func() int64 {
		u, err := s.Get("u")
		require.NoError(t, err)
		return u.TokenVersion - start
	}
	assert.EqualValues(t, 0, ver())
	require.NoError(t, s.SetPassword("u", "newhash", true))
	assert.EqualValues(t, 1, ver())
	u, _ := s.Get("u")
	assert.Equal(t, "newhash", u.PasswordHash)
	assert.True(t, u.MustChangePassword)
	require.NoError(t, s.SetRole("u", users.RoleAdmin))
	assert.EqualValues(t, 2, ver())
	require.NoError(t, s.SetRole("u", users.RoleAdmin))
	assert.EqualValues(t, 2, ver())
	require.NoError(t, s.Create(mk("other", users.RoleAdmin)))
	require.NoError(t, s.SetDisabled("u", true))
	assert.EqualValues(t, 3, ver())
	require.NoError(t, s.SetDisabled("u", true))
	assert.EqualValues(t, 3, ver())
	require.NoError(t, s.SetDisabled("u", false))
	assert.EqualValues(t, 4, ver())
}

func TestStore_RecreatedUserStartsAboveOldVersion(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.Create(mk("bob", users.RoleOperator)))
	require.NoError(t, s.SetPassword("bob", "h2", false))
	old, err := s.Get("bob")
	require.NoError(t, err)
	require.NoError(t, s.Delete("bob"))
	require.NoError(t, s.Create(mk("bob", users.RoleOperator)))
	fresh, err := s.Get("bob")
	require.NoError(t, err)
	assert.Greater(t, fresh.TokenVersion, old.TokenVersion)
}

func TestStore_HasEnabledUsers(t *testing.T) {
	s := newStore(t)
	has, err := s.HasEnabledUsers()
	require.NoError(t, err)
	assert.False(t, has)
	require.NoError(t, s.Create(users.User{Username: "d", PasswordHash: "h", Role: users.RoleOperator, Disabled: true}))
	has, _ = s.HasEnabledUsers()
	assert.False(t, has)
	require.NoError(t, s.Create(mk("e", users.RoleOperator)))
	has, _ = s.HasEnabledUsers()
	assert.True(t, has)
}

func TestStore_TouchLogin(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.Create(mk("u", users.RoleOperator)))
	at := time.Unix(1700000000, 0)
	require.NoError(t, s.TouchLogin("u", at))
	u, _ := s.Get("u")
	require.NotNil(t, u.LastLoginAt)
	assert.True(t, u.LastLoginAt.Equal(at))
	assert.ErrorIs(t, s.TouchLogin("nobody", at), users.ErrNotFound)
}

func TestEnsureInitialAdmin_EmptyTable(t *testing.T) {
	s := newStore(t)
	pw, created, err := s.EnsureInitialAdmin()
	require.NoError(t, err)
	require.True(t, created)
	assert.Len(t, pw, 20)
	u, err := s.Get(users.InitialAdminUsername)
	require.NoError(t, err)
	assert.Equal(t, "admin", u.Username)
	assert.Equal(t, users.RoleAdmin, u.Role)
	assert.True(t, u.MustChangePassword)
	assert.False(t, u.Disabled)
	assert.True(t, users.CheckPassword(u.PasswordHash, pw))

	pw2, created, err := s.EnsureInitialAdmin()
	require.NoError(t, err)
	assert.False(t, created)
	assert.Empty(t, pw2)
	again, err := s.Get("admin")
	require.NoError(t, err)
	assert.Equal(t, u.PasswordHash, again.PasswordHash, "a second call changes nothing")
	assert.Equal(t, u.TokenVersion, again.TokenVersion)
}

func TestEnsureInitialAdmin_NonEmptyTable(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.Create(users.User{Username: "ops", PasswordHash: "h", Role: users.RoleOperator, Disabled: true}))
	pw, created, err := s.EnsureInitialAdmin()
	require.NoError(t, err)
	assert.False(t, created)
	assert.Empty(t, pw)
	_, err = s.Get("admin")
	assert.ErrorIs(t, err, users.ErrNotFound)
}

func TestResetAdmin_ExistingDemotedDisabled(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.Create(users.User{Username: "admin", PasswordHash: "old", Role: users.RoleOperator, Disabled: true}))
	before, err := s.Get("admin")
	require.NoError(t, err)

	hash, err := users.HashPassword("brand-new-password-1")
	require.NoError(t, err)
	created, err := s.ResetAdmin(hash)
	require.NoError(t, err)
	assert.False(t, created)

	u, err := s.Get("admin")
	require.NoError(t, err)
	assert.Equal(t, users.RoleAdmin, u.Role)
	assert.False(t, u.Disabled)
	assert.True(t, u.MustChangePassword)
	assert.Greater(t, u.TokenVersion, before.TokenVersion, "sessions are revoked")
	assert.True(t, users.CheckPassword(u.PasswordHash, "brand-new-password-1"))
}

func TestResetAdmin_MatchesCaseInsensitively(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.Create(users.User{Username: "Admin", PasswordHash: "old", Role: users.RoleAdmin}))
	created, err := s.ResetAdmin("newhash")
	require.NoError(t, err)
	assert.False(t, created)
	list, err := s.List()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "newhash", list[0].PasswordHash)
}

func TestResetAdmin_MissingRecreates(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.Create(mk("alice", users.RoleAdmin)))
	created, err := s.ResetAdmin("h-admin")
	require.NoError(t, err)
	assert.True(t, created)
	u, err := s.Get("admin")
	require.NoError(t, err)
	assert.Equal(t, users.RoleAdmin, u.Role)
	assert.True(t, u.MustChangePassword)
	assert.False(t, u.Disabled)
	assert.Equal(t, "h-admin", u.PasswordHash)
}

func TestStore_NotFound(t *testing.T) {
	s := newStore(t)
	_, err := s.Get("x")
	assert.ErrorIs(t, err, users.ErrNotFound)
	assert.ErrorIs(t, s.SetRole("x", users.RoleAdmin), users.ErrNotFound)
	assert.ErrorIs(t, s.Delete("x"), users.ErrNotFound)
	assert.ErrorIs(t, s.SetDisabled("x", true), users.ErrNotFound)
	assert.ErrorIs(t, s.SetPassword("x", "h", false), users.ErrNotFound)
}

func TestStore_HasAnyUsers(t *testing.T) {
	s := newStore(t)
	has, err := s.HasAnyUsers()
	require.NoError(t, err)
	assert.False(t, has)
	require.NoError(t, s.Create(users.User{Username: "d", PasswordHash: "h", Role: users.RoleOperator, Disabled: true}))
	has, err = s.HasAnyUsers()
	require.NoError(t, err)
	assert.True(t, has, "a disabled user still makes the table non-empty")
}
