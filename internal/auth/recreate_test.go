package auth_test

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// A deleted and re-created user must never revive sessions the old account
// held: the new row starts at a token version the old row could not reach.
func TestRecreatedUser_DoesNotReviveOldSessions(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	store, err := users.New(db)
	require.NoError(t, err)
	require.NoError(t, store.Create(adminUser(t)))
	require.NoError(t, store.Create(operator(t, "bob", "secret")))
	s := sessionsWith(t, store)

	// Old bob: log in, change the password (version bump), keep that pair.
	tok := loginToken(t, s, "bob", "secret")
	rec := changePassword(t, s, tok, "secret", newPassword)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	oldAccess := body.AccessToken
	oldRefresh := cookieByName(t, rec, auth.RefreshCookie)
	require.Equal(t, http.StatusOK, getWithBearer(s, okHandler(), oldAccess).Code)

	// Delete bob, re-create him, and bump the new account once too.
	require.NoError(t, store.Delete("bob"))
	require.NoError(t, store.Create(operator(t, "bob", "secret")))
	tok = loginToken(t, s, "bob", "secret")
	require.Equal(t, http.StatusOK, changePassword(t, s, tok, "secret", newPassword).Code)

	assert.Equal(t, http.StatusUnauthorized, getWithBearer(s, okHandler(), oldAccess).Code,
		"the old account's access token must stay revoked")
	refresh := postJSON(t, s.Handler(), "/api/auth/refresh", "", oldRefresh)
	assert.Equal(t, http.StatusUnauthorized, refresh.Code,
		"the old account's refresh token must stay revoked")
}
