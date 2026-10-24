package console_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

const goodPassword = "correct-horse-battery"

func usersFixture(t *testing.T, actor *auth.Identity, logs *bytes.Buffer, seed ...users.User) (http.Handler, *users.Store) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	st, err := users.New(db)
	require.NoError(t, err)
	for _, u := range seed {
		if u.PasswordHash == "" {
			u.PasswordHash = "x"
		}
		require.NoError(t, st.Create(u))
	}
	logger := zerolog.Nop()
	if logs != nil {
		logger = zerolog.New(logs)
	}
	return withIdentity(console.NewHandler(console.Config{
		Store:       newTelemetryStore(t),
		Broadcaster: telemetry.NewBroadcaster(),
		Policy:      policy.NewRuntime(config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24}, config.CVEConfig{}, config.PolicyProfile{}, nil),
		Cache:       &fakeStats{},
		Purger:      &fakePurger{},
		Users:       st,
		Logger:      logger,
	}), actor), st
}

func doUsers(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var usersAdmin = &auth.Identity{Username: "admin", Role: users.RoleAdmin}

func TestUsersAPI_CreateListGet(t *testing.T) {
	h, _ := usersFixture(t, usersAdmin, nil)
	rec := doUsers(h, "POST", "/api/users", `{"username":"Alice","role":"operator","password":"`+goodPassword+`"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "password_hash")
	var created map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	assert.Equal(t, "Alice", created["username"])
	assert.Equal(t, "operator", created["role"])
	assert.Equal(t, true, created["must_change_password"])
	assert.Equal(t, false, created["disabled"])
	assert.Nil(t, created["last_login_at"])
	assert.NotEmpty(t, created["created_at"])

	rec = doUsers(h, "GET", "/api/users", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "password_hash")
	var list []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list, 1)
	assert.Equal(t, "Alice", list[0]["username"])
}

func TestUsersAPI_ListEmptyIsArray(t *testing.T) {
	h, _ := usersFixture(t, usersAdmin, nil)
	assert.JSONEq(t, `[]`, doUsers(h, "GET", "/api/users", "").Body.String())
}

func TestUsersAPI_NilStore503(t *testing.T) {
	h := withIdentity(console.NewHandler(console.Config{Logger: zerolog.Nop()}), usersAdmin)
	rec := doUsers(h, "GET", "/api/users", "")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.JSONEq(t, `{"error":"users_unavailable"}`, rec.Body.String())
}

func TestUsersAPI_DuplicateCaseInsensitive409(t *testing.T) {
	h, _ := usersFixture(t, usersAdmin, nil, users.User{Username: "Alice", Role: users.RoleOperator})
	rec := doUsers(h, "POST", "/api/users", `{"username":"ALICE","role":"operator","password":"`+goodPassword+`"}`)
	require.Equal(t, http.StatusConflict, rec.Code)
	assert.JSONEq(t, `{"error":"user_exists"}`, rec.Body.String())
}

func TestUsersAPI_InvalidUsernameAndPassword400(t *testing.T) {
	h, _ := usersFixture(t, usersAdmin, nil, users.User{Username: "bob", Role: users.RoleOperator})
	cases := []struct{ method, path, body, field string }{
		{"POST", "/api/users", `{"username":"bad name","role":"operator","password":"` + goodPassword + `"}`, "username"},
		{"POST", "/api/users", `{"username":"carol","role":"root","password":"` + goodPassword + `"}`, "role"},
		{"POST", "/api/users", `{"username":"carol","role":"operator","password":"short"}`, "password"},
		{"POST", "/api/users", `{"username":"carolcarolcarol","role":"operator","password":"CAROLCAROLCAROL"}`, "password"},
		{"POST", "/api/users/bob/password", `{"password":"short"}`, "password"},
		{"PATCH", "/api/users/bob", `{"role":"root"}`, "role"},
		{"PATCH", "/api/users/bob", `{}`, "body"},
		{"PATCH", "/api/users/bob", `{"bogus":1}`, "body"},
		{"POST", "/api/users", `not json`, "body"},
	}
	for _, c := range cases {
		rec := doUsers(h, c.method, c.path, c.body)
		require.Equal(t, http.StatusBadRequest, rec.Code, c.body)
		var m map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m))
		assert.Equal(t, "invalid_user", m["error"], c.body)
		assert.Equal(t, c.field, m["field"], c.body)
		assert.NotEmpty(t, m["message"])
	}
}

func TestUsersAPI_NotFound404(t *testing.T) {
	h, _ := usersFixture(t, usersAdmin, nil)
	for _, c := range [][3]string{
		{"PATCH", "/api/users/nobody", `{"disabled":true}`},
		{"POST", "/api/users/nobody/password", `{"password":"` + goodPassword + `"}`},
		{"DELETE", "/api/users/nobody", ""},
	} {
		rec := doUsers(h, c[0], c[1], c[2])
		require.Equal(t, http.StatusNotFound, rec.Code, c[1])
		assert.JSONEq(t, `{"error":"user_not_found"}`, rec.Body.String())
	}
}

func TestUsersAPI_SelfGuards409(t *testing.T) {
	h, st := usersFixture(t, &auth.Identity{Username: "Root", Role: users.RoleAdmin}, nil,
		users.User{Username: "root", Role: users.RoleAdmin},
		users.User{Username: "other", Role: users.RoleAdmin})
	for _, c := range [][3]string{
		{"DELETE", "/api/users/root", ""},
		{"PATCH", "/api/users/root", `{"disabled":true}`},
		{"PATCH", "/api/users/root", `{"role":"operator"}`},
	} {
		rec := doUsers(h, c[0], c[1], c[2])
		require.Equal(t, http.StatusConflict, rec.Code, c[1]+c[2])
		assert.JSONEq(t, `{"error":"self"}`, rec.Body.String())
	}
	u, err := st.Get("root")
	require.NoError(t, err)
	assert.Equal(t, users.RoleAdmin, u.Role)
	assert.False(t, u.Disabled)

	// Re-sending the current role is not a demotion.
	rec := doUsers(h, "PATCH", "/api/users/root", `{"role":"admin"}`)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestUsersAPI_LastAdmin409(t *testing.T) {
	h, _ := usersFixture(t, &auth.Identity{Username: "ghost", Role: users.RoleAdmin}, nil,
		users.User{Username: "root", Role: users.RoleAdmin})
	for _, c := range [][3]string{
		{"PATCH", "/api/users/root", `{"role":"operator"}`},
		{"PATCH", "/api/users/root", `{"disabled":true}`},
		{"DELETE", "/api/users/root", ""},
	} {
		rec := doUsers(h, c[0], c[1], c[2])
		require.Equal(t, http.StatusConflict, rec.Code, c[1]+c[2])
		assert.JSONEq(t, `{"error":"last_admin"}`, rec.Body.String())
	}
}

func TestUsersAPI_ResetPasswordForcesChange(t *testing.T) {
	h, st := usersFixture(t, usersAdmin, nil, users.User{Username: "bob", Role: users.RoleOperator})
	before, err := st.Get("bob")
	require.NoError(t, err)
	require.False(t, before.MustChangePassword)

	rec := doUsers(h, "POST", "/api/users/bob/password", `{"password":"`+goodPassword+`"}`)
	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Body.String())

	after, err := st.Get("bob")
	require.NoError(t, err)
	assert.True(t, after.MustChangePassword)
	assert.True(t, users.CheckPassword(after.PasswordHash, goodPassword))
	assert.Greater(t, after.TokenVersion, before.TokenVersion)
}

func TestUsersAPI_RoleChangeRevokesSessions(t *testing.T) {
	h, st := usersFixture(t, usersAdmin, nil,
		users.User{Username: "bob", Role: users.RoleOperator},
		users.User{Username: "root", Role: users.RoleAdmin})
	before, err := st.Get("bob")
	require.NoError(t, err)

	rec := doUsers(h, "PATCH", "/api/users/bob", `{"role":"admin"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"role":"admin"`)

	after, err := st.Get("bob")
	require.NoError(t, err)
	assert.Equal(t, before.TokenVersion+1, after.TokenVersion)
}

func TestUsersAPI_OperatorForbidden(t *testing.T) {
	h, _ := usersFixture(t, &auth.Identity{Username: "op", Role: users.RoleOperator}, nil,
		users.User{Username: "bob", Role: users.RoleOperator})
	for _, c := range [][3]string{
		{"GET", "/api/users", ""},
		{"POST", "/api/users", `{}`},
		{"PATCH", "/api/users/bob", `{"disabled":true}`},
		{"POST", "/api/users/bob/password", `{}`},
		{"DELETE", "/api/users/bob", ""},
	} {
		rec := doUsers(h, c[0], c[1], c[2])
		require.Equal(t, http.StatusForbidden, rec.Code, c[0]+" "+c[1])
		assert.JSONEq(t, `{"error":"forbidden"}`, rec.Body.String())
	}
}

func TestUsersAPI_Logs(t *testing.T) {
	var buf bytes.Buffer
	h, _ := usersFixture(t, usersAdmin, &buf, users.User{Username: "bob", Role: users.RoleAdmin})
	require.Equal(t, http.StatusCreated, doUsers(h, "POST", "/api/users",
		`{"username":"carol","role":"operator","password":"`+goodPassword+`"}`).Code)
	// Both fields in one PATCH log one line each.
	require.Equal(t, http.StatusOK, doUsers(h, "PATCH", "/api/users/carol", `{"role":"admin","disabled":true}`).Code)
	require.Equal(t, http.StatusNoContent, doUsers(h, "POST", "/api/users/carol/password",
		`{"password":"another-long-passphrase"}`).Code)
	require.Equal(t, http.StatusNoContent, doUsers(h, "DELETE", "/api/users/carol", "").Code)

	var actions []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		if m["message"] != "user management" {
			continue
		}
		assert.Equal(t, "admin", m["user"])
		assert.Equal(t, "carol", m["target"])
		actions = append(actions, m["action"].(string))
		if m["action"] == "create" || m["action"] == "role" {
			assert.NotEmpty(t, m["role"])
		}
	}
	assert.Equal(t, []string{"create", "role", "disable", "reset_password", "delete"}, actions)
	assert.NotContains(t, buf.String(), "password\":")
	assert.NotContains(t, buf.String(), goodPassword)
	assert.NotContains(t, buf.String(), "another-long-passphrase")
}
