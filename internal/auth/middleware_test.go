package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestMiddlewareLockedReturns503(t *testing.T) {
	u, err := auth.NewUsers(nil, "") // no users -> locked
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	u.Middleware(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, called, "locked middleware must not reach the handler")
	assert.Contains(t, rec.Body.String(), "auth_not_configured")
}

func TestMiddlewareNoCredentialsChallenges(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: hash(t, "secret")}}, "")
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	u.Middleware(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Basic realm=")
}

func TestMiddlewareBadCredentials(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: hash(t, "secret")}}, "")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.SetBasicAuth("admin", "wrong")
	rec := httptest.NewRecorder()
	u.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareGoodCredentialsPassesAndSetsContext(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: hash(t, "secret")}}, "")
	require.NoError(t, err)

	var seenUser string
	var seenOK bool
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUser, seenOK = auth.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.SetBasicAuth("admin", "secret")
	rec := httptest.NewRecorder()
	u.Middleware(probe).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, seenOK)
	assert.Equal(t, "admin", seenUser)
}
