package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// sessions builds a Sessions with one user "admin"/"secret". Pass no users to
// get the locked (fail-closed) state.
func sessions(t *testing.T, users ...auth.User) *auth.Sessions {
	t.Helper()
	u, err := auth.NewUsers(users, "")
	require.NoError(t, err)
	signer, err := auth.NewSigner([]byte(testSecret))
	require.NoError(t, err)
	return auth.NewSessions(u, signer, 15*time.Minute, 168*time.Hour)
}

func adminUser(t *testing.T) auth.User {
	t.Helper()
	return auth.User{Username: "admin", PasswordHash: hash(t, "secret")}
}

// accessToken logs in through the handler and returns the bearer token.
func accessToken(t *testing.T, s *auth.Sessions) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"secret"}`))
	s.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)
	return body.AccessToken
}

func TestMiddlewareLockedReturns503(t *testing.T) {
	s := sessions(t) // no users
	rec := httptest.NewRecorder()
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	s.Middleware(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, called, "locked middleware must not reach the handler")
	assert.Contains(t, rec.Body.String(), "auth_not_configured")
}

func TestMiddlewareWithoutCredentials401sWithoutBasicChallenge(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := httptest.NewRecorder()

	s.Middleware(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "unauthorized")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
		"a Basic challenge would make the browser cover the console's own login screen")
}

func TestMiddlewareRejectsBasicAuth(t *testing.T) {
	s := sessions(t, adminUser(t))
	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.SetBasicAuth("admin", "secret") // the credentials are right; the scheme is gone
	rec := httptest.NewRecorder()

	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareRejectsBasicAuthEvenWithAValidCookiePresent(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.SetBasicAuth("admin", "secret") // a malformed (non-Bearer) Authorization header
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: tok})
	rec := httptest.NewRecorder()

	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"a present Authorization header must not fall through to the cookie, even a valid one")
}

func TestMiddlewareBearerTokenWinsOverCookie(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: tok})
	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddlewareAcceptsBearerToken(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddlewareAcceptsAccessCookie(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: tok})
	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddlewarePutsUsernameInContext(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	var got string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		name, ok := auth.UserFromContext(r.Context())
		require.True(t, ok)
		got = name
	})
	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.Middleware(next).ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, "admin", got)
}

func TestMiddlewareRejectsRefreshTokenAsAccess(t *testing.T) {
	s := sessions(t, adminUser(t))
	// Log in, then present the refresh cookie where the access cookie belongs.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"secret"}`)))
	var refresh string
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.RefreshCookie {
			refresh = c.Value
		}
	}
	require.NotEmpty(t, refresh)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: refresh})
	out := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(out, req)

	assert.Equal(t, http.StatusUnauthorized, out.Code)
}

func TestMiddlewareRejectsExpiredToken(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{adminUser(t)}, "")
	require.NoError(t, err)
	signer, err := auth.NewSigner([]byte(testSecret))
	require.NoError(t, err)
	// A one-nanosecond access lifetime: the token is expired before it is read.
	s := auth.NewSessions(u, signer, time.Nanosecond, time.Hour)
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareRejectsTokenForRemovedUser(t *testing.T) {
	issuer := sessions(t, adminUser(t))
	tok := accessToken(t, issuer)
	// Same secret, but the user is no longer configured — as after an operator
	// removes a credential and restarts.
	other := sessions(t, auth.User{Username: "someone-else", PasswordHash: hash(t, "x")})

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	other.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareCookieMutationRequiresSameOrigin(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	cases := map[string]struct {
		origin    string
		fetchSit  string
		forwarded string
		want      int
	}{
		"same-origin header":   {origin: "http://example.test", want: http.StatusOK},
		"no origin at all":     {want: http.StatusOK},
		"sec-fetch-site same":  {fetchSit: "same-origin", want: http.StatusOK},
		"cross-site origin":    {origin: "http://evil.test", want: http.StatusForbidden},
		"sec-fetch-site cross": {fetchSit: "cross-site", want: http.StatusForbidden},
		"same host, wrong scheme": {
			origin: "http://example.test", forwarded: "https", want: http.StatusForbidden,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader(`{}`))
			req.Host = "example.test"
			req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: tok})
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.fetchSit != "" {
				req.Header.Set("Sec-Fetch-Site", tc.fetchSit)
			}
			if tc.forwarded != "" {
				req.Header.Set("X-Forwarded-Proto", tc.forwarded)
			}
			rec := httptest.NewRecorder()
			s.Middleware(okHandler()).ServeHTTP(rec, req)
			assert.Equal(t, tc.want, rec.Code)
		})
	}
}

func TestMiddlewareBearerMutationSkipsOriginCheck(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader(`{}`))
	req.Host = "example.test"
	req.Header.Set("Origin", "http://evil.test") // cannot be forged onto a bearer call
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddlewareGETSkipsOriginCheck(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Host = "example.test"
	req.Header.Set("Origin", "http://evil.test")
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: tok})
	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, req)

	// SameSite=Strict keeps the cookie off a cross-site GET anyway, and a read
	// is not a state change: the origin rule guards mutations only.
	assert.Equal(t, http.StatusOK, rec.Code)
}
