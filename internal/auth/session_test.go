package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

const testSecret = "0123456789abcdef0123456789abcdef"

// fakeStore is an in-memory auth.UserStore. Lookups are case-insensitive and
// return the stored username, like users.Store.
type fakeStore struct {
	mu      sync.Mutex
	byName  map[string]users.User // lower-cased username -> user
	touched map[string]time.Time
}

func newStore(us ...users.User) *fakeStore {
	f := &fakeStore{byName: map[string]users.User{}, touched: map[string]time.Time{}}
	for _, u := range us {
		f.byName[strings.ToLower(u.Username)] = u
	}
	return f
}

func (f *fakeStore) Get(username string) (users.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byName[strings.ToLower(username)]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	return u, nil
}

func (f *fakeStore) HasEnabledUsers() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.byName {
		if !u.Disabled {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) TouchLogin(username string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byName[strings.ToLower(username)]
	if !ok {
		return users.ErrNotFound
	}
	f.touched[u.Username] = at
	return nil
}

func (f *fakeStore) SetPassword(username, hash string, mustChange bool) error {
	return f.update(username, func(u *users.User) {
		u.PasswordHash = hash
		u.MustChangePassword = mustChange
		u.TokenVersion++
	})
}

// update mutates a stored user in place (disable, bump version, ...).
func (f *fakeStore) update(username string, fn func(*users.User)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.ToLower(username)
	u, ok := f.byName[key]
	if !ok {
		return users.ErrNotFound
	}
	fn(&u)
	f.byName[key] = u
	return nil
}

func (f *fakeStore) remove(username string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.byName, strings.ToLower(username))
}

func (f *fakeStore) touchedAt(username string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at, ok := f.touched[username]
	return at, ok
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func testSigner(t *testing.T) *auth.Signer {
	t.Helper()
	signer, err := auth.NewSigner([]byte(testSecret))
	require.NoError(t, err)
	return signer
}

// sessionsWith builds a Sessions over store with the default test lifetimes.
func sessionsWith(t *testing.T, store auth.UserStore, opts ...auth.Option) *auth.Sessions {
	t.Helper()
	return auth.NewSessions(store, testSigner(t), 15*time.Minute, 168*time.Hour, opts...)
}

// sessions builds a Sessions over the given users. Pass no users to get the
// locked (fail-closed) state.
func sessions(t *testing.T, us ...users.User) *auth.Sessions {
	t.Helper()
	return sessionsWith(t, newStore(us...))
}

// adminUser is "admin"/"secret" with the admin role.
func adminUser(t *testing.T) users.User {
	t.Helper()
	return users.User{Username: "admin", PasswordHash: hash(t, "secret"), Role: users.RoleAdmin}
}

// operator returns an operator account with the given name and password.
func operator(t *testing.T, name, password string) users.User {
	t.Helper()
	return users.User{Username: name, PasswordHash: hash(t, password), Role: users.RoleOperator}
}

// login posts credentials and returns the recorder.
func login(t *testing.T, s *auth.Sessions, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body)))
	return rec
}

// loginToken logs in and returns the bearer access token.
func loginToken(t *testing.T, s *auth.Sessions, username, password string) string {
	t.Helper()
	rec := login(t, s, username, password)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)
	return body.AccessToken
}

// accessToken logs in as admin/secret and returns the bearer token.
func accessToken(t *testing.T, s *auth.Sessions) string {
	t.Helper()
	return loginToken(t, s, "admin", "secret")
}

// getWithBearer runs a GET through the middleware with a bearer token.
func getWithBearer(s *auth.Sessions, h http.Handler, tok string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Middleware(h).ServeHTTP(rec, req)
	return rec
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

	assert.Equal(t, http.StatusOK, getWithBearer(s, okHandler(), tok).Code)
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
	getWithBearer(s, next, tok)

	assert.Equal(t, "admin", got)
}

func TestMiddlewareRejectsRefreshTokenAsAccess(t *testing.T) {
	s := sessions(t, adminUser(t))
	// Log in, then present the refresh cookie where the access cookie belongs.
	refresh := cookieByName(t, login(t, s, "admin", "secret"), auth.RefreshCookie).Value
	require.NotEmpty(t, refresh)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: refresh})
	out := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(out, req)

	assert.Equal(t, http.StatusUnauthorized, out.Code)
}

func TestMiddlewareRejectsExpiredToken(t *testing.T) {
	// A one-nanosecond access lifetime: the token is expired before it is read.
	s := auth.NewSessions(newStore(adminUser(t)), testSigner(t), time.Nanosecond, time.Hour)
	tok := accessToken(t, s)

	assert.Equal(t, http.StatusUnauthorized, getWithBearer(s, okHandler(), tok).Code)
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

func TestMiddleware_PutsIdentity(t *testing.T) {
	s := sessions(t, adminUser(t), operator(t, "anna", "secret"))
	tok := loginToken(t, s, "anna", "secret")

	var got auth.Identity
	var ok bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = auth.IdentityFromContext(r.Context())
	})
	getWithBearer(s, next, tok)

	require.True(t, ok)
	assert.Equal(t, auth.Identity{Username: "anna", Role: users.RoleOperator}, got)
}

func TestWithIdentityRoundTrip(t *testing.T) {
	id := auth.Identity{Username: "anna", Role: users.RoleOperator}
	ctx := auth.WithIdentity(context.Background(), id)

	got, ok := auth.IdentityFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, id, got)
	name, ok := auth.UserFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "anna", name)

	_, ok = auth.IdentityFromContext(context.Background())
	assert.False(t, ok)
	_, ok = auth.UserFromContext(context.Background())
	assert.False(t, ok)
}

func TestMiddleware_DisabledUser401(t *testing.T) {
	store := newStore(adminUser(t), operator(t, "anna", "secret"))
	s := sessionsWith(t, store)
	tok := loginToken(t, s, "anna", "secret")
	require.NoError(t, store.update("anna", func(u *users.User) { u.Disabled = true }))

	assert.Equal(t, http.StatusUnauthorized, getWithBearer(s, okHandler(), tok).Code)
}

func TestMiddleware_DeletedUser401(t *testing.T) {
	store := newStore(adminUser(t), operator(t, "anna", "secret"))
	s := sessionsWith(t, store)
	tok := loginToken(t, s, "anna", "secret")
	store.remove("anna")

	assert.Equal(t, http.StatusUnauthorized, getWithBearer(s, okHandler(), tok).Code)
}

func TestMiddleware_VersionBumpRevokes(t *testing.T) {
	store := newStore(adminUser(t))
	s := sessionsWith(t, store)
	rec := login(t, s, "admin", "secret")
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	refresh := cookieByName(t, rec, auth.RefreshCookie)
	require.Equal(t, http.StatusOK, getWithBearer(s, okHandler(), body.AccessToken).Code)

	require.NoError(t, store.update("admin", func(u *users.User) { u.TokenVersion++ }))

	assert.Equal(t, http.StatusUnauthorized, getWithBearer(s, okHandler(), body.AccessToken).Code,
		"an access token issued at the old version must stop working")
	out := postJSON(t, s.Handler(), "/api/auth/refresh", "",
		&http.Cookie{Name: auth.RefreshCookie, Value: refresh.Value})
	assert.Equal(t, http.StatusUnauthorized, out.Code,
		"a refresh token issued at the old version must not mint a new session")
	assert.Empty(t, out.Result().Cookies())
}

func TestMiddleware_MustChangePassword403(t *testing.T) {
	u := adminUser(t)
	u.MustChangePassword = true
	s := sessions(t, u)
	tok := accessToken(t, s)

	called := false
	rec := getWithBearer(s, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), tok)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.JSONEq(t, `{"error":"password_change_required"}`, rec.Body.String())
	assert.False(t, called)
}

func TestLocked_NoEnabledUsers503(t *testing.T) {
	u := adminUser(t)
	u.Disabled = true
	s := sessions(t, u)
	assert.True(t, s.Locked())

	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/x", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	assert.Equal(t, http.StatusServiceUnavailable, login(t, s, "admin", "secret").Code)
}

// brokenStore reports a database error from HasEnabledUsers.
type brokenStore struct{ *fakeStore }

func (brokenStore) HasEnabledUsers() (bool, error) { return false, errors.New("db down") }

func TestLocked_StoreErrorFailsClosed(t *testing.T) {
	s := sessionsWith(t, brokenStore{newStore(adminUser(t))})
	assert.True(t, s.Locked(), "a store error must lock the console, not open it")
}
