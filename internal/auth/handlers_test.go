package auth_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

func postJSON(t *testing.T, h http.Handler, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(http.MethodPost, path, nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func cookieByName(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q cookie in the response", name)
	return nil
}

func TestLoginSetsBothCookiesAndReturnsToken(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := postJSON(t, s.Handler(), "/api/auth/login", `{"username":"admin","password":"secret"}`)

	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Username    string `json:"username"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "admin", body.Username)
	assert.NotEmpty(t, body.AccessToken)
	assert.Equal(t, 900, body.ExpiresIn) // 15 minutes

	at := cookieByName(t, rec, auth.AccessCookie)
	assert.True(t, at.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, at.SameSite)
	assert.Equal(t, "/", at.Path)
	assert.Equal(t, 900, at.MaxAge)
	assert.False(t, at.Secure, "plain HTTP must not set Secure, or the browser drops the cookie")

	rt := cookieByName(t, rec, auth.RefreshCookie)
	assert.True(t, rt.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, rt.SameSite)
	assert.Equal(t, auth.RefreshCookiePath, rt.Path)
	assert.Equal(t, 168*3600, rt.MaxAge)
	assert.False(t, rt.Secure, "plain HTTP must not set Secure, or the browser drops the cookie")
}

func TestLoginOverTLSSetsSecureCookies(t *testing.T) {
	s := sessions(t, adminUser(t))
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"secret"}`))
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, cookieByName(t, rec, auth.AccessCookie).Secure)
	assert.True(t, cookieByName(t, rec, auth.RefreshCookie).Secure)
}

func TestLoginRejectsWrongPasswordAndUnknownUserIdentically(t *testing.T) {
	s := sessions(t, adminUser(t))

	wrong := postJSON(t, s.Handler(), "/api/auth/login", `{"username":"admin","password":"nope"}`)
	unknown := postJSON(t, s.Handler(), "/api/auth/login", `{"username":"ghost","password":"nope"}`)

	assert.Equal(t, http.StatusUnauthorized, wrong.Code)
	assert.Equal(t, http.StatusUnauthorized, unknown.Code)
	assert.JSONEq(t, `{"error":"invalid_credentials"}`, wrong.Body.String())
	assert.JSONEq(t, wrong.Body.String(), unknown.Body.String(),
		"the response must not reveal whether the username exists")
	assert.Empty(t, wrong.Result().Cookies())
	assert.Empty(t, unknown.Result().Cookies())
}

func TestLoginRejectsMalformedBody(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := postJSON(t, s.Handler(), "/api/auth/login", `not json`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestLoginLockedReturns503(t *testing.T) {
	s := sessions(t) // no users
	rec := postJSON(t, s.Handler(), "/api/auth/login", `{"username":"admin","password":"secret"}`)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "auth_not_configured")
}

func TestLoginRejectsCrossSiteOrigin(t *testing.T) {
	s := sessions(t, adminUser(t))

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "example.test"
	req.Header.Set("Origin", "http://evil.test")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, rec.Result().Cookies(), "a rejected cross-site login must not set a session")
}

func TestRefreshRotatesBothCookies(t *testing.T) {
	s := sessions(t, adminUser(t))
	login := postJSON(t, s.Handler(), "/api/auth/login", `{"username":"admin","password":"secret"}`)
	oldRefresh := cookieByName(t, login, auth.RefreshCookie)

	rec := postJSON(t, s.Handler(), "/api/auth/refresh", "",
		&http.Cookie{Name: auth.RefreshCookie, Value: oldRefresh.Value})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, cookieByName(t, rec, auth.AccessCookie).Value)
	newRefresh := cookieByName(t, rec, auth.RefreshCookie)
	assert.NotEqual(t, oldRefresh.Value, newRefresh.Value, "the refresh cookie must rotate")

	var body struct {
		Username  string `json:"username"`
		ExpiresIn int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "admin", body.Username)
	assert.Equal(t, 900, body.ExpiresIn)
}

func TestRefreshWithoutCookieIs401(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := postJSON(t, s.Handler(), "/api/auth/refresh", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRefreshRejectsAnAccessToken(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)
	rec := postJSON(t, s.Handler(), "/api/auth/refresh", "",
		&http.Cookie{Name: auth.RefreshCookie, Value: tok})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRefreshRejectsCrossSiteOrigin(t *testing.T) {
	s := sessions(t, adminUser(t))
	login := postJSON(t, s.Handler(), "/api/auth/login", `{"username":"admin","password":"secret"}`)
	oldRefresh := cookieByName(t, login, auth.RefreshCookie)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.Host = "example.test"
	req.Header.Set("Origin", "http://evil.test")
	req.AddCookie(&http.Cookie{Name: auth.RefreshCookie, Value: oldRefresh.Value})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestLogoutClearsBothCookies(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := postJSON(t, s.Handler(), "/api/auth/logout", "")

	assert.Equal(t, http.StatusNoContent, rec.Code)
	paths := map[string]string{
		auth.AccessCookie:  "/",
		auth.RefreshCookie: auth.RefreshCookiePath,
	}
	for name, wantPath := range paths {
		c := cookieByName(t, rec, name)
		assert.Empty(t, c.Value)
		assert.Equal(t, -1, c.MaxAge, "MaxAge=-1 is what expires the cookie now")
		assert.Equal(t, wantPath, c.Path,
			"clearing the wrong path leaves the real cookie alive in the browser")
	}
}

func TestMeReturnsTheUsername(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: tok})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"username":"admin","role":"admin","must_change_password":false}`, rec.Body.String())
}

func TestMeWithoutSessionIs401(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/me", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMeLockedReturns503(t *testing.T) {
	s := sessions(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/me", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// me calls GET /api/auth/me with a bearer token.
func me(s *auth.Sessions, tok string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestMe_ReturnsRoleAndFlag(t *testing.T) {
	anna := operator(t, "anna", "secret")
	anna.MustChangePassword = true
	s := sessions(t, adminUser(t), anna)
	tok := loginToken(t, s, "anna", "secret")

	rec := me(s, tok)

	require.Equal(t, http.StatusOK, rec.Code, "me must work while a password change is pending")
	assert.JSONEq(t, `{"username":"anna","role":"operator","must_change_password":true}`, rec.Body.String())
}

func TestLogin_ResponseCarriesRoleAndFlag(t *testing.T) {
	anna := operator(t, "anna", "secret")
	anna.MustChangePassword = true
	s := sessions(t, adminUser(t), anna)

	rec := login(t, s, "anna", "secret")

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Role               string `json:"role"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "operator", body.Role)
	assert.True(t, body.MustChangePassword)
}

func TestLogin_CaseInsensitiveUsername(t *testing.T) {
	s := sessions(t, adminUser(t), operator(t, "anna", "secret"))

	rec := login(t, s, "ANNA", "secret")

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Username    string `json:"username"`
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "anna", body.Username, "the response carries the stored username")
	claims, err := testSigner(t).Verify(body.AccessToken, auth.TypeAccess)
	require.NoError(t, err)
	assert.Equal(t, "anna", claims.Sub, "the token subject is the stored username")
}

func TestLogin_DisabledSameAsWrongPassword(t *testing.T) {
	anna := operator(t, "anna", "secret")
	anna.Disabled = true
	s := sessions(t, adminUser(t), anna)

	disabled := login(t, s, "anna", "secret")
	wrong := login(t, s, "admin", "nope")

	assert.Equal(t, http.StatusUnauthorized, disabled.Code)
	assert.Equal(t, wrong.Code, disabled.Code)
	assert.Equal(t, wrong.Body.String(), disabled.Body.String())
	assert.Empty(t, disabled.Result().Cookies())
}

// loginFrom posts credentials from the given remote address with extra headers.
func loginFrom(t *testing.T, s *auth.Sessions, remote string, hdr map[string]string, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(string(body)))
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestLogin_RateLimited(t *testing.T) {
	var logs bytes.Buffer
	s := sessionsWith(t, newStore(adminUser(t)), auth.WithLogger(zerolog.New(&logs)))
	for i := 0; i < auth.LoginPairLimit; i++ {
		rec := loginFrom(t, s, "1.1.1.1:1", nil, "admin", "wrong")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	blocked := loginFrom(t, s, "1.1.1.1:1", nil, "admin", "secret")
	require.Equal(t, http.StatusTooManyRequests, blocked.Code, "the correct password must not get past the block")
	assert.JSONEq(t, `{"error":"too_many_attempts"}`, blocked.Body.String())
	retry, err := strconv.Atoi(blocked.Header().Get("Retry-After"))
	require.NoError(t, err)
	assert.Positive(t, retry)
	assert.LessOrEqual(t, retry, int(auth.LoginWindow.Seconds()))
	assert.Empty(t, blocked.Result().Cookies())
	assert.Contains(t, logs.String(), `"message":"login rate limited"`)

	other := loginFrom(t, s, "2.2.2.2:1", nil, "admin", "secret")
	assert.Equal(t, http.StatusOK, other.Code, "another client IP is not blocked")
}

func TestLogin_UsesClientIPResolver(t *testing.T) {
	s := sessionsWith(t, newStore(adminUser(t)),
		auth.WithClientIP(func(r *http.Request) string { return r.Header.Get("X-Test-IP") }))
	nine := map[string]string{"X-Test-IP": "9.9.9.9"}
	for i := 0; i < auth.LoginPairLimit; i++ {
		// Every attempt arrives from a different socket address: only the
		// resolver's answer may key the limiter.
		rec := loginFrom(t, s, fmt.Sprintf("10.0.0.%d:1", i), nine, "admin", "wrong")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	assert.Equal(t, http.StatusTooManyRequests, loginFrom(t, s, "10.0.0.99:1", nine, "admin", "secret").Code)
	assert.Equal(t, http.StatusOK,
		loginFrom(t, s, "10.0.0.1:1", map[string]string{"X-Test-IP": "8.8.8.8"}, "admin", "secret").Code)
}

func TestLogin_TouchesLastLogin(t *testing.T) {
	store := newStore(adminUser(t))
	s := sessionsWith(t, store)
	before := time.Now()

	require.Equal(t, http.StatusOK, login(t, s, "ADMIN", "secret").Code)

	at, ok := store.touchedAt("admin")
	require.True(t, ok, "a successful login records last_login_at under the stored name")
	assert.False(t, at.Before(before))
}

func TestLogin_FailureDoesNotTouchLastLogin(t *testing.T) {
	store := newStore(adminUser(t))
	s := sessionsWith(t, store)

	require.Equal(t, http.StatusUnauthorized, login(t, s, "admin", "wrong").Code)

	_, ok := store.touchedAt("admin")
	assert.False(t, ok)
}

func TestLogin_LogsOutcomeWithoutPassword(t *testing.T) {
	var logs bytes.Buffer
	s := sessionsWith(t, newStore(adminUser(t)), auth.WithLogger(zerolog.New(&logs)))

	require.Equal(t, http.StatusUnauthorized, login(t, s, "admin", "wrong-pw-xyz").Code)
	require.Equal(t, http.StatusOK, login(t, s, "admin", "secret").Code)

	out := logs.String()
	assert.Contains(t, out, `"message":"login failed"`)
	assert.Contains(t, out, `"message":"login succeeded"`)
	assert.Contains(t, out, `"user":"admin"`)
	assert.Contains(t, out, `"client_ip":"192.0.2.1"`)
	assert.Contains(t, out, `"component":"auth"`)
	assert.NotContains(t, out, "wrong-pw-xyz")
	assert.NotContains(t, out, `"secret"`)
}

const newPassword = "correct horse battery"

// changePassword posts to /api/auth/password with the access token as a cookie.
func changePassword(t *testing.T, s *auth.Sessions, tok, current, next string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"current": current, "new": next})
	require.NoError(t, err)
	return postJSON(t, s.Handler(), "/api/auth/password", string(body),
		&http.Cookie{Name: auth.AccessCookie, Value: tok})
}

func TestChangePassword_Success(t *testing.T) {
	var logs bytes.Buffer
	u := adminUser(t)
	u.MustChangePassword = true
	store := newStore(u)
	s := sessionsWith(t, store, auth.WithLogger(zerolog.New(&logs)))
	oldTok := accessToken(t, s)

	rec := changePassword(t, s, oldTok, "secret", newPassword)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	newCookie := cookieByName(t, rec, auth.AccessCookie)
	assert.NotEmpty(t, newCookie.Value)
	assert.NotEmpty(t, cookieByName(t, rec, auth.RefreshCookie).Value)
	var body struct {
		AccessToken        string `json:"access_token"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, newCookie.Value, body.AccessToken)
	assert.False(t, body.MustChangePassword)

	assert.Equal(t, http.StatusUnauthorized, getWithBearer(s, okHandler(), oldTok).Code,
		"the pre-change session is revoked")
	assert.Equal(t, http.StatusOK, getWithBearer(s, okHandler(), body.AccessToken).Code,
		"the re-issued session works, and is no longer gated on a password change")

	stored, err := store.Get("admin")
	require.NoError(t, err)
	assert.False(t, stored.MustChangePassword)
	assert.True(t, users.CheckPassword(stored.PasswordHash, newPassword))
	assert.Contains(t, logs.String(), `"message":"password changed"`)
	assert.NotContains(t, logs.String(), newPassword)

	assert.Equal(t, http.StatusOK, login(t, s, "admin", newPassword).Code)
	assert.Equal(t, http.StatusUnauthorized, login(t, s, "admin", "secret").Code)
}

func TestChangePassword_BearerWorks(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password",
		strings.NewReader(`{"current":"secret","new":"`+newPassword+`"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestChangePassword_WrongCurrent401(t *testing.T) {
	store := newStore(adminUser(t))
	s := sessionsWith(t, store)
	tok := accessToken(t, s)

	rec := changePassword(t, s, tok, "not-the-password", newPassword)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.JSONEq(t, `{"error":"invalid_credentials"}`, rec.Body.String())
	stored, err := store.Get("admin")
	require.NoError(t, err)
	assert.Zero(t, stored.TokenVersion, "a refused change must not revoke anything")
}

func TestChangePassword_WrongCurrentCountsAgainstLimiter(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)
	for i := 0; i < auth.LoginPairLimit; i++ {
		require.Equal(t, http.StatusUnauthorized, changePassword(t, s, tok, "wrong", newPassword).Code)
	}

	rec := changePassword(t, s, tok, "secret", newPassword)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Equal(t, http.StatusTooManyRequests, login(t, s, "admin", "secret").Code,
		"failed current-password checks share the login limiter")
}

func TestChangePassword_TooShort400(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	rec := changePassword(t, s, tok, "secret", "short")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "invalid_password", body.Error)
	assert.NotEmpty(t, body.Message)
}

func TestChangePassword_SameAsCurrent400(t *testing.T) {
	s := sessions(t, users.User{Username: "admin", PasswordHash: hash(t, newPassword), Role: users.RoleAdmin})
	tok := loginToken(t, s, "admin", newPassword)

	rec := changePassword(t, s, tok, newPassword, newPassword)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), `"error":"invalid_password"`)
}

func TestChangePassword_AllowedWhileMustChange(t *testing.T) {
	anna := operator(t, "anna", "secret")
	anna.MustChangePassword = true
	store := newStore(adminUser(t), anna)
	s := sessionsWith(t, store)
	tok := loginToken(t, s, "anna", "secret")
	require.Equal(t, http.StatusForbidden, getWithBearer(s, okHandler(), tok).Code)

	rec := changePassword(t, s, tok, "secret", newPassword)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	stored, err := store.Get("anna")
	require.NoError(t, err)
	assert.False(t, stored.MustChangePassword)
}

func TestChangePassword_RequiresSession(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := postJSON(t, s.Handler(), "/api/auth/password", `{"current":"secret","new":"`+newPassword+`"}`)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestChangePassword_RejectsCrossSiteOrigin(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password",
		strings.NewReader(`{"current":"secret","new":"`+newPassword+`"}`))
	req.Host = "example.test"
	req.Header.Set("Origin", "http://evil.test")
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: tok})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}
