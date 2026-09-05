package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
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
	assert.Equal(t, auth.RefreshCookiePath, rt.Path)
	assert.Equal(t, 168*3600, rt.MaxAge)
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

func TestLogoutClearsBothCookies(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := postJSON(t, s.Handler(), "/api/auth/logout", "")

	assert.Equal(t, http.StatusNoContent, rec.Code)
	for _, name := range []string{auth.AccessCookie, auth.RefreshCookie} {
		c := cookieByName(t, rec, name)
		assert.Empty(t, c.Value)
		assert.Equal(t, -1, c.MaxAge, "MaxAge=-1 is what expires the cookie now")
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
	assert.JSONEq(t, `{"username":"admin"}`, rec.Body.String())
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
