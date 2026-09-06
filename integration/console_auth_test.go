//go:build integration

package integration_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/ggwpLab/Jo-ei/web"
)

// authConsoleStack mirrors cmd/jo-ei wiring: the console shell is public, the
// session endpoints are public, and sessions.Middleware gates the rest of
// /api/. users==nil yields the locked (fail-closed) state. The console
// handler logs into logBuf so attribution can be asserted.
func authConsoleStack(t *testing.T, upstream *httptest.Server, users *auth.Users, logBuf *bytes.Buffer) *httptest.Server {
	t.Helper()

	dir := t.TempDir()
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, StaleAfter: 24 * time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = localCache.Close() })

	runtime := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{}, config.PolicyProfile{}, nil,
	)
	store := newTelemetryStore(t)
	bcast := telemetry.NewBroadcaster()
	hub := &telemetry.Hub{Store: store, Broadcaster: bcast}

	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:  adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:   runtime,
		Cache:    cache.AsArtifactCache(localCache),
		Logger:   zerolog.Nop(),
		Recorder: hub,
	})
	mux := proxy.NewMux(map[string]*proxy.Handler{"pypi": handler}, nil, zerolog.Nop())

	consoleLogger := zerolog.New(logBuf)

	signer, err := auth.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	sessions := auth.NewSessions(users, signer, 15*time.Minute, 168*time.Hour)

	root := http.NewServeMux()
	root.Handle("/favicon.ico", web.FaviconHandler())
	root.Handle("/console/", web.ConsoleHandler())
	root.Handle("/api/auth/", sessions.Handler())
	root.Handle("/api/", sessions.Middleware(console.NewHandler(console.Config{
		Store: store, Broadcaster: bcast, Policy: runtime, Logger: consoleLogger,
	})))
	root.Handle("/", mux)

	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)
	return srv
}

func testUsers(t *testing.T) *auth.Users {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	require.NoError(t, err)
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: string(h)}}, "")
	require.NoError(t, err)
	return u
}

func TestConsoleAuth_ShellIsPublicButAPIIsNot(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	srv := authConsoleStack(t, upstream, testUsers(t), &bytes.Buffer{})

	shell, err := http.Get(srv.URL + "/console/")
	require.NoError(t, err)
	defer shell.Body.Close()
	assert.Equal(t, http.StatusOK, shell.StatusCode, "the login screen must load without a session")

	api, err := http.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	defer api.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, api.StatusCode)
	assert.Empty(t, api.Header.Get("WWW-Authenticate"))

	health, err := http.Get(srv.URL + "/health")
	require.NoError(t, err)
	defer health.Body.Close()
	assert.Equal(t, http.StatusOK, health.StatusCode, "/health must be open without credentials")
}

func TestConsoleAuth_LoginThenCookieAccess(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	srv := authConsoleStack(t, upstream, testUsers(t), &bytes.Buffer{})

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	login, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	require.NoError(t, err)
	defer login.Body.Close()
	require.Equal(t, http.StatusOK, login.StatusCode)

	// The jar now carries joei_at; the console makes exactly this call.
	res, err := client.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	me, err := client.Get(srv.URL + "/api/auth/me")
	require.NoError(t, err)
	defer me.Body.Close()
	body, err := io.ReadAll(me.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"username":"admin"}`, string(body))
}

func TestConsoleAuth_LoginThenBearerAccess(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	srv := authConsoleStack(t, upstream, testUsers(t), &bytes.Buffer{})

	login, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	require.NoError(t, err)
	defer login.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(login.Body).Decode(&out))
	require.NotEmpty(t, out.AccessToken)

	// The curl/CI path: no cookie jar, one header.
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/overview", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+out.AccessToken)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestConsoleAuth_RefreshKeepsSessionAliveAndLogoutEndsIt(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	srv := authConsoleStack(t, upstream, testUsers(t), &bytes.Buffer{})

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	srvURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	cookieValue := func(name string) string {
		for _, c := range jar.Cookies(srvURL) {
			if c.Name == name {
				return c.Value
			}
		}
		return ""
	}

	login, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	require.NoError(t, err)
	defer login.Body.Close()
	require.Equal(t, http.StatusOK, login.StatusCode)

	beforeAccess := cookieValue(auth.AccessCookie)
	require.NotEmpty(t, beforeAccess, "login must set the access cookie")

	refresh, err := client.Post(srv.URL+"/api/auth/refresh", "", nil)
	require.NoError(t, err)
	defer refresh.Body.Close()
	assert.Equal(t, http.StatusOK, refresh.StatusCode)

	afterAccess := cookieValue(auth.AccessCookie)
	require.NotEmpty(t, afterAccess)
	assert.NotEqual(t, beforeAccess, afterAccess,
		"refresh must mint a new access cookie, not merely succeed")

	after, err := client.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	defer after.Body.Close()
	assert.Equal(t, http.StatusOK, after.StatusCode)

	logout, err := client.Post(srv.URL+"/api/auth/logout", "", nil)
	require.NoError(t, err)
	defer logout.Body.Close()
	require.Equal(t, http.StatusNoContent, logout.StatusCode)

	gone, err := client.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	defer gone.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, gone.StatusCode)
}

func TestConsoleAuth_LockedReturns503(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	locked, err := auth.NewUsers(nil, "") // no users configured
	require.NoError(t, err)
	srv := authConsoleStack(t, upstream, locked, &bytes.Buffer{})

	res, err := http.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)

	login, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	require.NoError(t, err)
	defer login.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, login.StatusCode)

	health, err := http.Get(srv.URL + "/health")
	require.NoError(t, err)
	defer health.Body.Close()
	assert.Equal(t, http.StatusOK, health.StatusCode, "/health must still serve while /api/ is locked")
}

func TestConsoleAuth_PolicyChangeAttributed(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	var logBuf bytes.Buffer
	srv := authConsoleStack(t, upstream, testUsers(t), &logBuf)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	login, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	require.NoError(t, err)
	defer login.Body.Close()
	require.Equal(t, http.StatusOK, login.StatusCode)

	body := `{"mode":"enforce","min_age_hours":24,"cve_block_on":"HIGH","allowlist_supply":[],"allowlist_cve":[],"denylist":[]}`
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/policy", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Contains(t, logBuf.String(), `"user":"admin"`,
		"policy edit must be attributed to the authenticated user")
}
