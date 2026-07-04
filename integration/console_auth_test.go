//go:build integration

package integration_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
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
)

// authConsoleStack mirrors cmd/jo-ei wiring with auth.Middleware wrapping the
// /api/ handler. users==nil yields the locked (fail-closed) state. The console
// handler logs into logBuf so attribution can be asserted.
func authConsoleStack(t *testing.T, upstream *httptest.Server, users *auth.Users, logBuf *bytes.Buffer) *httptest.Server {
	t.Helper()

	dir := t.TempDir()
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: 24 * time.Hour})
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
		Cache:    &localCacheAdapter{lc: localCache},
		Logger:   zerolog.Nop(),
		Recorder: hub,
	})
	mux := proxy.NewMux(map[string]*proxy.Handler{"pypi": handler}, nil, zerolog.Nop())

	consoleLogger := zerolog.New(logBuf)
	root := http.NewServeMux()
	root.Handle("/api/", users.Middleware(console.NewHandler(console.Config{
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

func TestConsoleAuth_RequiresCredentials(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	srv := authConsoleStack(t, upstream, testUsers(t), &bytes.Buffer{})

	// No credentials -> 401.
	resp, err := http.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Basic realm=")

	// Wrong password -> 401.
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/overview", nil)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "wrong")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Correct credentials -> 200.
	req, err = http.NewRequest(http.MethodGet, srv.URL+"/api/overview", nil)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "s3cret")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// /health is open without credentials.
	resp, err = http.Get(srv.URL + "/health")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestConsoleAuth_LockedReturns503(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()

	locked, err := auth.NewUsers(nil, "") // no users
	require.NoError(t, err)
	srv := authConsoleStack(t, upstream, locked, &bytes.Buffer{})

	resp, err := http.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	// Proxy/health still serve while the console is locked.
	resp, err = http.Get(srv.URL + "/health")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestConsoleAuth_PolicyChangeAttributed(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	var logBuf bytes.Buffer
	srv := authConsoleStack(t, upstream, testUsers(t), &logBuf)

	body := `{"mode":"enforce","min_age_hours":24,"cve_block_on":"HIGH","allowlist_supply":[],"allowlist_cve":[],"denylist":[]}`
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/policy", strings.NewReader(body))
	require.NoError(t, err)
	req.SetBasicAuth("admin", "s3cret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Contains(t, logBuf.String(), `"user":"admin"`,
		"policy edit must be attributed to the authenticated user")
}
