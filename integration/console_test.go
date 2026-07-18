//go:build integration

package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/storage/storagetest"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func newTelemetryStore(t *testing.T) *telemetry.Store {
	t.Helper()
	db, err := storage.Open(filepath.Join(storagetest.TempDir(t), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := telemetry.Open(db, 30, 365, zerolog.Nop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// consoleStack mirrors the cmd/jo-ei wiring: handler + recorder hub +
// runtime policy + console API behind one mux.
func consoleStack(t *testing.T, upstream *httptest.Server) (*httptest.Server, *policy.Runtime) {
	t.Helper()

	dir := t.TempDir()
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:   dir,
		MaxSizeGB:  1,
		StaleAfter: 24 * time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = localCache.Close() })

	runtime := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{},
		config.PolicyProfile{},
		nil,
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
	root := http.NewServeMux()
	root.Handle("/api/", console.NewHandler(console.Config{
		Store: store, Broadcaster: bcast, Policy: runtime, Logger: zerolog.Nop(),
	}))
	root.Handle("/", mux)

	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)
	return srv, runtime
}

func TestConsole_EndToEnd(t *testing.T) {
	// Upstream serving a 1h-old package (younger than the 24h min age).
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()

	srv, runtime := consoleStack(t, upstream)
	url := srv.URL + "/pypi/packages/py3/f/fresh-pkg/fresh_pkg-1.0.0-py3-none-any.whl"

	// 1. Fresh package is blocked at the supply gate (423).
	resp, err := http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusLocked, resp.StatusCode)

	// 2. The block shows up in the request feed…
	var feed struct {
		Requests []struct {
			Verdict string `json:"verdict"`
			Gate    string `json:"gate"`
			Pkg     string `json:"pkg"`
		} `json:"requests"`
	}
	getInto(t, srv.URL+"/api/requests", &feed)
	require.NotEmpty(t, feed.Requests)
	assert.Equal(t, "BLOCK", feed.Requests[0].Verdict)
	assert.Equal(t, "supply", feed.Requests[0].Gate)
	assert.Equal(t, "fresh-pkg", feed.Requests[0].Pkg)

	// 3. …and in quarantine.
	var quar struct {
		Quarantine []struct {
			Pkg string `json:"pkg"`
		} `json:"quarantine"`
	}
	getInto(t, srv.URL+"/api/quarantine", &quar)
	require.Len(t, quar.Quarantine, 1)
	assert.Equal(t, "fresh-pkg", quar.Quarantine[0].Pkg)

	// 4. PUT /api/policy lowers min_age to 0 — applies without restart.
	body := `{"mode":"enforce","min_age_hours":0,"cve_block_on":"HIGH","allowlist_supply":[],"allowlist_cve":[],"denylist":[]}`
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/policy", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	presp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	presp.Body.Close()
	require.Equal(t, http.StatusOK, presp.StatusCode)
	assert.Equal(t, 0, runtime.Current().MinAgeHours)

	// 5. The same package now passes under the new policy.
	resp, err = http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 6. Second fetch is a cache hit; overview KPIs reflect all three proxy requests.
	resp, err = http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var overview struct {
		KPIs struct {
			RequestsTotal uint64 `json:"requests_total"`
			CacheHits     uint64 `json:"cache_hits"`
			BlockedTotal  uint64 `json:"blocked_total"`
		} `json:"kpis"`
	}
	getInto(t, srv.URL+"/api/overview", &overview)
	assert.Equal(t, uint64(3), overview.KPIs.RequestsTotal)
	assert.Equal(t, uint64(1), overview.KPIs.CacheHits)
	assert.Equal(t, uint64(1), overview.KPIs.BlockedTotal)

	// 7. The earlier quarantine entry is still derived from history (its
	// BlockUntil has not expired) — acceptable: quarantine reflects past
	// block events, and the entry ages out of the ring buffer over time.
}

func getInto(t *testing.T, url string, into any) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(into))
}
