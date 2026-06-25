//go:build integration

package integration_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

// TestIntegration_MavenFallsBackToSecondUpstream verifies that when the first
// upstream returns 404 for every request, the proxy transparently falls back to
// the second upstream and serves the artifact with HTTP 200.
func TestIntegration_MavenFallsBackToSecondUpstream(t *testing.T) {
	lastModified := time.Now().UTC().Add(-72 * time.Hour)

	// First upstream: always 404.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()

	// Second upstream: serves the .jar body with a Last-Modified that satisfies
	// the 24h age check (the supply-chain date comes from the download response).
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("jar-bytes"))
	}))
	defer up.Close()

	dir := t.TempDir()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewMavenAdapter([]string{down.URL, up.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   &localCacheAdapter{lc: lc},
		Logger:  zerolog.Nop(),
	})
	mux := proxy.NewMux(map[string]*proxy.Handler{"maven": h}, nil, zerolog.Nop())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/maven/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
