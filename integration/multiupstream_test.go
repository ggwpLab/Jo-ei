//go:build integration

package integration_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sca-proxy/sca-proxy/internal/cache"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// Second upstream: serves .pom HEAD (with a Last-Modified that satisfies the
	// 24h age check) and the .jar body.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".pom") {
			w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("jar-bytes"))
	}))
	defer up.Close()

	dir := t.TempDir()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewMavenAdapter([]string{down.URL, up.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   &localCacheAdapter{lc: lc},
		Logger:  zerolog.Nop(),
	})
	mux := proxy.NewMux(map[string]*proxy.Handler{"maven": h}, zerolog.Nop())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/maven/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
