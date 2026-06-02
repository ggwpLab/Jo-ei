//go:build integration

package integration_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_RubyGemsFallsBackToSecondUpstream(t *testing.T) {
	createdAt := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/versions/") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"number":"7.0.4","platform":"ruby","created_at":"` + createdAt + `","licenses":["MIT"],"sha":"abc123"}]`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("gem-bytes"))
	}))
	defer up.Close()

	dir := t.TempDir()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)

	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewRubyGemsAdapter([]string{down.URL, up.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   &localCacheAdapter{lc: lc},
		Logger:  zerolog.Nop(),
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/gems/rails-7.0.4.gem")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
