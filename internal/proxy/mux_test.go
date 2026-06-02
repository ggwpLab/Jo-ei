package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildHandlerFor wires a minimal handler for a single registry adapter.
func buildHandlerFor(adapter proxy.RegistryAdapter) *proxy.Handler {
	return proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapter,
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   newFakeCache(),
		Logger:  zerolog.Nop(),
	})
}

func TestMux_StripsPrefixAndRoutesToPyPI(t *testing.T) {
	// Upstream asserts it receives the prefix-stripped path.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/simple/requests/", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>simple</html>"))
	}))
	defer upstream.Close()

	mux := proxy.NewMux(map[string]*proxy.Handler{
		"pypi": buildHandlerFor(adapters.NewPyPIAdapter([]string{upstream.URL})),
	}, zerolog.Nop())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/pypi/simple/requests/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMux_UnknownPrefixReturns404(t *testing.T) {
	mux := proxy.NewMux(map[string]*proxy.Handler{}, zerolog.Nop())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/rubygems/foo")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestMux_HealthEndpoint(t *testing.T) {
	mux := proxy.NewMux(map[string]*proxy.Handler{}, zerolog.Nop())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
