package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
)

// OSV has no mirror to fail over to, so the registry circuit breaker would only
// widen one 503 from osv.dev into a cooldown that fails every CVE lookup — and,
// fail-closed, every uncached download. The OSV client must not carry it.
func TestBuildUpstream_OSVClientHasNoCircuitBreaker(t *testing.T) {
	var calls atomic.Int32
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer osv.Close()
	cfg := &config.Config{}
	cfg.CVE.BaseURL = osv.URL

	up, err := buildUpstream(cfg, nil, zerolog.Nop())
	require.NoError(t, err)

	for i, want := range []int{http.StatusServiceUnavailable, http.StatusOK} {
		resp, err := up.osv.Get(osv.URL + "/v1/query")
		require.NoError(t, err, "request %d", i)
		resp.Body.Close()
		assert.Equal(t, want, resp.StatusCode, "request %d", i)
	}
}
