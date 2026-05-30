package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCache is an in-memory ArtifactCache for handler tests.
type fakeCache struct {
	entries map[string]*proxy.ArtifactEntry
}

func newFakeCache() *fakeCache {
	return &fakeCache{entries: map[string]*proxy.ArtifactEntry{}}
}

func (f *fakeCache) Get(ref *proxy.PackageRef) (*proxy.ArtifactEntry, bool) {
	e, ok := f.entries[ref.Key()]
	return e, ok
}
func (f *fakeCache) Put(ref *proxy.PackageRef, tmpPath string, clean bool, scanJSON string) error {
	f.entries[ref.Key()] = &proxy.ArtifactEntry{ArtifactPath: tmpPath, ScanClean: clean}
	return nil
}
func (f *fakeCache) Invalidate(ref *proxy.PackageRef) error {
	delete(f.entries, ref.Key())
	return nil
}

func setupTestProxy(t *testing.T, upstream *httptest.Server, mode string) *httptest.Server {
	t.Helper()

	adapter := adapters.NewPyPIAdapter(upstream.URL)
	sc := supplychain.NewFilter(config.SupplyChainConfig{
		MinAgeHours: 24,
		Mode:        mode,
	}, nil)
	fc := newFakeCache()
	logger := zerolog.Nop()

	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:  adapter,
		Filter:   sc,
		Cache:    fc,
		Logger:   logger,
		Upstream: upstream.URL,
	})

	return httptest.NewServer(handler)
}

func makeUpstream(t *testing.T, name, version string, ageHours int) *httptest.Server {
	t.Helper()
	publishedAt := time.Now().UTC().Add(-time.Duration(ageHours) * time.Hour)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pypi/"+name+"/"+version+"/json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{
					"name": name, "version": version,
					"license": "MIT", "author": "test",
				},
				"urls": []map[string]any{{
					"upload_time_iso_8601": publishedAt.Format(time.RFC3339),
					"url":                 "https://example.com/" + name + ".whl",
					"digests":             map[string]any{"sha256": "abc123"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("wheel-content-" + name + "-" + version))
	}))
}

func TestHandler_SimpleAPIProxiedAsIs(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/simple/requests/", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>simple API</html>"))
	}))
	defer upstream.Close()

	srv := setupTestProxy(t, upstream, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/simple/requests/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandler_BlocksNewPackage(t *testing.T) {
	upstream := makeUpstream(t, "requests", "2.32.0", 1) // 1h old
	defer upstream.Close()

	srv := setupTestProxy(t, upstream, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.32.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusLocked, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "package_blocked", body["error"])
	assert.Equal(t, "package_version_newer_than_24h", body["reason"])
}

func TestHandler_AllowsOldPackage(t *testing.T) {
	upstream := makeUpstream(t, "requests", "2.31.0", 25) // 25h old
	defer upstream.Close()

	srv := setupTestProxy(t, upstream, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandler_HealthEndpoint(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv := setupTestProxy(t, upstream, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
