//go:build integration

package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// localCacheAdapter bridges cache.LocalCache to proxy.ArtifactCache for tests.
type localCacheAdapter struct {
	lc *cache.LocalCache
}

func (a *localCacheAdapter) Get(ref *proxy.PackageRef) (*proxy.ArtifactEntry, bool) {
	entry, found := a.lc.Get(ref)
	if !found {
		return nil, false
	}
	return &proxy.ArtifactEntry{ArtifactPath: entry.ArtifactPath, ScanClean: entry.ScanClean}, true
}
func (a *localCacheAdapter) Put(ref *proxy.PackageRef, tmpPath string, clean bool, scanJSON string) error {
	return a.lc.Put(ref, tmpPath, clean, scanJSON)
}
func (a *localCacheAdapter) Invalidate(ref *proxy.PackageRef) error {
	return a.lc.Invalidate(ref)
}

// newTestRegistry creates a mock PyPI server serving a single package version.
func newTestRegistry(t *testing.T, packageName, version string, ageHours int) *httptest.Server {
	t.Helper()
	publishedAt := time.Now().UTC().Add(-time.Duration(ageHours) * time.Hour)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pypi/"+packageName+"/"+version+"/json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{
					"name": packageName, "version": version,
					"license": "MIT", "author": "test",
				},
				"urls": []map[string]any{{
					"upload_time_iso_8601": publishedAt.Format(time.RFC3339),
					"url":                 "https://example.com/" + packageName + ".whl",
					"digests":             map[string]any{"sha256": "abc123"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fake-wheel-content-for-" + packageName + "-" + version))
	}))
}

func newTestProxy(t *testing.T, upstream *httptest.Server, mode string) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:  dir,
		MaxSizeGB: 1,
		TTL:       24 * time.Hour,
	})
	require.NoError(t, err)

	adapter := adapters.NewPyPIAdapter([]string{upstream.URL})
	filter := supplychain.NewFilter(config.SupplyChainConfig{
		MinAgeHours: 24,
		Mode:        mode,
	}, nil)

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapter,
		Filter:  filter,
		Cache:   &localCacheAdapter{lc: localCache},
		Logger:  zerolog.Nop(),
	})

	return httptest.NewServer(h)
}

func TestIntegration_OldPackageAllowed(t *testing.T) {
	registry := newTestRegistry(t, "requests", "2.31.0", 48)
	defer registry.Close()

	srv := newTestProxy(t, registry, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_NewPackageBlocked(t *testing.T) {
	registry := newTestRegistry(t, "malicious-pkg", "1.0.0", 1)
	defer registry.Close()

	srv := newTestProxy(t, registry, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/m/malicious-pkg/malicious_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusLocked, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "package_blocked", body["error"])
	assert.Equal(t, "package_version_newer_than_24h", body["reason"])
}

func TestIntegration_CacheHitNoUpstreamOnSecondRequest(t *testing.T) {
	requestCount := 0
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path == "/pypi/flask/3.0.0/json" {
			publishedAt := time.Now().UTC().Add(-48 * time.Hour)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{"name": "flask", "version": "3.0.0", "license": "BSD", "author": "PF"},
				"urls": []map[string]any{{
					"upload_time_iso_8601": publishedAt.Format(time.RFC3339),
					"url":                 "https://files.example.com/flask-3.0.0.whl",
					"digests":             map[string]any{"sha256": "def456"},
				}},
			})
			return
		}
		w.Write([]byte("flask-wheel"))
	}))
	defer registry.Close()

	srv := newTestProxy(t, registry, "enforce")
	defer srv.Close()

	url := srv.URL + "/packages/py3/f/flask/flask-3.0.0-py3-none-any.whl"

	// First request — cache miss
	resp1, err := http.Get(url)
	require.NoError(t, err)
	resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	countAfterFirst := requestCount

	// Second request — cache hit (LocalCache, not fakeCache)
	resp2, err := http.Get(url)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	assert.Equal(t, "HIT", resp2.Header.Get("X-Joei-Cache"))

	// Upstream must not be contacted on second request
	assert.Equal(t, countAfterFirst, requestCount)
}

func TestIntegration_DryRunPassesNewPackage(t *testing.T) {
	registry := newTestRegistry(t, "brand-new-pkg", "0.1.0", 1)
	defer registry.Close()

	srv := newTestProxy(t, registry, "dry_run")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/b/brand-new-pkg/brand_new_pkg-0.1.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_HealthEndpointAvailable(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer registry.Close()

	srv := newTestProxy(t, registry, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
