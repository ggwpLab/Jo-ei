package proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCache is an in-memory ArtifactCache for handler tests.
// Put copies the artifact to its own temp file so the entry survives
// the handler's defer os.Remove(tmpPath) after the first request.
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
	// Copy the artifact to a new temp file so the entry persists independently
	// of the handler's defer os.Remove(tmpPath).
	src, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.CreateTemp("", "fakecache-*")
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		os.Remove(dst.Name())
		return err
	}

	f.entries[ref.Key()] = &proxy.ArtifactEntry{ArtifactPath: dst.Name(), ScanClean: clean}
	return nil
}

func (f *fakeCache) Invalidate(ref *proxy.PackageRef) error {
	if e, ok := f.entries[ref.Key()]; ok {
		os.Remove(e.ArtifactPath)
	}
	delete(f.entries, ref.Key())
	return nil
}

func setupTestProxy(t *testing.T, upstream *httptest.Server, mode string) *httptest.Server {
	t.Helper()

	adapter := adapters.NewPyPIAdapter([]string{upstream.URL})
	sc := supplychain.NewFilter(config.SupplyChainConfig{
		MinAgeHours: 24,
		Mode:        mode,
	}, nil)
	fc := newFakeCache()
	logger := zerolog.Nop()

	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapter,
		Filter:  sc,
		Cache:   fc,
		Logger:  logger,
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

func TestHandler_CacheHitAvoidsDuplicateUpstreamCall(t *testing.T) {
	callCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
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
	defer upstream.Close()

	srv := setupTestProxy(t, upstream, "enforce")
	defer srv.Close()

	url := srv.URL + "/packages/py3/f/flask/flask-3.0.0-py3-none-any.whl"

	// First request: cache miss, hits upstream
	resp1, err := http.Get(url)
	require.NoError(t, err)
	resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	countAfterFirst := callCount

	// Second request: should use fakeCache (returns same entry)
	// fakeCache.Get returns the entry stored in first Put
	resp2, err := http.Get(url)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	assert.Equal(t, "HIT", resp2.Header.Get("X-SCA-Proxy-Cache"))
	// Upstream call count should not increase on cache hit
	assert.Equal(t, countAfterFirst, callCount)
}

func TestHandler_MetadataFailureReturns502(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/pypi/") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte("content"))
	}))
	defer upstream.Close()

	srv := setupTestProxy(t, upstream, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

// ─── mock CVE scanner / policy decider ────────────────────────────────────

type mockScanner struct {
	result *proxy.ScanResult
	err    error
}

func (m *mockScanner) Scan(_ context.Context, _ *proxy.PackageRef) (*proxy.ScanResult, error) {
	return m.result, m.err
}

type mockPolicy struct {
	decision proxy.PolicyDecision
}

func (m *mockPolicy) Evaluate(_ *proxy.PackageRef, _ *proxy.ScanResult) proxy.PolicyDecision {
	return m.decision
}

// setupTestProxyCVE creates a proxy handler with CVE scanner and policy decider wired in.
func setupTestProxyCVE(t *testing.T, upstream *httptest.Server, sc proxy.CVEScanner, pol proxy.PolicyDecider) *httptest.Server {
	t.Helper()
	filter := supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil)
	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:     filter,
		Cache:      newFakeCache(),
		Logger:     zerolog.Nop(),
		CVEScanner: sc,
		Policy:     pol,
	})
	return httptest.NewServer(handler)
}

func TestHandler_CVEFoundReturns403(t *testing.T) {
	upstream := makeUpstream(t, "requests", "2.28.0", 48)
	defer upstream.Close()

	sc := &mockScanner{result: &proxy.ScanResult{
		Clean:    false,
		Findings: []proxy.CVEFinding{{ID: "CVE-2024-001", Severity: proxy.SeverityHigh, Summary: "RCE"}},
	}}
	pol := &mockPolicy{decision: proxy.PolicyDecision{
		Allowed:  false,
		Reason:   "cve_found",
		Findings: []proxy.CVEFinding{{ID: "CVE-2024-001", Severity: proxy.SeverityHigh, Summary: "RCE"}},
	}}

	srv := setupTestProxyCVE(t, upstream, sc, pol)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.28.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "package_blocked", body["error"])
	assert.Equal(t, "cve_found", body["reason"])
	cves, ok := body["cves"].([]any)
	require.True(t, ok)
	assert.Len(t, cves, 1)
}

func TestHandler_NoCVEScannerAllows(t *testing.T) {
	upstream := makeUpstream(t, "safe-pkg", "1.0.0", 48)
	defer upstream.Close()

	// CVEScanner is nil — no scanning
	srv := setupTestProxyCVE(t, upstream, nil, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/s/safe-pkg/safe_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandler_CVEScannerErrorFailsClosed(t *testing.T) {
	upstream := makeUpstream(t, "pkg", "1.0.0", 48)
	defer upstream.Close()

	sc := &mockScanner{err: fmt.Errorf("osv.dev unavailable")}
	srv := setupTestProxyCVE(t, upstream, sc, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/p/pkg/pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// ─── mock AV scanner ──────────────────────────────────────────────────────

type mockAVScanner struct {
	result *proxy.AVResult
	err    error
}

func (m *mockAVScanner) Scan(_ context.Context, _ string) (*proxy.AVResult, error) {
	return m.result, m.err
}

// setupTestProxyAV wires an AV scanner into the handler (no CVE scanner).
func setupTestProxyAV(t *testing.T, upstream *httptest.Server, av proxy.AVScanner) *httptest.Server {
	t.Helper()
	filter := supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil)
	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:   adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:    filter,
		Cache:     newFakeCache(),
		Logger:    zerolog.Nop(),
		AVScanner: av,
	})
	return httptest.NewServer(handler)
}

func TestHandler_MalwareReturns403(t *testing.T) {
	upstream := makeUpstream(t, "evil-pkg", "1.0.0", 48)
	defer upstream.Close()

	av := &mockAVScanner{result: &proxy.AVResult{Clean: false, Signature: "Win.Test.EICAR", Engine: "clamav"}}
	srv := setupTestProxyAV(t, upstream, av)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/e/evil-pkg/evil_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "package_blocked", body["error"])
	assert.Equal(t, "malware_found", body["reason"])
	assert.Equal(t, "Win.Test.EICAR", body["signature"])
	assert.Equal(t, "clamav", body["engine"])
}

func TestHandler_AVScannerErrorFailsClosed(t *testing.T) {
	upstream := makeUpstream(t, "pkg", "1.0.0", 48)
	defer upstream.Close()

	av := &mockAVScanner{err: fmt.Errorf("clamd unavailable")}
	srv := setupTestProxyAV(t, upstream, av)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/p/pkg/pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandler_CleanArtifactPassesAV(t *testing.T) {
	upstream := makeUpstream(t, "safe-pkg", "1.0.0", 48)
	defer upstream.Close()

	av := &mockAVScanner{result: &proxy.AVResult{Clean: true}}
	srv := setupTestProxyAV(t, upstream, av)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/s/safe-pkg/safe_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandler_MultiScannerReportsDetectingEngine(t *testing.T) {
	upstream := makeUpstream(t, "evil-pkg", "1.0.0", 48)
	defer upstream.Close()

	// First engine clean, second detects — verify the handler surfaces the
	// detecting engine end-to-end through a real MultiScanner.
	cleanEngine := &mockAVScanner{result: &proxy.AVResult{Clean: true, Engine: "clamav"}}
	infectedEngine := &mockAVScanner{result: &proxy.AVResult{Clean: false, Signature: "Win.Test.EICAR", Engine: "icap"}}
	multi := scanner.NewMultiScanner(cleanEngine, infectedEngine)

	srv := setupTestProxyAV(t, upstream, multi)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/e/evil-pkg/evil_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "package_blocked", body["error"])
	assert.Equal(t, "malware_found", body["reason"])
	assert.Equal(t, "Win.Test.EICAR", body["signature"])
	assert.Equal(t, "icap", body["engine"])
}

// ─── download fallback tests ───────────────────────────────────────────────

// setupTwoUpstreamProxy builds a PyPI handler over [first, second].
func setupTwoUpstreamProxy(t *testing.T, first, second *httptest.Server) *httptest.Server {
	t.Helper()
	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewPyPIAdapter([]string{first.URL, second.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   newFakeCache(),
		Logger:  zerolog.Nop(),
	})
	return httptest.NewServer(handler)
}

func TestHandler_DownloadFallsBackToSecondUpstream(t *testing.T) {
	published := time.Now().UTC().Add(-48 * time.Hour)
	metaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/pypi/") {
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{"name": "requests", "version": "2.31.0", "license": "MIT", "author": "x"},
				"urls": []map[string]any{{
					"upload_time_iso_8601": published.Format(time.RFC3339),
					"url":                  "https://example.com/requests.whl",
					"digests":              map[string]any{"sha256": "abc"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound) // artifact missing here
	}))
	defer metaSrv.Close()
	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("wheel-bytes"))
	}))
	defer artifactSrv.Close()

	srv := setupTwoUpstreamProxy(t, metaSrv, artifactSrv)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "wheel-bytes", string(body))
}

func TestHandler_DownloadAllNotFoundReturns404(t *testing.T) {
	published := time.Now().UTC().Add(-48 * time.Hour)
	meta := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/pypi/") {
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{"name": "requests", "version": "2.31.0", "license": "MIT", "author": "x"},
				"urls": []map[string]any{{
					"upload_time_iso_8601": published.Format(time.RFC3339),
					"url":                  "https://example.com/requests.whl",
					"digests":              map[string]any{"sha256": "abc"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
	a := httptest.NewServer(http.HandlerFunc(meta))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(meta))
	defer b.Close()

	srv := setupTwoUpstreamProxy(t, a, b)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandler_TransparentProxyFallsBackToSecondUpstream(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("simple-index-html"))
	}))
	defer up.Close()

	srv := setupTwoUpstreamProxy(t, down, up)
	defer srv.Close()

	// /simple/ is a metadata path (not intercepted) → transparent proxy.
	resp, err := http.Get(srv.URL + "/simple/requests/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "simple-index-html", string(body))
}

func TestHandler_TransparentProxyAllNotFoundReturns404(t *testing.T) {
	down1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down1.Close()
	down2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down2.Close()

	srv := setupTwoUpstreamProxy(t, down1, down2)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/simple/nonexistent/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandler_DownloadServerErrorReturns502(t *testing.T) {
	published := time.Now().UTC().Add(-48 * time.Hour)
	meta := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/pypi/") {
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{"name": "requests", "version": "2.31.0", "license": "MIT", "author": "x"},
				"urls": []map[string]any{{
					"upload_time_iso_8601": published.Format(time.RFC3339),
					"url":                  "https://example.com/requests.whl",
					"digests":              map[string]any{"sha256": "abc"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError) // not a 404
	}
	a := httptest.NewServer(http.HandlerFunc(meta))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(meta))
	defer b.Close()

	srv := setupTwoUpstreamProxy(t, a, b)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}
