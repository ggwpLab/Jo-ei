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
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

// When the primary upstream throttles (429), the circuit breaker fast-fails it
// and the handler's multi-upstream fallback serves the artifact from the mirror.
func TestHandler_MavenFallsBackToMirrorOnThrottle(t *testing.T) {
	old := time.Now().UTC().Add(-72 * time.Hour)
	var primaryHits, mirrorHits atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryHits.Add(1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer primary.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mirrorHits.Add(1)
		w.Header().Set("Last-Modified", old.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("jar-bytes"))
		}
	}))
	defer mirror.Close()

	transport := httpx.NewCircuitBreaker(
		httpx.NewRateLimiter(httpx.NewConcurrencyLimiter(http.DefaultTransport, 6), 10, 20),
		time.Second, 20*time.Second,
	)
	client := &http.Client{Timeout: 60 * time.Second, Transport: transport}

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapters.NewMavenAdapter([]string{primary.URL, mirror.URL}, adapters.WithHTTPClient(client)),
		Filter:     supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:      newFakeCache(),
		Logger:     zerolog.Nop(),
		HTTPClient: client,
	})
	req := httptest.NewRequest(http.MethodGet,
		"/com/fasterxml/classmate/1.7.3/classmate-1.7.3.jar", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("throttled-primary download failed: status=%d body=%s", w.Code, w.Body.String())
	}
	if mirrorHits.Load() == 0 {
		t.Fatalf("mirror was not used as fallback")
	}
}

// A single cold Maven dependency must download through the exact production
// transport chain (circuit breaker over rate + concurrency limiters). This pins
// down whether the Last-Modified/limiter work broke the happy path.
func TestHandler_MavenSingleDownloadThroughProductionTransport(t *testing.T) {
	old := time.Now().UTC().Add(-72 * time.Hour)
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
		}
		w.Header().Set("Last-Modified", old.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("jar-bytes"))
		}
	}))
	defer srv.Close()

	// Identical to cmd/jo-ei wiring.
	transport := httpx.NewCircuitBreaker(
		httpx.NewRateLimiter(httpx.NewConcurrencyLimiter(http.DefaultTransport, 6), 10, 20),
		time.Second, 20*time.Second,
	)
	client := &http.Client{Timeout: 60 * time.Second, Transport: transport}

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapters.NewMavenAdapter([]string{srv.URL}, adapters.WithHTTPClient(client)),
		Filter:     supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:      newFakeCache(),
		Logger:     zerolog.Nop(),
		HTTPClient: client,
	})
	req := httptest.NewRequest(http.MethodGet,
		"/com/fasterxml/classmate/1.7.3/classmate-1.7.3.jar", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("single Maven download failed: status=%d body=%s", w.Code, w.Body.String())
	}
	if gets.Load() != 1 {
		t.Fatalf("expected exactly one upstream GET, got %d", gets.Load())
	}
}

// Maven derives the supply-chain publish date from the artifact download
// response's Last-Modified, so no separate metadata HEAD is issued. A too-new
// artifact is blocked using that date.
func TestHandler_MavenSupplyChainFromDownloadNoHead(t *testing.T) {
	var headCount, getCount atomic.Int32
	recent := time.Now().UTC().Add(-1 * time.Hour) // younger than the 24h min-age
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			headCount.Add(1)
		case http.MethodGet:
			getCount.Add(1)
		}
		w.Header().Set("Last-Modified", recent.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("jar-bytes"))
		}
	}))
	defer srv.Close()

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewMavenAdapter([]string{srv.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   newFakeCache(),
		Logger:  zerolog.Nop(),
	})
	req := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusLocked, w.Code, "a recent artifact must be blocked by min-age")
	assert.Equal(t, int32(0), headCount.Load(), "no separate metadata HEAD should be issued")
	assert.GreaterOrEqual(t, getCount.Load(), int32(1), "the artifact GET supplies the date")
}

// fakeCache is an in-memory ArtifactCache for handler tests.
// Put copies the artifact to its own temp file so the entry survives
// the handler's defer os.Remove(tmpPath) after the first request.
type fakeCache struct {
	entries map[string]*gate.ArtifactEntry
}

func newFakeCache() *fakeCache {
	return &fakeCache{entries: map[string]*gate.ArtifactEntry{}}
}

func (f *fakeCache) Get(ref *gate.PackageRef) (*gate.ArtifactEntry, bool) {
	e, ok := f.entries[ref.Key()]
	return e, ok
}

func (f *fakeCache) Put(ref *gate.PackageRef, tmpPath string, clean bool, scanJSON string) error {
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

	f.entries[ref.Key()] = &gate.ArtifactEntry{ArtifactPath: dst.Name(), ScanClean: clean, LastCVECheck: time.Now(), LastMalwareCheck: time.Now()}
	return nil
}

func (f *fakeCache) Invalidate(ref *gate.PackageRef) error {
	if e, ok := f.entries[ref.Key()]; ok {
		os.Remove(e.ArtifactPath)
	}
	delete(f.entries, ref.Key())
	return nil
}

func (f *fakeCache) MarkCVEChecked(ref *gate.PackageRef, ts time.Time) error {
	if e, ok := f.entries[ref.Key()]; ok {
		e.LastCVECheck = ts
	}
	return nil
}

func (f *fakeCache) MarkMalwareChecked(ref *gate.PackageRef, ts time.Time) error {
	if e, ok := f.entries[ref.Key()]; ok {
		e.LastMalwareCheck = ts
	}
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
					"url":                  "https://example.com/" + name + ".whl",
					"digests":              map[string]any{"sha256": "abc123"},
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
	assert.Equal(t, "package_younger_than_min_age", body["reason"])
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
					"url":                  "https://files.example.com/flask-3.0.0.whl",
					"digests":              map[string]any{"sha256": "def456"},
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
	assert.Equal(t, "HIT", resp2.Header.Get("X-Joei-Cache"))
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
	result *gate.ScanResult
	err    error
}

func (m *mockScanner) Scan(_ context.Context, _ *gate.PackageRef) (*gate.ScanResult, error) {
	return m.result, m.err
}

type mockPolicy struct {
	decision gate.PolicyDecision
}

func (m *mockPolicy) Evaluate(_ *gate.PackageRef, _ *gate.ScanResult) gate.PolicyDecision {
	return m.decision
}

// setupTestProxyCVE creates a proxy handler with CVE scanner and policy decider wired in.
func setupTestProxyCVE(t *testing.T, upstream *httptest.Server, sc gate.CVEScanner, pol gate.PolicyDecider) *httptest.Server {
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

	sc := &mockScanner{result: &gate.ScanResult{
		Clean:    false,
		Findings: []gate.CVEFinding{{ID: "CVE-2024-001", Severity: gate.SeverityHigh, Summary: "RCE"}},
	}}
	pol := &mockPolicy{decision: gate.PolicyDecision{
		Allowed:  false,
		Reason:   "cve_found",
		Findings: []gate.CVEFinding{{ID: "CVE-2024-001", Severity: gate.SeverityHigh, Summary: "RCE"}},
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
	result *gate.AVResult
	err    error
}

func (m *mockAVScanner) Scan(_ context.Context, _ string) (*gate.AVResult, error) {
	return m.result, m.err
}

// setupTestProxyAV wires an AV scanner into the handler (no CVE scanner).
func setupTestProxyAV(t *testing.T, upstream *httptest.Server, av gate.AVScanner) *httptest.Server {
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

	av := &mockAVScanner{result: &gate.AVResult{Clean: false, Signature: "Win.Test.EICAR", Engine: "clamav"}}
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

	av := &mockAVScanner{result: &gate.AVResult{Clean: true}}
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
	cleanEngine := &mockAVScanner{result: &gate.AVResult{Clean: true, Engine: "clamav"}}
	infectedEngine := &mockAVScanner{result: &gate.AVResult{Clean: false, Signature: "Win.Test.EICAR", Engine: "icap"}}
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
