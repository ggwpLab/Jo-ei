package proxy_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

type proxyAdapter = gate.RegistryAdapter

func mavenAdapter(upstreams []string, opts ...adapters.Option) proxyAdapter {
	return adapters.NewMavenAdapter(upstreams, opts...)
}

func pypiAdapter(upstreams []string, opts ...adapters.Option) proxyAdapter {
	return adapters.NewPyPIAdapter(upstreams, opts...)
}

func statusServer(status int, retryAfter string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
	}))
}

// throttledHandler builds a handler over upstreams whose traffic goes through
// a circuit breaker that also serves as the handler's throttle lookup, as in
// production.
func throttledHandler(t *testing.T, adapter func(upstreams []string, opts ...adapters.Option) proxyAdapter, upstreams []string, logBuf *bytes.Buffer) http.Handler {
	t.Helper()
	cb := httpx.NewCircuitBreaker(http.DefaultTransport, time.Millisecond, time.Minute)
	client := &http.Client{Transport: cb}
	return proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapter(upstreams, adapters.WithHTTPClient(client)),
		Filter:     supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:      newFakeCache(),
		Logger:     zerolog.New(logBuf),
		HTTPClient: client,
		Throttles:  cb,
	})
}

func retryAfterSeconds(t *testing.T, h http.Header) int {
	t.Helper()
	v := h.Get("Retry-After")
	require.NotEmpty(t, v, "Retry-After header")
	n, err := strconv.Atoi(v)
	require.NoError(t, err, "Retry-After must be delta-seconds")
	return n
}

// The reported case: a Maven artifact absent from one mirror while another
// throttles. That is not proof of absence and not an outage: 429, with the
// throttled mirror's Retry-After, instead of a misleading 502.
func TestHandler_DownloadNotFoundPlusThrottledReturns429(t *testing.T) {
	missing := statusServer(http.StatusNotFound, "")
	defer missing.Close()
	throttled := statusServer(http.StatusTooManyRequests, "30")
	defer throttled.Close()

	var logBuf bytes.Buffer
	h := throttledHandler(t, mavenAdapter, []string{missing.URL, throttled.URL}, &logBuf)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/com/example/lib/1.0.0/lib-1.0.0.jar", nil))

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Contains(t, rec.Body.String(), "upstream_throttled")
	got := retryAfterSeconds(t, rec.Header())
	assert.True(t, got == 30 || got == 31, "Retry-After = %d, want the upstream's 30s", got)
	assert.True(t, strings.Contains(logBuf.String(), "upstream_attempts"), "log keeps the attempt array")

	// The breaker is now open on the throttled mirror: a second request is
	// fast-failed there and must still read as a throttle, not a 502.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/com/example/lib/1.0.0/lib-1.0.0.jar", nil))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
}

// A 503 from the only other mirror answers 503, not 429.
func TestHandler_DownloadNotFoundPlusUnavailableReturns503(t *testing.T) {
	missing := statusServer(http.StatusNotFound, "")
	defer missing.Close()
	unavailable := statusServer(http.StatusServiceUnavailable, "")
	defer unavailable.Close()

	var logBuf bytes.Buffer
	h := throttledHandler(t, mavenAdapter, []string{missing.URL, unavailable.URL}, &logBuf)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/com/example/lib/1.0.0/lib-1.0.0.jar", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	// No upstream Retry-After: the breaker's own backoff is still the honest hint.
	assert.GreaterOrEqual(t, retryAfterSeconds(t, rec.Header()), 1)
}

// A genuine failure on any mirror keeps the 502, throttle or not.
func TestHandler_DownloadServerErrorPlusThrottledStays502(t *testing.T) {
	broken := statusServer(http.StatusInternalServerError, "")
	defer broken.Close()
	throttled := statusServer(http.StatusTooManyRequests, "30")
	defer throttled.Close()

	var logBuf bytes.Buffer
	h := throttledHandler(t, mavenAdapter, []string{broken.URL, throttled.URL}, &logBuf)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/com/example/lib/1.0.0/lib-1.0.0.jar", nil))
	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Empty(t, rec.Header().Get("Retry-After"))
}

// Without a throttle lookup the status still follows the rule; only the
// Retry-After hint is missing.
func TestHandler_ThrottleWithoutLookupHasNoRetryAfter(t *testing.T) {
	missing := statusServer(http.StatusNotFound, "")
	defer missing.Close()
	throttled := statusServer(http.StatusTooManyRequests, "30")
	defer throttled.Close()

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewMavenAdapter([]string{missing.URL, throttled.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   newFakeCache(),
		Logger:  zerolog.Nop(),
	})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/com/example/lib/1.0.0/lib-1.0.0.jar", nil))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Empty(t, rec.Header().Get("Retry-After"))
}

// Metadata fetched before the download (PyPI) follows the same rule.
func TestHandler_MetadataNotFoundPlusThrottledReturns429(t *testing.T) {
	missing := statusServer(http.StatusNotFound, "")
	defer missing.Close()
	throttled := statusServer(http.StatusTooManyRequests, "12")
	defer throttled.Close()

	var logBuf bytes.Buffer
	h := throttledHandler(t, pypiAdapter, []string{missing.URL, throttled.URL}, &logBuf)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl", nil))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	got := retryAfterSeconds(t, rec.Header())
	assert.True(t, got == 12 || got == 13, "Retry-After = %d, want ~12", got)
}

// A transparent (non-intercepted) request follows the same rule.
func TestHandler_TransparentNotFoundPlusThrottledReturns429(t *testing.T) {
	missing := statusServer(http.StatusNotFound, "")
	defer missing.Close()
	throttled := statusServer(http.StatusTooManyRequests, "5")
	defer throttled.Close()

	var logBuf bytes.Buffer
	h := throttledHandler(t, pypiAdapter, []string{missing.URL, throttled.URL}, &logBuf)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/simple/requests/", nil))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	got := retryAfterSeconds(t, rec.Header())
	assert.True(t, got == 5 || got == 6, "Retry-After = %d, want ~5", got)
}
