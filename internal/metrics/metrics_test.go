package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/client_golang/prometheus/testutil/promlint"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
)

// newFullyWired returns a Metrics whose every metric has been touched so
// registry-wide checks (lint, drift) see all series. Later tasks extend it.
func newFullyWired(t *testing.T) *Metrics {
	t.Helper()
	m := New(BuildInfo{Version: "1.2.3", Commit: "abc"}, zerolog.Nop())
	m.WrapHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), NewRouteFunc([]string{"pypi"})).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/pypi/x", nil))
	// A cancelled client touches the aborted counter so it appears in Gather.
	abortedCtx, cancel := context.WithCancel(context.Background())
	cancel()
	m.WrapHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), NewRouteFunc([]string{"pypi"})).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/pypi/x", nil).WithContext(abortedCtx))
	failing := m.WrapTransport(rtFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	}), []string{"pypi.org"})
	req, _ := http.NewRequest(http.MethodGet, "https://pypi.org/x", nil)
	_, _ = failing.RoundTrip(req)
	req, _ = http.NewRequest(http.MethodGet, "https://pypi.org/y", nil)
	_, _ = m.WrapTransport(okRT(), []string{"pypi.org"}).RoundTrip(req)
	m.RegisterCircuitBreaker(fakeReporter{open: []string{"pypi.org"}}, []string{"pypi.org"})
	for _, f := range []fakeAV{{res: &gate.AVResult{Clean: true}}, {res: &gate.AVResult{}}, {err: context.DeadlineExceeded}} {
		_, _ = m.WrapAVScanner("clamav", f).Scan(context.Background(), "f")
	}
	m.SetScanConcurrencyLimit(8)
	m.ScanWaitObserver()(time.Millisecond)
	m.RegisterScannerHealth(func() []health.ScannerHealth {
		return []health.ScannerHealth{{Name: "clamav", Status: health.StatusOK, Enabled: true}}
	}, nil)
	m.WrapRecorder(&fakeRecorder{}).Record(gate.Event{Ecosystem: "npm", Verdict: gate.VerdictPass, Gate: gate.GateCVE})
	m.RegisterCache(fakeStatter{stats: cache.CacheStats{SizeBytes: 1024}}, 4096)
	return m
}

// filterJoEi keeps only lint problems for Jō-ei's own metrics; go_* and
// process_* come from third-party collectors.
func filterJoEi(problems []promlint.Problem) []promlint.Problem {
	var out []promlint.Problem
	for _, p := range problems {
		if strings.HasPrefix(p.Metric, "jo_ei_") {
			out = append(out, p)
		}
	}
	return out
}

func TestNew_RegistersRuntimeProcessAndBuildInfo(t *testing.T) {
	m := New(BuildInfo{Version: "1.2.3", Commit: "abc"}, zerolog.Nop())
	mfs, err := m.Registry.Gather()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	for _, n := range []string{"go_goroutines", "go_gc_duration_seconds", "jo_ei_build_info"} {
		assert.True(t, names[n], n)
	}
	// process_* only where procfs works.
	if runtime.GOOS == "linux" {
		assert.True(t, names["process_cpu_seconds_total"])
	}
}

func TestBuildInfoLabels(t *testing.T) {
	m := New(BuildInfo{Version: "1.2.3", Commit: "abc"}, zerolog.Nop())
	expected := `# HELP jo_ei_build_info Build information; value is always 1.
# TYPE jo_ei_build_info gauge
jo_ei_build_info{commit="abc",goversion="` + runtime.Version() + `",version="1.2.3"} 1
`
	require.NoError(t, testutil.GatherAndCompare(m.Registry, strings.NewReader(expected), "jo_ei_build_info"))
}

func TestHandler_ServesOpenMetricsAndSelfMetrics(t *testing.T) {
	m := New(BuildInfo{Version: "1.2.3", Commit: "abc"}, zerolog.Nop())
	h := m.Handler()
	get := func() string {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		require.Equal(t, http.StatusOK, rec.Code)
		b, err := io.ReadAll(rec.Body)
		require.NoError(t, err)
		return string(b)
	}
	assert.Contains(t, get(), "jo_ei_build_info")
	assert.Contains(t, get(), "promhttp_metric_handler_requests_total")
}

func TestNoDefaultRegistererPollution(t *testing.T) {
	assert.NotPanics(t, func() {
		New(BuildInfo{}, zerolog.Nop())
		New(BuildInfo{}, zerolog.Nop())
	})
}

func TestLint(t *testing.T) {
	m := newFullyWired(t)
	problems, err := testutil.GatherAndLint(m.Registry)
	require.NoError(t, err)
	assert.Empty(t, filterJoEi(problems))
}

func TestOneOf(t *testing.T) {
	allowed := map[string]struct{}{"a": {}}
	assert.Equal(t, "a", oneOf("a", allowed))
	assert.Equal(t, "other", oneOf("zzz", allowed))
}

func TestDurationHistogramOpts(t *testing.T) {
	o := newDurationHistogramOpts("jo_ei_x_seconds", "h")
	assert.Equal(t, durationBuckets, o.Buckets)
	assert.Equal(t, 1.1, o.NativeHistogramBucketFactor)
}
