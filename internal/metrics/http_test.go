package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubHandler struct{}

func (*stubHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func newTestMetrics() *Metrics { return New(BuildInfo{}, zerolog.Nop()) }

func serve(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestRouteFunc(t *testing.T) {
	rf := NewRouteFunc([]string{"pypi", "npm", "yarn", "v2"})
	cases := map[string]string{
		"/pypi/simple/requests/":         "pypi",
		"/yarn/x":                        "yarn",
		"/v2/library/alpine/manifests/3": "docker",
		"/maven/x":                       "other",
		"/console/":                      "console",
		"/console":                       "console",
		"/api/auth/login":                "auth",
		"/api/overview":                  "api",
		"/health":                        "health",
		"/ready":                         "health",
		"/favicon.ico":                   "favicon",
		"/":                              "other",
		"/.well-known/x":                 "other",
	}
	for in, want := range cases {
		assert.Equal(t, want, rf(in), in)
	}
}

func TestWrapHandler_CountsCodeAndMethod(t *testing.T) {
	m := newTestMetrics()
	h := m.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}), NewRouteFunc([]string{"npm"}))
	serve(h, "PROPFIND", "/npm/x")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.http.requests.WithLabelValues("npm", "other", "404")))
}

func TestWrapHandler_ImplicitOK(t *testing.T) {
	m := newTestMetrics()
	h := m.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hi"))
	}), NewRouteFunc([]string{"npm"}))
	serve(h, http.MethodGet, "/npm/x")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.http.requests.WithLabelValues("npm", "GET", "200")))
}

func TestWrapHandler_InFlightReturnsToZero(t *testing.T) {
	m := newTestMetrics()
	var during float64
	h := m.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		during = testutil.ToFloat64(m.http.inFlight.WithLabelValues("pypi"))
	}), NewRouteFunc([]string{"pypi"}))
	serve(h, http.MethodGet, "/pypi/simple/x/")
	assert.Equal(t, 1.0, during)
	assert.Equal(t, 0.0, testutil.ToFloat64(m.http.inFlight.WithLabelValues("pypi")))
}

func TestWrapHandler_PreservesFlusher(t *testing.T) {
	m := newTestMetrics()
	var ok bool
	h := m.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok = w.(http.Flusher)
	}), NewRouteFunc(nil))
	serve(h, http.MethodGet, "/health")
	assert.True(t, ok)
}

func TestWrapHandler_SSEExcludedFromHistogram(t *testing.T) {
	m := newTestMetrics()
	h := m.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), NewRouteFunc(nil))
	serve(h, http.MethodGet, "/api/events")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.http.requests.WithLabelValues("api", "GET", "200")))
	assert.Equal(t, 0, testutil.CollectAndCount(m.http.duration))
}

func TestWrapHandler_RouteComputedBeforeNext(t *testing.T) {
	m := newTestMetrics()
	h := m.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/stripped" // the proxy mux rewrites the path
	}), NewRouteFunc([]string{"npm"}))
	serve(h, http.MethodGet, "/npm/x")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.http.requests.WithLabelValues("npm", "GET", "200")))
}

func TestWrapHandler_CountsAbort(t *testing.T) {
	m := newTestMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	h := m.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
	}), NewRouteFunc([]string{"pypi"}))
	req := httptest.NewRequest(http.MethodGet, "/pypi/x", nil).WithContext(ctx)
	h.ServeHTTP(httptest.NewRecorder(), req)
	assert.Equal(t, 1.0, testutil.ToFloat64(m.http.aborted.WithLabelValues("pypi")))
}

func TestWrapHandler_NilMetricsPassThrough(t *testing.T) {
	var m *Metrics
	h := &stubHandler{}
	got := m.WrapHandler(h, nil)
	require.NotNil(t, got)
	assert.Same(t, h, got.(*stubHandler))
}

// A response write that fails on the server's side — an expired write
// deadline, as httpx.CopyWithWriteDeadline sets for a stalled client — is an
// aborted request even while the client's connection is still open.
func TestWrapHandler_CountsFailedWriteAsAborted(t *testing.T) {
	m := newTestMetrics()
	done := make(chan struct{})
	h := m.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(-time.Second))
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 64<<10)
		for i := 0; i < 16; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}), NewRouteFunc([]string{"pypi"}))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()

	go func() {
		if resp, err := http.Get(srv.URL + "/pypi/x"); err == nil {
			resp.Body.Close()
		}
	}()
	<-done
	assert.Equal(t, 1.0, testutil.ToFloat64(m.http.aborted.WithLabelValues("pypi")))
}
