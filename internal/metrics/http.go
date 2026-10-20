package metrics

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/felixge/httpsnoop"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// RouteFunc maps a request path to a bounded route label.
type RouteFunc func(path string) string

// NewRouteFunc returns a RouteFunc that labels paths by first segment when it
// is one of proxyPrefixes ("v2" is reported as "docker"), and by fixed names
// for the console, API, health and favicon paths. Anything else is "other".
func NewRouteFunc(proxyPrefixes []string) RouteFunc {
	prefixes := make(map[string]struct{}, len(proxyPrefixes))
	for _, p := range proxyPrefixes {
		prefixes[p] = struct{}{}
	}
	return func(path string) string {
		switch {
		case path == "/favicon.ico":
			return "favicon"
		case path == "/health":
			return "health"
		case path == "/console" || strings.HasPrefix(path, "/console/"):
			return "console"
		case strings.HasPrefix(path, "/api/auth/"):
			return "auth"
		case strings.HasPrefix(path, "/api/"):
			return "api"
		}
		seg := strings.TrimPrefix(path, "/")
		if i := strings.IndexByte(seg, '/'); i >= 0 {
			seg = seg[:i]
		}
		if _, ok := prefixes[seg]; ok {
			if seg == "v2" {
				return "docker"
			}
			return seg
		}
		return "other"
	}
}

var httpMethods = map[string]struct{}{
	http.MethodGet: {}, http.MethodHead: {}, http.MethodPost: {}, http.MethodPut: {},
	http.MethodPatch: {}, http.MethodDelete: {}, http.MethodOptions: {},
}

// ssePath is a long-lived stream; its duration would distort latency
// histograms, so only the duration observation is skipped for it.
const ssePath = "/api/events"

type httpMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight *prometheus.GaugeVec
	aborted  *prometheus.CounterVec
}

func newHTTPMetrics(reg prometheus.Registerer) *httpMetrics {
	f := promauto.With(reg)
	return &httpMetrics{
		requests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "jo_ei_http_requests_total",
			Help: "Inbound HTTP requests by route, method and status code.",
		}, []string{"route", "method", "code"}),
		duration: f.NewHistogramVec(newDurationHistogramOpts(
			"jo_ei_http_request_duration_seconds",
			"Inbound HTTP request duration by route and method (excludes the SSE stream)."),
			[]string{"route", "method"}),
		inFlight: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "jo_ei_http_requests_in_flight",
			Help: "Inbound HTTP requests currently being served, by route.",
		}, []string{"route"}),
		aborted: f.NewCounterVec(prometheus.CounterOpts{
			Name: "jo_ei_http_requests_aborted_total",
			Help: "Inbound requests whose client went away or whose response write failed (including the server write timeout).",
		}, []string{"route"}),
	}
}

// WrapHandler instruments next with request count, duration, in-flight and
// client-abort metrics. A nil *Metrics returns next unchanged.
func (m *Metrics) WrapHandler(next http.Handler, route RouteFunc) http.Handler {
	if m == nil {
		return next
	}
	if route == nil {
		route = NewRouteFunc(nil)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Resolve labels before next runs: the proxy mux rewrites r.URL.Path.
		rt := route(r.URL.Path)
		method := oneOf(r.Method, httpMethods)
		sse := r.URL.Path == ssePath

		g := m.http.inFlight.WithLabelValues(rt)
		g.Inc()
		defer g.Dec()

		res := httpsnoop.CaptureMetrics(next, w, r)

		m.http.requests.WithLabelValues(rt, method, strconv.Itoa(res.Code)).Inc()
		if !sse {
			m.http.duration.WithLabelValues(rt, method).Observe(res.Duration.Seconds())
		}
		if r.Context().Err() != nil {
			m.http.aborted.WithLabelValues(rt).Inc()
		}
	})
}
