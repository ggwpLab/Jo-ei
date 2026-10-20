package metrics

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
)

type upstreamMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight *prometheus.GaugeVec
	errors   *prometheus.CounterVec
}

func newUpstreamMetrics(reg prometheus.Registerer) *upstreamMetrics {
	f := promauto.With(reg)
	return &upstreamMetrics{
		requests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "jo_ei_upstream_requests_total",
			Help: `Outbound upstream requests by host and status code ("error" when no response was received).`,
		}, []string{"host", "code"}),
		duration: f.NewHistogramVec(newDurationHistogramOpts(
			"jo_ei_upstream_request_duration_seconds",
			"Outbound upstream request duration by host, until response headers or error."),
			[]string{"host"}),
		inFlight: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "jo_ei_upstream_requests_in_flight",
			Help: "Outbound upstream requests currently in flight, by host.",
		}, []string{"host"}),
		errors: f.NewCounterVec(prometheus.CounterOpts{
			Name: "jo_ei_upstream_errors_total",
			Help: "Outbound upstream requests that failed without a response, by host and reason.",
		}, []string{"host", "reason"}),
	}
}

// UpstreamHosts returns the deduplicated URL hosts (host[:port]) of every URL
// in upstreamLists, in first-seen order. Unparseable or host-less URLs are
// skipped. The result is the closed host-label set for upstream metrics.
func UpstreamHosts(upstreamLists ...[]string) []string {
	seen := map[string]struct{}{}
	var hosts []string
	for _, list := range upstreamLists {
		for _, raw := range list {
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" {
				continue
			}
			if _, dup := seen[u.Host]; dup {
				continue
			}
			seen[u.Host] = struct{}{}
			hosts = append(hosts, u.Host)
		}
	}
	return hosts
}

func hostSet(hosts []string) map[string]struct{} {
	set := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		set[h] = struct{}{}
	}
	return set
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// WrapTransport instruments rt with upstream request count, duration,
// in-flight and error-reason metrics. hosts is the closed host-label set (see
// UpstreamHosts); any other request host is labelled "other". Install it as
// the outermost layer of the upstream transport chain so rate-limit waits and
// circuit-open fast-fails are visible. It never registers collectors. A nil
// *Metrics returns rt unchanged.
func (m *Metrics) WrapTransport(rt http.RoundTripper, hosts []string) http.RoundTripper {
	if m == nil {
		return rt
	}
	known := hostSet(hosts)
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		host := oneOf(req.URL.Host, known)

		g := m.upstream.inFlight.WithLabelValues(host)
		g.Inc()
		defer g.Dec()

		start := time.Now()
		resp, err := rt.RoundTrip(req)
		m.upstream.duration.WithLabelValues(host).Observe(time.Since(start).Seconds())

		if err != nil {
			m.upstream.requests.WithLabelValues(host, "error").Inc()
			m.upstream.errors.WithLabelValues(host, classifyUpstreamError(err)).Inc()
			return resp, err
		}
		m.upstream.requests.WithLabelValues(host, strconv.Itoa(resp.StatusCode)).Inc()
		return resp, nil
	})
}

// classifyUpstreamError maps a transport error to a bounded reason label.
func classifyUpstreamError(err error) string {
	var (
		dnsErr    *net.DNSError
		opErr     *net.OpError
		certVerif *tls.CertificateVerificationError
		unknownCA x509.UnknownAuthorityError
		hostErr   x509.HostnameError
		certInval x509.CertificateInvalidError
		recHeader tls.RecordHeaderError
	)
	switch {
	case errors.Is(err, httpx.ErrCircuitOpen):
		return "circuit_open"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case isTimeout(err):
		return "timeout"
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.As(err, &certVerif), errors.As(err, &unknownCA),
		errors.As(err, &hostErr), errors.As(err, &certInval), errors.As(err, &recHeader):
		return "tls"
	case errors.As(err, &opErr):
		return "connection"
	}
	return "other"
}

// OpenHostsReporter reports which upstream hosts currently have an open
// circuit. *httpx.CircuitBreaker implements it.
type OpenHostsReporter interface{ OpenHosts() []string }

var circuitOpenDesc = prometheus.NewDesc(
	"jo_ei_upstream_circuit_open",
	"1 when the circuit breaker for the upstream host is open, else 0.",
	[]string{"host"}, nil)

// circuitCollector emits a 0/1 gauge per configured host at scrape time, plus
// "other" only when a host outside the configured set is open.
type circuitCollector struct {
	cb    OpenHostsReporter
	hosts []string
	known map[string]struct{}
}

func (c *circuitCollector) Describe(ch chan<- *prometheus.Desc) { ch <- circuitOpenDesc }

func (c *circuitCollector) Collect(ch chan<- prometheus.Metric) {
	open := map[string]bool{}
	for _, h := range c.cb.OpenHosts() {
		open[oneOf(h, c.known)] = true
	}
	for _, h := range c.hosts {
		ch <- prometheus.MustNewConstMetric(circuitOpenDesc, prometheus.GaugeValue, b2f(open[h]), h)
	}
	// An unknown open host is reported as "other"; a configured host literally
	// named "other" is already emitted above.
	if _, configured := c.known["other"]; open["other"] && !configured {
		ch <- prometheus.MustNewConstMetric(circuitOpenDesc, prometheus.GaugeValue, 1, "other")
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// RegisterCircuitBreaker exposes jo_ei_upstream_circuit_open, read from cb at
// scrape time, for each of hosts. Call it once per process: a repeated call
// is ignored (the first registration stays). A nil *Metrics is a no-op.
func (m *Metrics) RegisterCircuitBreaker(cb OpenHostsReporter, hosts []string) {
	if m == nil {
		return
	}
	hosts = append([]string(nil), hosts...)
	sort.Strings(hosts)
	err := m.Registry.Register(&circuitCollector{cb: cb, hosts: hosts, known: hostSet(hosts)})
	var already prometheus.AlreadyRegisteredError
	if err != nil && !errors.As(err, &already) {
		m.log.Error().Err(err).Msg("register circuit breaker collector")
	}
}
