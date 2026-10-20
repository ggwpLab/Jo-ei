package metrics

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func okRT() http.RoundTripper {
	return rtFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
}

func doGet(t *testing.T, rt http.RoundTripper, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	return rt.RoundTrip(req)
}

type fakeReporter struct{ open []string }

func (f fakeReporter) OpenHosts() []string { return f.open }

func TestClassifyUpstreamError(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"circuit":  {fmt.Errorf("x: %w", httpx.ErrCircuitOpen), "circuit_open"},
		"canceled": {context.Canceled, "canceled"},
		"deadline": {context.DeadlineExceeded, "timeout"},
		"dns":      {&net.DNSError{}, "dns"},
		"tls":      {&tls.CertificateVerificationError{}, "tls"},
		"conn":     {&net.OpError{Op: "dial", Err: errors.New("refused")}, "connection"},
		"other":    {errors.New("x"), "other"},
	}
	for name, c := range cases {
		assert.Equal(t, c.want, classifyUpstreamError(c.err), name)
	}
}

func TestUpstreamHosts(t *testing.T) {
	got := UpstreamHosts([]string{"https://pypi.org/simple", "https://pypi.org"}, []string{"http://nexus:8081/x", "::bad"})
	assert.Equal(t, []string{"pypi.org", "nexus:8081"}, got)
}

func TestWrapTransport_StatusAndUnknownHost(t *testing.T) {
	m := newTestMetrics()
	rt := m.WrapTransport(okRT(), []string{"pypi.org"})

	_, err := doGet(t, rt, "https://pypi.org/x")
	require.NoError(t, err)
	_, err = doGet(t, rt, "https://cdn.example.net/blob")
	require.NoError(t, err)

	assert.Equal(t, 1.0, testutil.ToFloat64(m.upstream.requests.WithLabelValues("pypi.org", "200")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.upstream.requests.WithLabelValues("other", "200")))
}

func TestWrapTransport_ErrorCountsReason(t *testing.T) {
	m := newTestMetrics()
	rt := m.WrapTransport(rtFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	}), []string{"pypi.org"})

	_, err := doGet(t, rt, "https://pypi.org/x")
	require.Error(t, err)

	assert.Equal(t, 1.0, testutil.ToFloat64(m.upstream.requests.WithLabelValues("pypi.org", "error")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.upstream.errors.WithLabelValues("pypi.org", "timeout")))
	assert.Equal(t, 0.0, testutil.ToFloat64(m.upstream.inFlight.WithLabelValues("pypi.org")))
}

func TestWrapTransport_NilSafe(t *testing.T) {
	var m *Metrics
	rt := okRT()
	assert.NotNil(t, m.WrapTransport(rt, nil))
	m.RegisterCircuitBreaker(fakeReporter{}, nil) // must not panic
}

func TestCircuitCollector(t *testing.T) {
	m := newTestMetrics()
	m.RegisterCircuitBreaker(fakeReporter{open: []string{"pypi.org", "evil:1"}}, []string{"pypi.org", "npmjs.org"})

	mfs, err := m.Registry.Gather()
	require.NoError(t, err)
	got := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "jo_ei_upstream_circuit_open" {
			continue
		}
		for _, mm := range mf.GetMetric() {
			got[mm.GetLabel()[0].GetValue()] = mm.GetGauge().GetValue()
		}
	}
	assert.Equal(t, map[string]float64{"pypi.org": 1, "npmjs.org": 0, "other": 1}, got)
}

func TestCircuitCollector_NoOtherWhenAllKnown(t *testing.T) {
	m := newTestMetrics()
	m.RegisterCircuitBreaker(fakeReporter{}, []string{"pypi.org"})
	assert.Equal(t, 1, testutil.CollectAndCount(m.Registry, "jo_ei_upstream_circuit_open"))
}

func TestRegisterCircuitBreaker_SecondCallDoesNotPanic(t *testing.T) {
	m := newTestMetrics()
	m.RegisterCircuitBreaker(fakeReporter{}, []string{"a"})
	assert.NotPanics(t, func() { m.RegisterCircuitBreaker(fakeReporter{}, []string{"a"}) })
}
