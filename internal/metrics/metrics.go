// Package metrics owns every Prometheus metric Jō-ei exposes.
//
// Hook rule: no other package imports client_golang. They expose optional
// observer hooks (funcs or small interfaces) and cmd/jo-ei wires them to the
// methods here.
//
// To add a metric:
//  1. Add its collector as an unexported field on a sub-struct of Metrics and
//     register it in New (or a helper New calls) on m.Registry.
//  2. Expose a nil-safe Wrap*/Register*/Observe* method that updates it.
//  3. Constrain every label value to a closed set via oneOf; use
//     newDurationHistogramOpts for latency histograms.
//  4. Touch it in newFullyWired (metrics_test.go) so lint and drift tests see it.
package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

// durationBuckets are the classic-histogram upper bounds, in seconds, shared
// by every latency histogram.
var durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

// newDurationHistogramOpts returns HistogramOpts with the shared buckets and
// native-histogram settings applied.
func newDurationHistogramOpts(name, help string) prometheus.HistogramOpts {
	return prometheus.HistogramOpts{
		Name:                            name,
		Help:                            help,
		Buckets:                         durationBuckets,
		NativeHistogramBucketFactor:     1.1,
		NativeHistogramMaxBucketNumber:  100,
		NativeHistogramMinResetDuration: time.Hour,
	}
}

// oneOf returns v if it is in allowed, otherwise "other". It keeps label
// cardinality bounded.
func oneOf(v string, allowed map[string]struct{}) string {
	if _, ok := allowed[v]; ok {
		return v
	}
	return "other"
}

// BuildInfo identifies the running binary.
type BuildInfo struct{ Version, Commit string }

// Metrics holds the registry and all Jō-ei collectors.
//
// A nil *Metrics is valid and means "metrics disabled": every Wrap*/Register*
// method added to this type is nil-safe and becomes a no-op or pass-through.
type Metrics struct {
	Registry *prometheus.Registry
	log      zerolog.Logger
	http     *httpMetrics
	upstream *upstreamMetrics
	scanner  *scannerMetrics
	domain   *domainMetrics
}

// New builds a private registry with Go runtime, process and build-info
// collectors. It never touches prometheus.DefaultRegisterer.
func New(info BuildInfo, log zerolog.Logger) *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(collectors.WithGoCollectorRuntimeMetrics(
			collectors.MetricsGC, collectors.MetricsMemory, collectors.MetricsScheduler)),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	bi := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "jo_ei_build_info",
		Help: "Build information; value is always 1.",
	}, []string{"version", "commit", "goversion"})
	reg.MustRegister(bi)
	bi.WithLabelValues(info.Version, info.Commit, runtime.Version()).Set(1)

	return &Metrics{
		Registry: reg,
		log:      log.With().Str("component", "metrics").Logger(),
		http:     newHTTPMetrics(reg),
		upstream: newUpstreamMetrics(reg),
		scanner:  newScannerMetrics(reg),
		domain:   newDomainMetrics(reg),
	}
}

// Handler serves the registry in Prometheus/OpenMetrics text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.InstrumentMetricHandler(m.Registry, promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{
		Registry:            m.Registry,
		EnableOpenMetrics:   true,
		MaxRequestsInFlight: 4,
		Timeout:             10 * time.Second,
		ErrorLog:            errorLogger{m.log},
	}))
}

// errorLogger adapts zerolog to promhttp.Logger.
type errorLogger struct{ log zerolog.Logger }

func (l errorLogger) Println(v ...interface{}) {
	l.log.Error().Msg(strings.TrimSpace(fmt.Sprintln(v...)))
}
