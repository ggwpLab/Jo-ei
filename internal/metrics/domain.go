package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
)

var (
	knownEcosystems = hostSet([]string{"pypi", "npm", "maven", "rubygems", "go", "docker"})
	knownVerdicts   = hostSet([]string{"pass", "cache", "block", "error"})
	knownGates      = hostSet([]string{
		gate.GateCache, gate.GateSupply, gate.GateCVE, gate.GateMalware, gate.GateImageScan,
	})
)

type domainMetrics struct {
	verdicts *prometheus.CounterVec
}

func newDomainMetrics(reg prometheus.Registerer) *domainMetrics {
	return &domainMetrics{
		verdicts: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "jo_ei_verdicts_total",
			Help: "Gate verdicts by ecosystem, verdict and deciding gate.",
		}, []string{"ecosystem", "verdict", "gate"}),
	}
}

type instrumentedRecorder struct {
	m     *Metrics
	inner gate.Recorder
}

func (r *instrumentedRecorder) Record(e gate.Event) {
	gt := "none"
	if e.Gate != "" {
		gt = oneOf(e.Gate, knownGates)
	}
	r.m.domain.verdicts.WithLabelValues(
		oneOf(e.Ecosystem, knownEcosystems),
		oneOf(lower(e.Verdict), knownVerdicts),
		gt,
	).Inc()
	r.inner.Record(e)
}

// lower lowercases ASCII verdict names; anything else falls to "other" via oneOf.
func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// WrapRecorder counts every event in jo_ei_verdicts_total, then delegates to
// r. A nil *Metrics returns r unchanged.
func (m *Metrics) WrapRecorder(r gate.Recorder) gate.Recorder {
	if m == nil {
		return r
	}
	return &instrumentedRecorder{m: m, inner: r}
}

// CacheStatter is the slice of the cache the size collector needs.
type CacheStatter interface {
	Stats() (cache.CacheStats, error)
}

var cacheSizeDesc = prometheus.NewDesc(
	"jo_ei_cache_size_bytes",
	"Current cache size in bytes.",
	nil, nil)

// cacheSizeCollector emits jo_ei_cache_size_bytes from cache stats at scrape
// time; it skips the series when Stats fails.
type cacheSizeCollector struct {
	stats CacheStatter
}

func (c *cacheSizeCollector) Describe(ch chan<- *prometheus.Desc) { ch <- cacheSizeDesc }

func (c *cacheSizeCollector) Collect(ch chan<- prometheus.Metric) {
	st, err := c.stats.Stats()
	if err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(cacheSizeDesc, prometheus.GaugeValue, float64(st.SizeBytes))
}

// RegisterCache exposes jo_ei_cache_size_bytes (read at scrape time) and,
// when maxBytes > 0, the constant jo_ei_cache_max_bytes. Call it once per
// process: a repeated call is ignored. A nil *Metrics or nil s is a no-op.
func (m *Metrics) RegisterCache(s CacheStatter, maxBytes int64) {
	if m == nil || s == nil {
		return
	}
	err := m.Registry.Register(&cacheSizeCollector{stats: s})
	var already prometheus.AlreadyRegisteredError
	if errors.As(err, &already) {
		return
	}
	if err != nil {
		m.log.Error().Err(err).Msg("register cache collector")
		return
	}
	if maxBytes <= 0 {
		return
	}
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "jo_ei_cache_max_bytes",
		Help: "Configured cache size limit in bytes.",
	})
	g.Set(float64(maxBytes))
	if err := m.Registry.Register(g); err != nil {
		m.log.Error().Err(err).Msg("register cache max gauge")
	}
}
