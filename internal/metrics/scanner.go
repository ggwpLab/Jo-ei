package metrics

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/proxy/dockerproxy"
)

// knownScanners is the closed set of scanner label values.
var knownScanners = hostSet([]string{"clamav", "icap", "osv", "trivy"})

type scannerMetrics struct {
	scans     *prometheus.CounterVec
	duration  *prometheus.HistogramVec
	inFlight  *prometheus.GaugeVec
	queueWait prometheus.Histogram
	limit     prometheus.Gauge
}

func newScannerMetrics(reg prometheus.Registerer) *scannerMetrics {
	f := promauto.With(reg)
	return &scannerMetrics{
		scans: f.NewCounterVec(prometheus.CounterOpts{
			Name: "jo_ei_scans_total",
			Help: "Scans by scanner and result (clean, detected, timeout, error).",
		}, []string{"scanner", "result"}),
		duration: f.NewHistogramVec(newDurationHistogramOpts(
			"jo_ei_scan_duration_seconds",
			"Scan duration by scanner."), []string{"scanner"}),
		inFlight: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "jo_ei_scans_in_flight",
			Help: "Scans currently running, by scanner.",
		}, []string{"scanner"}),
		queueWait: f.NewHistogram(newDurationHistogramOpts(
			"jo_ei_scan_queue_wait_seconds",
			"Time an antivirus scan waited for a concurrency slot.")),
		limit: f.NewGauge(prometheus.GaugeOpts{
			Name: "jo_ei_scan_concurrency_limit",
			Help: "Configured maximum concurrent antivirus scans (0 = unlimited).",
		}),
	}
}

// isTimeout reports whether err is a deadline or network timeout.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &netErr) && netErr.Timeout()
}

// record runs scan under in-flight/duration/result instrumentation. detected
// is consulted only when scan returns no error.
func (m *Metrics) record(engine string, scan func() (detected bool, err error)) {
	name := oneOf(engine, knownScanners)
	g := m.scanner.inFlight.WithLabelValues(name)
	g.Inc()
	defer g.Dec()

	start := time.Now()
	detected, err := scan()
	m.scanner.duration.WithLabelValues(name).Observe(time.Since(start).Seconds())

	result := "clean"
	switch {
	case err != nil && isTimeout(err):
		result = "timeout"
	case err != nil:
		result = "error"
	case detected:
		result = "detected"
	}
	m.scanner.scans.WithLabelValues(name, result).Inc()
}

type avFunc func(ctx context.Context, filePath string) (*gate.AVResult, error)

func (f avFunc) Scan(ctx context.Context, filePath string) (*gate.AVResult, error) {
	return f(ctx, filePath)
}

// WrapAVScanner instruments s as the given engine (clamav, icap; anything
// else is "other"). A nil *Metrics returns s unchanged.
func (m *Metrics) WrapAVScanner(engine string, s gate.AVScanner) gate.AVScanner {
	if m == nil {
		return s
	}
	return avFunc(func(ctx context.Context, filePath string) (res *gate.AVResult, err error) {
		m.record(engine, func() (bool, error) {
			res, err = s.Scan(ctx, filePath)
			return res != nil && !res.Clean, err
		})
		return res, err
	})
}

type cveFunc func(ctx context.Context, pkg *gate.PackageRef) (*gate.ScanResult, error)

func (f cveFunc) Scan(ctx context.Context, pkg *gate.PackageRef) (*gate.ScanResult, error) {
	return f(ctx, pkg)
}

// WrapCVEScanner instruments s as the given engine. A nil *Metrics returns s
// unchanged.
func (m *Metrics) WrapCVEScanner(engine string, s gate.CVEScanner) gate.CVEScanner {
	if m == nil {
		return s
	}
	return cveFunc(func(ctx context.Context, pkg *gate.PackageRef) (res *gate.ScanResult, err error) {
		m.record(engine, func() (bool, error) {
			res, err = s.Scan(ctx, pkg)
			return res != nil && !res.Clean, err
		})
		return res, err
	})
}

type instrumentedImageScanner struct {
	m      *Metrics
	engine string
	inner  dockerproxy.ImageScanner
}

func (i *instrumentedImageScanner) ScanImage(ctx context.Context, imageRef string) (res *dockerproxy.ImageScanResult, err error) {
	i.m.record(i.engine, func() (bool, error) {
		res, err = i.inner.ScanImage(ctx, imageRef)
		return res != nil && len(res.Findings) > 0, err
	})
	return res, err
}

func (i *instrumentedImageScanner) Health() health.Sample { return i.inner.Health() }

// WrapImageScanner instruments s as the given engine and forwards Health. A
// nil *Metrics returns s unchanged.
func (m *Metrics) WrapImageScanner(engine string, s dockerproxy.ImageScanner) dockerproxy.ImageScanner {
	if m == nil {
		return s
	}
	return &instrumentedImageScanner{m: m, engine: engine, inner: s}
}

// ScanWaitObserver returns a func recording an AV scan's concurrency-slot wait
// into jo_ei_scan_queue_wait_seconds, or nil when m is nil (so callers skip
// timing entirely).
func (m *Metrics) ScanWaitObserver() func(time.Duration) {
	if m == nil {
		return nil
	}
	return func(d time.Duration) { m.scanner.queueWait.Observe(d.Seconds()) }
}

// SetScanConcurrencyLimit records the configured AV scan concurrency limit.
// A nil *Metrics is a no-op.
func (m *Metrics) SetScanConcurrencyLimit(n int) {
	if m == nil {
		return
	}
	m.scanner.limit.Set(float64(n))
}

var scannerUpDesc = prometheus.NewDesc(
	"jo_ei_scanner_up",
	"1 when the scanner's last health check passed (ok or warn), 0 when it failed. Absent while unknown or disabled.",
	[]string{"scanner"}, nil)

// scannerUpCollector emits jo_ei_scanner_up from a health snapshot at scrape
// time.
type scannerUpCollector struct {
	snapshot func() []health.ScannerHealth
}

func (c *scannerUpCollector) Describe(ch chan<- *prometheus.Desc) { ch <- scannerUpDesc }

func (c *scannerUpCollector) Collect(ch chan<- prometheus.Metric) {
	seen := map[string]bool{}
	for _, sh := range c.snapshot() {
		if !sh.Enabled || sh.Status == health.StatusUnknown {
			continue
		}
		name := sh.Name
		if name == "osv.dev" {
			name = "osv"
		}
		name = oneOf(name, knownScanners)
		if seen[name] {
			continue // duplicate series would fail the whole scrape
		}
		seen[name] = true
		up := sh.Status == health.StatusOK || sh.Status == health.StatusWarn
		ch <- prometheus.MustNewConstMetric(scannerUpDesc, prometheus.GaugeValue, b2f(up), name)
	}
}

// RegisterScannerHealth exposes jo_ei_scanner_up, derived from snapshot at
// scrape time. Call it once per process: a repeated call is ignored. A nil
// *Metrics is a no-op.
func (m *Metrics) RegisterScannerHealth(snapshot func() []health.ScannerHealth) {
	if m == nil {
		return
	}
	err := m.Registry.Register(&scannerUpCollector{snapshot: snapshot})
	var already prometheus.AlreadyRegisteredError
	if err != nil && !errors.As(err, &already) {
		m.log.Error().Err(err).Msg("register scanner health collector")
	}
}
