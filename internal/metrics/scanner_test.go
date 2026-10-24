package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/proxy/dockerproxy"
)

type fakeAV struct {
	res *gate.AVResult
	err error
}

func (f fakeAV) Scan(context.Context, string) (*gate.AVResult, error) { return f.res, f.err }

type fakeCVE struct {
	res *gate.ScanResult
	err error
}

func (f fakeCVE) Scan(context.Context, *gate.PackageRef) (*gate.ScanResult, error) {
	return f.res, f.err
}

type fakeImage struct {
	res *dockerproxy.ImageScanResult
	err error
}

func (f fakeImage) ScanImage(context.Context, string) (*dockerproxy.ImageScanResult, error) {
	return f.res, f.err
}
func (f fakeImage) Health() health.Sample {
	return health.Sample{OK: true, HasData: true, Latency: 7 * time.Millisecond}
}

func scanCount(t *testing.T, m *Metrics, scanner, result string) float64 {
	t.Helper()
	return testutil.ToFloat64(m.scanner.scans.WithLabelValues(scanner, result))
}

func TestWrapAVScanner_Results(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	fakes := map[string]fakeAV{
		"clean":    {res: &gate.AVResult{Clean: true}},
		"detected": {res: &gate.AVResult{Clean: false}},
		"timeout":  {err: context.DeadlineExceeded},
		"error":    {err: errors.New("x")},
	}
	for _, f := range fakes {
		_, _ = m.WrapAVScanner("clamav", f).Scan(context.Background(), "f")
	}
	for result := range fakes {
		assert.Equal(t, 1.0, scanCount(t, m, "clamav", result), result)
	}
	assert.Equal(t, 0.0, testutil.ToFloat64(m.scanner.inFlight.WithLabelValues("clamav")))
	assert.Equal(t, uint64(4), histCount(t, m, "jo_ei_scan_duration_seconds"))
}

func TestWrapAVScanner_NilResultIsClean(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	_, err := m.WrapAVScanner("icap", fakeAV{}).Scan(context.Background(), "f")
	require.NoError(t, err)
	assert.Equal(t, 1.0, scanCount(t, m, "icap", "clean"))
}

func TestWrapAVScanner_UnknownEngineIsOther(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	_, _ = m.WrapAVScanner("mystery", fakeAV{res: &gate.AVResult{Clean: true}}).Scan(context.Background(), "f")
	assert.Equal(t, 1.0, scanCount(t, m, "other", "clean"))
}

func TestWrapCVEScanner_Detected(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	_, _ = m.WrapCVEScanner("osv", fakeCVE{res: &gate.ScanResult{Clean: false}}).Scan(context.Background(), &gate.PackageRef{})
	assert.Equal(t, 1.0, scanCount(t, m, "osv", "detected"))
}

func TestWrapImageScanner_ForwardsHealth(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	f := fakeImage{res: &dockerproxy.ImageScanResult{Findings: []gate.CVEFinding{{}}}}
	w := m.WrapImageScanner("trivy", f)
	assert.Equal(t, f.Health(), w.Health())
	_, err := w.ScanImage(context.Background(), "alpine")
	require.NoError(t, err)
	assert.Equal(t, 1.0, scanCount(t, m, "trivy", "detected"))
}

func TestScannerUpCollector(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	m.RegisterScannerHealth(func() []health.ScannerHealth {
		return []health.ScannerHealth{
			{Name: "osv.dev", Status: health.StatusOK, Enabled: true},
			{Name: "clamav", Status: health.StatusDown, Enabled: true},
			{Name: "icap", Status: health.StatusUnknown, Enabled: true},
			{Name: "trivy", Status: health.StatusOff, Enabled: false},
		}
	}, nil)
	// A second registration is ignored.
	m.RegisterScannerHealth(func() []health.ScannerHealth { return nil }, nil)
	expected := `# HELP jo_ei_scanner_up 1 when the scanner's last health check passed (ok or warn), 0 when it failed. Absent while unknown or disabled.
# TYPE jo_ei_scanner_up gauge
jo_ei_scanner_up{scanner="clamav"} 0
jo_ei_scanner_up{scanner="osv"} 1
`
	require.NoError(t, testutil.GatherAndCompare(m.Registry, strings.NewReader(expected), "jo_ei_scanner_up"))
}

func TestScanQueueMetrics(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	m.SetScanConcurrencyLimit(8)
	m.ScanWaitObserver()(time.Second)
	assert.Equal(t, 8.0, testutil.ToFloat64(m.scanner.limit))
	assert.Equal(t, uint64(1), histCount(t, m, "jo_ei_scan_queue_wait_seconds"))
}

func TestScannerNilMetrics(t *testing.T) {
	var m *Metrics
	av := fakeAV{}
	assert.Equal(t, av, m.WrapAVScanner("clamav", av))
	cve := fakeCVE{}
	assert.Equal(t, cve, m.WrapCVEScanner("osv", cve))
	img := fakeImage{}
	assert.Equal(t, img, m.WrapImageScanner("trivy", img))
	assert.Nil(t, m.ScanWaitObserver())
	m.SetScanConcurrencyLimit(1)
	m.RegisterScannerHealth(nil, nil)
}

func TestScannerUpCollector_NamedEnginesLabelByType(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	m.RegisterScannerHealth(func() []health.ScannerHealth {
		return []health.ScannerHealth{
			{Name: "kaspersky", Status: health.StatusOK, Enabled: true},
			{Name: "clamav-eu", Status: health.StatusDown, Enabled: true},
		}
	}, map[string]string{"kaspersky": "icap", "clamav-eu": "clamav"})
	expected := `# HELP jo_ei_scanner_up 1 when the scanner's last health check passed (ok or warn), 0 when it failed. Absent while unknown or disabled.
# TYPE jo_ei_scanner_up gauge
jo_ei_scanner_up{scanner="clamav"} 0
jo_ei_scanner_up{scanner="icap"} 1
`
	require.NoError(t, testutil.GatherAndCompare(m.Registry, strings.NewReader(expected), "jo_ei_scanner_up"))
}

// histCount sums the sample count of every series of the named histogram.
func histCount(t *testing.T, m *Metrics, name string) uint64 {
	t.Helper()
	mfs, err := m.Registry.Gather()
	require.NoError(t, err)
	var n uint64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, mm := range mf.GetMetric() {
			n += mm.GetHistogram().GetSampleCount()
		}
	}
	return n
}
