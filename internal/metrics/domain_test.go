package metrics

import (
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
)

type fakeRecorder struct{ got []gate.Event }

func (f *fakeRecorder) Record(e gate.Event) { f.got = append(f.got, e) }

type fakeStatter struct {
	stats cache.CacheStats
	err   error
}

func (f fakeStatter) Stats() (cache.CacheStats, error) { return f.stats, f.err }

func seriesCount(t *testing.T, m *Metrics, name string) int {
	t.Helper()
	mfs, err := m.Registry.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == name {
			return len(mf.GetMetric())
		}
	}
	return 0
}

func TestWrapRecorder_CountsAndDelegates(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	inner := &fakeRecorder{}
	r := m.WrapRecorder(inner)

	ev := gate.Event{Ecosystem: "npm", Verdict: "BLOCK", Gate: "cve"}
	r.Record(ev)
	r.Record(gate.Event{Ecosystem: "cargo", Verdict: "PASS", Gate: ""})

	assert.Equal(t, []gate.Event{ev, {Ecosystem: "cargo", Verdict: "PASS"}}, inner.got)
	expected := `# HELP jo_ei_verdicts_total Gate verdicts by ecosystem, verdict and deciding gate.
# TYPE jo_ei_verdicts_total counter
jo_ei_verdicts_total{ecosystem="npm",gate="cve",verdict="block"} 1
jo_ei_verdicts_total{ecosystem="other",gate="none",verdict="pass"} 1
`
	require.NoError(t, testutil.GatherAndCompare(m.Registry, strings.NewReader(expected), "jo_ei_verdicts_total"))
}

func TestWrapRecorder_NilMetricsPassesThrough(t *testing.T) {
	var m *Metrics
	inner := &fakeRecorder{}
	assert.Same(t, inner, m.WrapRecorder(inner))
}

func TestCacheCollector(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	m.RegisterCache(fakeStatter{stats: cache.CacheStats{SizeBytes: 1024}}, 4096)
	m.RegisterCache(fakeStatter{stats: cache.CacheStats{SizeBytes: 1}}, 1) // repeat ignored
	expected := `# HELP jo_ei_cache_max_bytes Configured cache size limit in bytes.
# TYPE jo_ei_cache_max_bytes gauge
jo_ei_cache_max_bytes 4096
# HELP jo_ei_cache_size_bytes Current cache size in bytes.
# TYPE jo_ei_cache_size_bytes gauge
jo_ei_cache_size_bytes 1024
`
	require.NoError(t, testutil.GatherAndCompare(m.Registry, strings.NewReader(expected),
		"jo_ei_cache_size_bytes", "jo_ei_cache_max_bytes"))
}

func TestCacheCollector_StatsError(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	m.RegisterCache(fakeStatter{err: errors.New("boom")}, 4096)
	_, err := m.Registry.Gather()
	require.NoError(t, err)
	assert.Zero(t, seriesCount(t, m, "jo_ei_cache_size_bytes"))
}

func TestCacheCollector_NoMax(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	m.RegisterCache(fakeStatter{stats: cache.CacheStats{SizeBytes: 5}}, 0)
	assert.Equal(t, 1, seriesCount(t, m, "jo_ei_cache_size_bytes"))
	assert.Zero(t, seriesCount(t, m, "jo_ei_cache_max_bytes"))
}

func TestRegisterCache_NilIsNoop(t *testing.T) {
	var nilM *Metrics
	assert.NotPanics(t, func() { nilM.RegisterCache(fakeStatter{}, 1) })
	m := New(BuildInfo{}, zerolog.Nop())
	assert.NotPanics(t, func() { m.RegisterCache(nil, 4096) })
	assert.Zero(t, seriesCount(t, m, "jo_ei_cache_max_bytes"))
	// A nil call must not consume the once-per-process registration.
	m.RegisterCache(fakeStatter{stats: cache.CacheStats{SizeBytes: 7}}, 0)
	assert.Equal(t, 1, seriesCount(t, m, "jo_ei_cache_size_bytes"))
}
