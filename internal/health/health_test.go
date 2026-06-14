package health

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassify(t *testing.T) {
	slow := 2 * time.Second
	cases := []struct {
		name     string
		sample   Sample
		wantStat Status
		wantMS   int64
	}{
		{"no data is unknown", Sample{HasData: false}, StatusUnknown, 0},
		{"no data ignores latency", Sample{HasData: false, Latency: 5 * time.Second}, StatusUnknown, 0},
		{"error is down", Sample{HasData: true, OK: false, Latency: 50 * time.Millisecond}, StatusDown, 0},
		{"slow is warn", Sample{HasData: true, OK: true, Latency: 3 * time.Second}, StatusWarn, 3000},
		{"fast is ok", Sample{HasData: true, OK: true, Latency: 40 * time.Millisecond}, StatusOK, 40},
		{"at threshold is ok", Sample{HasData: true, OK: true, Latency: 2 * time.Second}, StatusOK, 2000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotStat, gotMS := classify(tc.sample, slow)
			assert.Equal(t, tc.wantStat, gotStat)
			assert.Equal(t, tc.wantMS, gotMS)
		})
	}
}

func TestClassify_NoThresholdNeverWarns(t *testing.T) {
	got, _ := classify(Sample{HasData: true, OK: true, Latency: time.Hour}, 0)
	assert.Equal(t, StatusOK, got)
}

func TestMonitor_DisabledIsOff(t *testing.T) {
	m := NewMonitor(time.Minute, 2*time.Second)
	m.AddDisabled("clamav", "tcp:host:3310")
	snap := m.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, StatusOff, snap[0].Status)
	assert.Equal(t, "clamav", snap[0].Name)
	assert.False(t, snap[0].Enabled)
}

func TestMonitor_ActiveUnknownBeforeStart(t *testing.T) {
	m := NewMonitor(time.Minute, 2*time.Second)
	m.AddActive("clamav", "tcp:host:3310", true, func(context.Context) error { return nil })
	snap := m.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, StatusUnknown, snap[0].Status)
	assert.True(t, snap[0].Enabled)
}

func TestMonitor_ActiveOKAndDown(t *testing.T) {
	m := NewMonitor(20*time.Millisecond, 2*time.Second)
	m.AddActive("good", "a", true, func(context.Context) error { return nil })
	m.AddActive("bad", "b", true, func(context.Context) error { return errFail })
	m.Start()
	defer m.Close()
	require.Eventually(t, func() bool {
		snap := m.Snapshot()
		return snap[0].Status == StatusOK && snap[1].Status == StatusDown
	}, 2*time.Second, 10*time.Millisecond)
}

func TestMonitor_PassiveReadsLive(t *testing.T) {
	m := NewMonitor(time.Minute, 2*time.Second)
	var sample atomic.Value
	sample.Store(Sample{HasData: false})
	m.AddPassive("osv.dev", "https://api.osv.dev", true, func() Sample {
		return sample.Load().(Sample)
	})
	assert.Equal(t, StatusUnknown, m.Snapshot()[0].Status)
	sample.Store(Sample{HasData: true, OK: true, Latency: 30 * time.Millisecond})
	assert.Equal(t, StatusOK, m.Snapshot()[0].Status)
	sample.Store(Sample{HasData: true, OK: false})
	assert.Equal(t, StatusDown, m.Snapshot()[0].Status)
}

func TestMonitor_Refreshes(t *testing.T) {
	m := NewMonitor(20*time.Millisecond, 2*time.Second)
	var ok atomic.Bool
	m.AddActive("flappy", "a", true, func(context.Context) error {
		if ok.Load() {
			return nil
		}
		return errFail
	})
	m.Start()
	defer m.Close()
	require.Eventually(t, func() bool { return m.Snapshot()[0].Status == StatusDown }, time.Second, 5*time.Millisecond)
	ok.Store(true)
	require.Eventually(t, func() bool { return m.Snapshot()[0].Status == StatusOK }, time.Second, 5*time.Millisecond)
}

func TestMonitor_CloseStopsProbing(t *testing.T) {
	m := NewMonitor(10*time.Millisecond, 2*time.Second)
	var calls atomic.Int64
	m.AddActive("x", "a", true, func(context.Context) error { calls.Add(1); return nil })
	m.Start()
	require.Eventually(t, func() bool { return calls.Load() > 0 }, time.Second, 5*time.Millisecond)
	require.NoError(t, m.Close())
	after := calls.Load()
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, after, calls.Load(), "probing must stop after Close")
}

func TestMonitor_AddAfterStartPanics(t *testing.T) {
	m := NewMonitor(time.Minute, time.Second)
	m.Start()
	defer m.Close()
	assert.Panics(t, func() {
		m.AddDisabled("late", "x")
	})
}

func TestMonitor_DoubleStartIsSafe(t *testing.T) {
	m := NewMonitor(time.Minute, time.Second)
	m.AddActive("x", "a", true, func(context.Context) error { return nil })
	m.Start()
	m.Start() // must not spawn a second goroutine or panic
	assert.NoError(t, m.Close())
}

var errFail = errTest("probe failed")

type errTest string

func (e errTest) Error() string { return string(e) }
