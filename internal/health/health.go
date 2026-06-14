// Package health probes scan engines for liveness and latency and exposes a
// snapshot for the admin console. It is protocol-agnostic: liveness checks are
// injected as closures, so this package does not import internal/scanner.
package health

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Status is a scan engine's health classification.
type Status string

const (
	StatusOK      Status = "ok"      // reachable, latency within threshold
	StatusWarn    Status = "warn"    // reachable but slow (latency over threshold)
	StatusDown    Status = "down"    // last check failed
	StatusUnknown Status = "unknown" // not checked yet / no traffic yet
	StatusOff     Status = "off"     // configured but not attached by the active profile
)

// Sample is one raw liveness observation, before classification.
type Sample struct {
	OK      bool          // last check/scan succeeded
	Latency time.Duration // observed round-trip
	HasData bool          // false means "never checked" → unknown
}

// ScannerHealth is the per-engine record surfaced in GET /api/overview.
type ScannerHealth struct {
	Name      string `json:"name"`
	Detail    string `json:"detail"`
	Enabled   bool   `json:"enabled"`
	Status    Status `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
}

// classify maps a raw Sample to a Status + latency in milliseconds. Latency is
// only reported for reachable scanners; unknown and down both report 0, since a
// round-trip to a host that then failed is not a meaningful latency to display.
// A slow threshold of zero disables the warn state.
func classify(s Sample, slow time.Duration) (Status, int64) {
	if !s.HasData {
		return StatusUnknown, 0
	}
	if !s.OK {
		return StatusDown, 0
	}
	ms := s.Latency.Milliseconds()
	if slow > 0 && s.Latency > slow {
		return StatusWarn, ms
	}
	return StatusOK, ms
}

// Probe checks a scanner's liveness. Used for actively-probed (socket) engines.
type Probe func(ctx context.Context) error

// Reporter returns the current passive sample for an engine that tracks its own
// outcomes (e.g. the osv.dev client).
type Reporter func() Sample

const (
	defaultInterval = 30 * time.Second
	maxProbeTimeout = 10 * time.Second
)

type entryKind int

const (
	kindActive entryKind = iota
	kindPassive
	kindDisabled
)

type entry struct {
	meta   ScannerHealth // Name/Detail/Enabled fixed; Status/LatencyMS computed per snapshot
	kind   entryKind
	probe  Probe    // kindActive
	report Reporter // kindPassive

	// kindActive only; guarded by Monitor.mu.
	sample  Sample
	sampled bool
}

// Monitor probes active scanners on a timer and classifies all registered
// engines for the console. Register entries with Add* before calling Start.
type Monitor struct {
	interval time.Duration
	slow     time.Duration

	entries []*entry // fixed after Start; safe to read without the lock

	mu        sync.Mutex // guards each active entry's sample/sampled
	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	startOnce sync.Once
	started   atomic.Bool
}

// NewMonitor returns a monitor that probes every interval and flags latencies
// above slow as warn. A non-positive interval falls back to 30s; a non-positive
// slow disables the warn state.
func NewMonitor(interval, slow time.Duration) *Monitor {
	if interval <= 0 {
		interval = defaultInterval
	}
	if slow < 0 {
		slow = 0
	}
	return &Monitor{interval: interval, slow: slow, stop: make(chan struct{})}
}

func (m *Monitor) assertNotStarted() {
	if m.started.Load() {
		panic("health.Monitor: Add* called after Start")
	}
}

// AddActive registers a socket scanner probed on the background timer.
func (m *Monitor) AddActive(name, detail string, enabled bool, probe Probe) {
	m.assertNotStarted()
	m.entries = append(m.entries, &entry{
		meta:  ScannerHealth{Name: name, Detail: detail, Enabled: enabled},
		kind:  kindActive,
		probe: probe,
	})
}

// AddPassive registers an engine that reports its own last outcome.
func (m *Monitor) AddPassive(name, detail string, enabled bool, report Reporter) {
	m.assertNotStarted()
	m.entries = append(m.entries, &entry{
		meta:   ScannerHealth{Name: name, Detail: detail, Enabled: enabled},
		kind:   kindPassive,
		report: report,
	})
}

// AddDisabled registers a configured-but-unattached engine (always reported off).
func (m *Monitor) AddDisabled(name, detail string) {
	m.assertNotStarted()
	m.entries = append(m.entries, &entry{
		meta: ScannerHealth{Name: name, Detail: detail, Enabled: false},
		kind: kindDisabled,
	})
}

// Start launches the background probe loop. Safe to call once; extra calls are
// no-ops. Call all Add* methods before Start.
func (m *Monitor) Start() {
	m.startOnce.Do(func() {
		m.started.Store(true)
		m.wg.Add(1)
		go m.loop()
	})
}

func (m *Monitor) loop() {
	defer m.wg.Done()
	m.probeAll()
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.probeAll()
		}
	}
}

func (m *Monitor) probeTimeout() time.Duration {
	if m.interval < maxProbeTimeout {
		return m.interval
	}
	return maxProbeTimeout
}

func (m *Monitor) probeAll() {
	for _, e := range m.entries {
		if e.kind != kindActive {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), m.probeTimeout())
		start := time.Now()
		err := e.probe(ctx)
		cancel()
		s := Sample{OK: err == nil, Latency: time.Since(start), HasData: true}
		m.mu.Lock()
		e.sample, e.sampled = s, true
		m.mu.Unlock()
	}
}

// Snapshot returns the current health of every registered engine, in
// registration order.
func (m *Monitor) Snapshot() []ScannerHealth {
	out := make([]ScannerHealth, 0, len(m.entries))
	for _, e := range m.entries {
		sh := e.meta
		switch e.kind {
		case kindDisabled:
			sh.Status, sh.LatencyMS = StatusOff, 0
		case kindPassive:
			sh.Status, sh.LatencyMS = classify(e.report(), m.slow)
		case kindActive:
			m.mu.Lock()
			sampled, sample := e.sampled, e.sample
			m.mu.Unlock()
			if !sampled {
				sh.Status, sh.LatencyMS = StatusUnknown, 0
			} else {
				sh.Status, sh.LatencyMS = classify(sample, m.slow)
			}
		}
		out = append(out, sh)
	}
	return out
}

// Close stops the probe loop and waits for it to exit. Safe to call once; extra
// calls are no-ops.
func (m *Monitor) Close() error {
	m.closeOnce.Do(func() {
		close(m.stop)
		m.wg.Wait()
	})
	return nil
}
