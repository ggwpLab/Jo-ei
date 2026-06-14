# Scanner Health-Probes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface live availability + latency for each scan engine (osv.dev, ClamAV, ICAP) in `GET /api/overview`, driving the console's existing health dots.

**Architecture:** A new dependency-light `internal/health.Monitor` owns liveness state. Socket scanners (clamd, ICAP) are *actively* probed on a background timer via an injected `Probe(ctx) error` closure; the remote osv.dev API is tracked *passively* from its real scan outcomes. The monitor measures latency uniformly and classifies each engine as `ok`/`warn`/`down`/`unknown`/`off`. The console reads `monitor.Snapshot()` and emits the per-engine status + latency.

**Tech Stack:** Go 1.25 stdlib (`net`, `context`, `sync`, `time`, `bufio`, `net/textproto`), testify, zerolog. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-06-14-scanner-health-probes-design.md`

---

## File Structure

**Create:**
- `internal/health/health.go` — `Status`, `Sample`, `ScannerHealth`, `classify`, `Monitor` (Add*/Start/Snapshot/Close).
- `internal/health/health_test.go` — classify + Monitor behaviour.
- `internal/scanner/probe.go` — `Prober` interface; `(*ClamAVScanner).Probe`, `(*ICAPScanner).Probe`.
- `internal/scanner/probe_test.go` — Probe success/failure for both socket scanners.
- `integration/scanner_health_test.go` — overview reflects a `down` scanner end-to-end.

**Modify:**
- `internal/scanner/osv.go` — passive health tracking + `Health() health.Sample`.
- `internal/scanner/osv_test.go` (or `osv_internal_test.go`) — Health() transitions.
- `internal/config/config.go` — `HealthConfig` + `Config.Health`.
- `internal/config/config_test.go` — defaults/validation.
- `internal/console/server.go` — replace `Scanners []ScannerInfo` with `Health ScannerHealthProvider`; drop `ScannerInfo`; emit live shape.
- `internal/console/server_test.go` — stub provider; assert status + latency.
- `cmd/jo-ei/main.go` — build/start/close the monitor; wire probes; drop `scannerInfo()`.
- `web/console/api.js` — map real `status` + `latency_ms`.
- `web/console/hero.jsx` — show latency next to each scanner.
- `config.yaml` — commented `health:` block.
- `README.md` — document health probes in the scanner section.

---

## Task 1: health types + classify

**Files:**
- Create: `internal/health/health.go`
- Test: `internal/health/health_test.go`

- [ ] **Step 1: Write the failing test**

```go
package health

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClassify(t *testing.T) {
	slow := 2 * time.Second
	cases := []struct {
		name      string
		sample    Sample
		wantStat  Status
		wantMS    int64
	}{
		{"no data is unknown", Sample{HasData: false}, StatusUnknown, 0},
		{"error is down", Sample{HasData: true, OK: false, Latency: 50 * time.Millisecond}, StatusDown, 50},
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/health/ -run TestClassify -v`
Expected: FAIL — `undefined: Sample`, `undefined: classify`, etc.

- [ ] **Step 3: Write minimal implementation**

Create `internal/health/health.go`:

```go
// Package health probes scan engines for liveness and latency and exposes a
// snapshot for the admin console. It is protocol-agnostic: liveness checks are
// injected as closures, so this package does not import internal/scanner.
package health

import "time"

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

// classify maps a raw Sample to a Status + latency in milliseconds. A slow
// threshold of zero disables the warn state.
func classify(s Sample, slow time.Duration) (Status, int64) {
	if !s.HasData {
		return StatusUnknown, 0
	}
	ms := s.Latency.Milliseconds()
	if !s.OK {
		return StatusDown, ms
	}
	if slow > 0 && s.Latency > slow {
		return StatusWarn, ms
	}
	return StatusOK, ms
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/health/ -run TestClassify -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/health/health.go internal/health/health_test.go
git commit -m "feat(health): status types and classify"
```

---

## Task 2: health Monitor

**Files:**
- Modify: `internal/health/health.go`
- Test: `internal/health/health_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/health/health_test.go`:

```go
import (
	"context"
	"sync/atomic"
	// (keep existing imports: testing, time, assert)
	"github.com/stretchr/testify/require"
)

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

var errFail = errTest("probe failed")

type errTest string

func (e errTest) Error() string { return string(e) }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/health/ -run TestMonitor -v`
Expected: FAIL — `undefined: NewMonitor`, `undefined: (*Monitor).AddActive`, etc.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/health/health.go` (add `context`, `sync` to imports):

```go
import (
	"context"
	"sync"
	"time"
)

// Probe checks a scanner's liveness. Used for actively-probed (socket) engines.
type Probe func(ctx context.Context) error

// Reporter returns the current passive sample for an engine that tracks its own
// outcomes (e.g. the osv.dev client).
type Reporter func() Sample

const (
	defaultInterval    = 30 * time.Second
	maxProbeTimeout    = 10 * time.Second
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

// AddActive registers a socket scanner probed on the background timer.
func (m *Monitor) AddActive(name, detail string, enabled bool, probe Probe) {
	m.entries = append(m.entries, &entry{
		meta:  ScannerHealth{Name: name, Detail: detail, Enabled: enabled},
		kind:  kindActive,
		probe: probe,
	})
}

// AddPassive registers an engine that reports its own last outcome.
func (m *Monitor) AddPassive(name, detail string, enabled bool, report Reporter) {
	m.entries = append(m.entries, &entry{
		meta:   ScannerHealth{Name: name, Detail: detail, Enabled: enabled},
		kind:   kindPassive,
		report: report,
	})
}

// AddDisabled registers a configured-but-unattached engine (always reported off).
func (m *Monitor) AddDisabled(name, detail string) {
	m.entries = append(m.entries, &entry{
		meta: ScannerHealth{Name: name, Detail: detail, Enabled: false},
		kind: kindDisabled,
	})
}

// Start launches the background probe loop. Call Add* before Start.
func (m *Monitor) Start() {
	m.wg.Add(1)
	go m.loop()
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/health/ -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add internal/health/health.go internal/health/health_test.go
git commit -m "feat(health): Monitor with active/passive/disabled entries"
```

---

## Task 3: socket scanner Prober (ClamAV PING + ICAP OPTIONS)

**Files:**
- Create: `internal/scanner/probe.go`
- Test: `internal/scanner/probe_test.go`

> Note: the spec named these `Ping`/`Options`; the implementation unifies them
> under a single `Probe(ctx) error` method (one `Prober` interface) so the
> wiring is one type assertion. The clamd command is still PING and the ICAP
> method is still OPTIONS internally.

- [ ] **Step 1: Write the failing tests**

Create `internal/scanner/probe_test.go`:

```go
package scanner_test

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/scanner"
)

// newMockClamdPing accepts one connection, reads the NUL-terminated command and
// replies with the given response.
func newMockClamdPing(t *testing.T, response string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				_, _ = r.ReadBytes(0x00) // zPING\x00
				c.Write([]byte(response))
			}(conn)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// newMockICAPOptions accepts one connection, drains the request header block and
// replies with the given canned ICAP response.
func newMockICAPOptions(t *testing.T, response string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				c.Write([]byte(response))
			}(conn)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

func TestClamAVProbe_OK(t *testing.T) {
	addr := newMockClamdPing(t, "PONG\x00")
	sc, err := scanner.NewClamAVScanner(addr, 2*time.Second)
	require.NoError(t, err)
	assert.NoError(t, sc.Probe(context.Background()))
}

func TestClamAVProbe_UnexpectedReply(t *testing.T) {
	addr := newMockClamdPing(t, "ERROR\x00")
	sc, err := scanner.NewClamAVScanner(addr, 2*time.Second)
	require.NoError(t, err)
	assert.Error(t, sc.Probe(context.Background()))
}

func TestClamAVProbe_ConnRefused(t *testing.T) {
	sc, err := scanner.NewClamAVScanner("tcp:127.0.0.1:1", time.Second)
	require.NoError(t, err)
	assert.Error(t, sc.Probe(context.Background()))
}

func TestICAPProbe_OK(t *testing.T) {
	addr := newMockICAPOptions(t, "ICAP/1.0 200 OK\r\nMethods: RESPMOD\r\n\r\n")
	sc, err := scanner.NewICAPScanner(addr, "srv", 2*time.Second)
	require.NoError(t, err)
	assert.NoError(t, sc.Probe(context.Background()))
}

func TestICAPProbe_ServerError(t *testing.T) {
	addr := newMockICAPOptions(t, "ICAP/1.0 500 Server Error\r\n\r\n")
	sc, err := scanner.NewICAPScanner(addr, "srv", 2*time.Second)
	require.NoError(t, err)
	assert.Error(t, sc.Probe(context.Background()))
}

func TestICAPProbe_ConnRefused(t *testing.T) {
	sc, err := scanner.NewICAPScanner("tcp:127.0.0.1:1", "srv", time.Second)
	require.NoError(t, err)
	assert.Error(t, sc.Probe(context.Background()))
}

// Compile-time check that both socket scanners satisfy Prober.
var _ scanner.Prober = (*scanner.ClamAVScanner)(nil)
var _ scanner.Prober = (*scanner.ICAPScanner)(nil)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run Probe -v`
Expected: FAIL — `sc.Probe undefined`, `undefined: scanner.Prober`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/scanner/probe.go`:

```go
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// Prober is an optional scanner capability: a cheap liveness check that does not
// scan a file. ClamAVScanner and ICAPScanner implement it; the health Monitor
// calls Probe on a background timer.
type Prober interface {
	Probe(ctx context.Context) error
}

// dialProbe opens a connection to the scanner with the scanner's timeout, also
// honouring an earlier context deadline. The caller must Close the conn.
func dialProbe(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	return conn, nil
}

// Probe checks clamd liveness with the PING command (expects PONG).
func (s *ClamAVScanner) Probe(ctx context.Context) error {
	conn, err := dialProbe(ctx, s.network, s.addr, s.timeout)
	if err != nil {
		return fmt.Errorf("connecting to clamd: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return fmt.Errorf("sending PING: %w", err)
	}
	resp, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("reading clamd ping reply: %w", err)
	}
	if !strings.Contains(string(resp), "PONG") {
		return fmt.Errorf("unexpected clamd ping reply: %q", strings.TrimSpace(string(resp)))
	}
	return nil
}

// Probe checks ICAP liveness with the OPTIONS method (expects a 2xx status).
func (s *ICAPScanner) Probe(ctx context.Context) error {
	conn, err := dialProbe(ctx, s.network, s.addr, s.timeout)
	if err != nil {
		return fmt.Errorf("connecting to icap server: %w", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("OPTIONS icap://%s/%s ICAP/1.0\r\nHost: %s\r\n\r\n", s.addr, s.service, s.addr)
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("sending OPTIONS: %w", err)
	}
	tp := textproto.NewReader(bufio.NewReader(conn))
	statusLine, err := tp.ReadLine()
	if err != nil {
		return fmt.Errorf("reading icap options status: %w", err)
	}
	code, err := icapStatusCode(statusLine)
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("icap OPTIONS returned status %d", code)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/ -run Probe -v`
Expected: PASS

Then the full scanner package: `go test ./internal/scanner/`
Expected: PASS (no regressions)

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/probe.go internal/scanner/probe_test.go
git commit -m "feat(scanner): Prober with clamd PING and ICAP OPTIONS"
```

---

## Task 4: osv.dev passive health tracking

**Files:**
- Modify: `internal/scanner/osv.go`
- Test: `internal/scanner/osv_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/scanner/osv_test.go` (check its existing imports; add `time`, `health` import path `github.com/ggwpLab/Jo-ei/internal/health`, and `httptest`/`net/http` if not present):

```go
func TestOSVHealth_NoTrafficUnknown(t *testing.T) {
	s := scanner.NewOSVScanner("https://api.osv.dev", time.Hour)
	defer s.Close()
	h := s.Health()
	assert.False(t, h.HasData)
}

func TestOSVHealth_AfterSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"vulns":[]}`))
	}))
	defer srv.Close()
	s := scanner.NewOSVScanner(srv.URL, time.Hour)
	defer s.Close()
	_, err := s.Scan(context.Background(), &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"})
	require.NoError(t, err)
	h := s.Health()
	assert.True(t, h.HasData)
	assert.True(t, h.OK)
}

func TestOSVHealth_AfterError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := scanner.NewOSVScanner(srv.URL, time.Hour)
	defer s.Close()
	_, _ = s.Scan(context.Background(), &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"})
	h := s.Health()
	assert.True(t, h.HasData)
	assert.False(t, h.OK)
}
```

> If `osv_test.go` is `package scanner_test`, the `proxy` import is
> `github.com/ggwpLab/Jo-ei/internal/proxy`. Match the existing test file's
> package and import style; reuse helpers already there (e.g. its mock server)
> rather than duplicating if convenient.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestOSVHealth -v`
Expected: FAIL — `s.Health undefined`.

- [ ] **Step 3: Write minimal implementation**

In `internal/scanner/osv.go`:

1. Add the health import and fields. Add to the import block:
```go
	"github.com/ggwpLab/Jo-ei/internal/health"
```
2. Add fields to the `OSVScanner` struct (after the existing cache fields):
```go
	healthMu      sync.Mutex
	healthLatency time.Duration
	healthOK      bool
	healthHasData bool
```
3. In `Scan`, wrap the live query so only real network calls (not cache hits) record health. Replace:
```go
	result, err := s.queryOSV(ctx, ref)
	if err != nil {
		return nil, err
	}
```
with:
```go
	start := time.Now()
	result, err := s.queryOSV(ctx, ref)
	s.recordHealth(time.Since(start), err)
	if err != nil {
		return nil, err
	}
```
4. Add the recorder and accessor at the end of the file:
```go
// recordHealth stores the outcome of the most recent live OSV query for the
// passive health probe. Cache hits do not call this, so health reflects real
// reachability of api.osv.dev.
func (s *OSVScanner) recordHealth(latency time.Duration, err error) {
	s.healthMu.Lock()
	s.healthLatency = latency
	s.healthOK = err == nil
	s.healthHasData = true
	s.healthMu.Unlock()
}

// Health reports the result of the last live query as a passive health sample.
// Before any query runs, HasData is false (status unknown).
func (s *OSVScanner) Health() health.Sample {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	return health.Sample{OK: s.healthOK, Latency: s.healthLatency, HasData: s.healthHasData}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/ -run TestOSVHealth -v`
Expected: PASS

Then: `go test ./internal/scanner/`
Expected: PASS (no regressions)

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/osv.go internal/scanner/osv_test.go
git commit -m "feat(scanner): passive osv.dev health tracking"
```

---

## Task 5: config HealthConfig

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/config/config_test.go` (match existing package/imports):

```go
func TestValidate_RejectsNegativeHealth(t *testing.T) {
	c := &config.Config{}
	c.Health.ProbeIntervalSeconds = -1
	err := c.Validate()
	require.Error(t, err)
}
```

> If the existing tests build a `Config` via a helper or YAML fixture, follow
> that style; the assertion just needs a negative health field to trip Validate.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestValidate_RejectsNegativeHealth -v`
Expected: FAIL — `c.Health undefined` (compile error).

- [ ] **Step 3: Write minimal implementation**

In `internal/config/config.go`:

1. Add the field to `Config`:
```go
	Health      HealthConfig      `mapstructure:"health"`
```
2. Add the type (near the other config structs):
```go
// HealthConfig tunes the scanner health probes. Zero values use defaults
// (30s interval, 2000ms slow threshold).
type HealthConfig struct {
	ProbeIntervalSeconds int `mapstructure:"probe_interval_seconds"`
	SlowThresholdMS      int `mapstructure:"slow_threshold_ms"`
}
```
3. Add to `Validate()` before `return nil`:
```go
	if c.Health.ProbeIntervalSeconds < 0 {
		return fmt.Errorf("health.probe_interval_seconds must not be negative")
	}
	if c.Health.SlowThresholdMS < 0 {
		return fmt.Errorf("health.slow_threshold_ms must not be negative")
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS (all config tests)

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): health probe interval and slow threshold"
```

---

## Task 6: console emits live scanner health

**Files:**
- Modify: `internal/console/server.go`
- Test: `internal/console/server_test.go`

- [ ] **Step 1: Update the test (failing)**

In `internal/console/server_test.go`:

1. Add a stub provider near the top of the file:
```go
type stubHealth struct{ scanners []health.ScannerHealth }

func (s stubHealth) Snapshot() []health.ScannerHealth { return s.scanners }
```
2. Add the import `github.com/ggwpLab/Jo-ei/internal/health`.
3. In `newFixture`, replace the `Scanners:` line with:
```go
		Health: stubHealth{scanners: []health.ScannerHealth{
			{Name: "osv.dev", Detail: "https://api.osv.dev", Enabled: true, Status: health.StatusOK, LatencyMS: 42},
		}},
```
4. In `TestOverview`, change the `Scanners` field type in the anonymous struct and add assertions:
```go
		Scanners []health.ScannerHealth `json:"scanners"`
```
After `require.Len(t, body.Scanners, 1)` add:
```go
	assert.Equal(t, health.StatusOK, body.Scanners[0].Status)
	assert.Equal(t, int64(42), body.Scanners[0].LatencyMS)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/console/ -run TestOverview -v`
Expected: FAIL — `unknown field Health`, `undefined: console.ScannerInfo` still referenced, compile errors.

- [ ] **Step 3: Update the implementation**

In `internal/console/server.go`:

1. Add import `github.com/ggwpLab/Jo-ei/internal/health`.
2. Delete the `ScannerInfo` struct (lines defining `type ScannerInfo ...`).
3. Add the provider interface near the other interfaces:
```go
// ScannerHealthProvider supplies live scan-engine health for the overview.
// *health.Monitor satisfies it.
type ScannerHealthProvider interface {
	Snapshot() []health.ScannerHealth
}
```
4. In `Config`, replace `Scanners []ScannerInfo` with:
```go
	Health        ScannerHealthProvider // optional; nil reports no scanners
```
5. In `NewHandler`, delete the `if cfg.Scanners == nil { ... }` guard.
6. In `overview`, replace `"scanners": s.cfg.Scanners,` with a computed slice. Before `s.writeJSON(...)`:
```go
	scanners := []health.ScannerHealth{}
	if s.cfg.Health != nil {
		scanners = s.cfg.Health.Snapshot()
	}
```
and use `"scanners": scanners,` in the map.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/console/ -v`
Expected: PASS (all console tests)

- [ ] **Step 5: Commit**

```bash
git add internal/console/server.go internal/console/server_test.go
git commit -m "feat(console): emit live scanner health in overview"
```

---

## Task 7: wire the monitor in main

**Files:**
- Modify: `cmd/jo-ei/main.go`

This is wiring code verified by Task 9's integration test; no new unit test here.

- [ ] **Step 1: Add imports and helpers**

In `cmd/jo-ei/main.go`:

1. Add imports:
```go
	"github.com/ggwpLab/Jo-ei/internal/health"
```
2. Delete the `scannerInfo` function entirely.

- [ ] **Step 2: Hoist the av scanner slice**

Change the malware block so the per-engine instances are visible later. Replace:
```go
	engineCount := 0
	if profile.MalwareBlock && len(cfg.Malware.Scanners) > 0 {
		scanners := make([]proxy.AVScanner, 0, len(cfg.Malware.Scanners))
		for _, sc := range cfg.Malware.Scanners {
			av, err := scanner.New(sc)
			if err != nil {
				return err
			}
			scanners = append(scanners, av)
		}
		shared.avScanner = scanner.NewMultiScanner(scanners...)
		engineCount = len(scanners)
	} else if len(cfg.Malware.Scanners) > 0 {
		logger.Warn().Str("active_profile", cfg.Policy.ActiveProfile).
			Msg("malware.scanners configured but active profile has malware_block:false — scanners not attached")
	}
```
with:
```go
	engineCount := 0
	var avScanners []proxy.AVScanner
	if profile.MalwareBlock && len(cfg.Malware.Scanners) > 0 {
		avScanners = make([]proxy.AVScanner, 0, len(cfg.Malware.Scanners))
		for _, sc := range cfg.Malware.Scanners {
			av, err := scanner.New(sc)
			if err != nil {
				return err
			}
			avScanners = append(avScanners, av)
		}
		shared.avScanner = scanner.NewMultiScanner(avScanners...)
		engineCount = len(avScanners)
	} else if len(cfg.Malware.Scanners) > 0 {
		logger.Warn().Str("active_profile", cfg.Policy.ActiveProfile).
			Msg("malware.scanners configured but active profile has malware_block:false — scanners not attached")
	}
```

- [ ] **Step 3: Build, start and defer-close the monitor**

After the malware block (and after the CVE block where `osvScanner` is created — note `osvScanner` is currently scoped inside the `if cfg.CVE.Enabled` block; widen it: declare `var osvScanner *scanner.OSVScanner` before that block and assign inside, keeping the existing `shared.cveScanner = osvScanner` and `defer osvScanner.Close()`), insert:

```go
	// Scanner health monitor: active probes for socket engines, passive
	// tracking for the remote osv.dev API.
	interval := time.Duration(cfg.Health.ProbeIntervalSeconds) * time.Second
	slow := time.Duration(cfg.Health.SlowThresholdMS) * time.Millisecond
	if slow <= 0 {
		slow = 2000 * time.Millisecond
	}
	healthMon := health.NewMonitor(interval, slow) // interval<=0 → 30s default
	if cfg.CVE.Enabled && osvScanner != nil {
		base := cfg.CVE.BaseURL
		if base == "" {
			base = defaultOSVBaseURL
		}
		healthMon.AddPassive("osv.dev", base, true, osvScanner.Health)
	}
	for i, sc := range cfg.Malware.Scanners {
		if profile.MalwareBlock && i < len(avScanners) {
			if pr, ok := avScanners[i].(scanner.Prober); ok {
				healthMon.AddActive(sc.Type, sc.Address, true, pr.Probe)
				continue
			}
		}
		healthMon.AddDisabled(sc.Type, sc.Address)
	}
	healthMon.Start()
	defer healthMon.Close()
```

> The `defaultOSVBaseURL` const already exists. Make sure `osvScanner` is the
> widened variable, not re-declared.

- [ ] **Step 4: Pass the monitor to the console**

In the `console.NewHandler(console.Config{...})` literal, replace:
```go
			Scanners:      scannerInfo(cfg, profile),
```
with:
```go
			Health:        healthMon,
```

- [ ] **Step 5: Build and run the full suite**

Run: `go build ./... && go test ./...`
Expected: PASS (build clean; existing tests green). On Windows `gofmt -l .` may flag CRLF — ignore; CI on Linux is authoritative.

- [ ] **Step 6: Commit**

```bash
git add cmd/jo-ei/main.go
git commit -m "feat(cmd): wire scanner health monitor into the console"
```

---

## Task 8: frontend — show real status + latency

**Files:**
- Modify: `web/console/api.js`
- Modify: `web/console/hero.jsx`

No JS test harness in this repo; verify by reading and (optionally) `go test ./web/` if it embeds/validates assets.

- [ ] **Step 1: Map real status + latency in api.js**

In `web/console/api.js`, replace the `J.scanners = ...` block:
```js
    J.scanners = (o.scanners || []).map((s) => ({
      name: s.name, detail: s.detail,
      status: s.status || (s.enabled ? "ok" : "off"),
      latency: s.latency_ms ? `${s.latency_ms}ms` : "",
    }));
```

> Keep the `s.enabled ? "ok" : "off"` fallback so an older backend (no `status`
> field) still renders sensibly.

- [ ] **Step 2: Render latency in hero.jsx**

In `web/console/hero.jsx`, in `ScannerStrip`, replace the scanner `.map(...)` body:
```jsx
            : JOEI.scanners.map((s) => (
                <span className={`health ${s.status}`} key={s.name + s.detail} title={s.detail}>
                  <i className="hdot"></i>{s.name}{s.latency ? ` · ${s.latency}` : ""}
                </span>
              ))}
```

- [ ] **Step 3: Verify assets still build/embed**

Run: `go build ./... && go test ./web/ 2>/dev/null || echo "no web tests"`
Expected: build PASS.

- [ ] **Step 4: Commit**

```bash
git add web/console/api.js web/console/hero.jsx
git commit -m "feat(console-ui): show live scanner status and latency"
```

---

## Task 9: integration — overview reflects a down scanner

**Files:**
- Create: `integration/scanner_health_test.go`

- [ ] **Step 1: Write the test**

Create `integration/scanner_health_test.go` (match the package + helper style of `integration/console_auth_test.go`):

```go
package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/ggwpLab/Jo-ei/internal/config"
)

func TestOverview_ReflectsDownScanner(t *testing.T) {
	// A clamd scanner pointed at a closed port: its active probe must fail,
	// surfacing status "down" in the overview.
	sc, err := scanner.NewClamAVScanner("tcp:127.0.0.1:1", time.Second)
	require.NoError(t, err)

	mon := health.NewMonitor(20*time.Millisecond, 2*time.Second)
	mon.AddActive("clamav", "tcp:127.0.0.1:1", true, sc.Probe)
	mon.Start()
	defer mon.Close()

	store := telemetry.NewStore(100)
	runtime := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce"},
		config.CVEConfig{},
		config.PolicyProfile{},
		nil,
	)
	h := console.NewHandler(console.Config{
		Store:       store,
		Broadcaster: telemetry.NewBroadcaster(),
		Policy:      runtime,
		Health:      mon,
		Logger:      zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	require.Eventually(t, func() bool {
		resp, err := http.Get(srv.URL + "/api/overview")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var body struct {
			Scanners []health.ScannerHealth `json:"scanners"`
		}
		if json.NewDecoder(resp.Body).Decode(&body) != nil || len(body.Scanners) != 1 {
			return false
		}
		return body.Scanners[0].Status == health.StatusDown
	}, 2*time.Second, 25*time.Millisecond)
}
```

> Constructors verified against the codebase: `telemetry.NewStore(capacity int)`,
> `telemetry.NewBroadcaster()`, and `policy.NewRuntime(SupplyChainConfig,
> CVEConfig, PolicyProfile, allowlist)` (copy the exact call from
> `internal/console/server_test.go`'s `newFixture`).

- [ ] **Step 2: Run the test**

Run: `go test ./integration/ -run TestOverview_ReflectsDownScanner -v`
Expected: PASS (probe to closed port fails → status down).

- [ ] **Step 3: Commit**

```bash
git add integration/scanner_health_test.go
git commit -m "test(integration): overview reflects a down scanner"
```

---

## Task 10: documentation

**Files:**
- Modify: `config.yaml`
- Modify: `README.md`

- [ ] **Step 1: Add the health block to config.yaml**

Add (commented, with the other optional blocks) to `config.yaml`:
```yaml
# Scanner health probes (optional). Surfaced in the console overview.
# health:
#   probe_interval_seconds: 30   # how often socket scanners (clamd/ICAP) are probed
#   slow_threshold_ms: 2000      # latency above which a scanner shows "warn"
```

- [ ] **Step 2: Document in README**

In the scanner/console section of `README.md`, add a short subsection:
```markdown
### Scanner health

The console overview shows live health for each scan engine:

- **ClamAV / ICAP** are actively probed (clamd `PING`, ICAP `OPTIONS`) every
  `health.probe_interval_seconds` (default 30s).
- **osv.dev** health is derived passively from real scan traffic — no extra
  requests are sent to the public API.

Status is `ok` (reachable, fast), `warn` (reachable but slower than
`health.slow_threshold_ms`, default 2000ms), `down` (last check failed),
`unknown` (no data yet), or `off` (configured but not attached by the active
profile).
```

- [ ] **Step 3: Verify build (docs only, sanity)**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add config.yaml README.md
git commit -m "docs: document scanner health probes and config"
```

---

## Final verification

- [ ] `go build ./...` — clean
- [ ] `go test ./...` — all green (CI runs `-race` on Linux)
- [ ] `go vet ./...` — clean
- [ ] Manual check: `golangci-lint run` if available locally (CI is authoritative; remember errcheck flags `fmt.Fprintln`/`Write` with an explicit writer — all such returns in new code are already checked).
- [ ] Push branch, open PR into **develop** (not main).
