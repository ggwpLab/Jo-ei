package proxy_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

// flipCVE returns clean until vulnerable is set; scanErr forces an error.
type flipCVE struct {
	vulnerable atomic.Bool
	scanErr    atomic.Bool
	calls      atomic.Int32
}

func (s *flipCVE) Scan(context.Context, *gate.PackageRef) (*gate.ScanResult, error) {
	s.calls.Add(1)
	if s.scanErr.Load() {
		return nil, errors.New("osv down")
	}
	if s.vulnerable.Load() {
		return &gate.ScanResult{Findings: []gate.CVEFinding{{ID: "CVE-2026-0001", Severity: gate.SeverityCritical}}}, nil
	}
	return &gate.ScanResult{Clean: true}, nil
}

// blockOnFindings blocks whenever the scan has findings.
type blockOnFindings struct{}

func (blockOnFindings) Evaluate(_ *gate.PackageRef, res *gate.ScanResult) gate.PolicyDecision {
	if len(res.Findings) > 0 {
		return gate.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: res.Findings}
	}
	return gate.PolicyDecision{Allowed: true, Reason: "ok"}
}

// flipAV mirrors flipCVE for the malware scanner.
type flipAV struct {
	infected atomic.Bool
	scanErr  atomic.Bool
	calls    atomic.Int32
}

func (s *flipAV) Scan(context.Context, string) (*gate.AVResult, error) {
	s.calls.Add(1)
	if s.scanErr.Load() {
		return nil, errors.New("clamd down")
	}
	if s.infected.Load() {
		return &gate.AVResult{Clean: false, Engine: "clamav", Signature: "EICAR"}, nil
	}
	return &gate.AVResult{Clean: true}, nil
}

// mu guards events: the recheck-coalescing tests have every waiter record its
// own event concurrently from its own request goroutine.
type eventSpy struct {
	mu     sync.Mutex
	events []gate.Event
}

func (r *eventSpy) Record(e gate.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// recheckHarness caches one clean artifact through the full pipeline and
// returns everything a re-check test needs to manipulate.
type recheckHarness struct {
	srv  *httptest.Server
	fc   *fakeCache
	cve  *flipCVE
	av   *flipAV
	rec  *eventSpy
	ref  gate.PackageRef
	path string // download path for repeat GETs
}

func newRecheckHarness(t *testing.T, cveTTL, avTTL time.Duration) *recheckHarness {
	t.Helper()
	upstream := makeUpstream(t, "victim", "1.0.0", 72)
	t.Cleanup(upstream.Close)

	fc := newFakeCache()
	cve := &flipCVE{}
	av := &flipAV{}
	rec := &eventSpy{}
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:           adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:            supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:             fc,
		Logger:            zerolog.Nop(),
		CVEScanner:        cve,
		Policy:            blockOnFindings{},
		AVScanner:         av,
		Recorder:          rec,
		CVERecheckTTL:     cveTTL,
		MalwareRecheckTTL: avTTL,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	hs := &recheckHarness{
		srv: srv, fc: fc, cve: cve, av: av, rec: rec,
		ref:  gate.PackageRef{Ecosystem: "pypi", Name: "victim", Version: "1.0.0"},
		path: "/packages/py3/v/victim/victim-1.0.0-py3-none-any.whl",
	}
	resp, err := http.Get(srv.URL + hs.path)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed download must pass")
	return hs
}

// rewind pushes both check timestamps into the past on the cached entry.
func (hs *recheckHarness) rewind(d time.Duration) {
	e := hs.fc.entries[hs.ref.Key()]
	e.LastCVECheck = e.LastCVECheck.Add(-d)
	e.LastMalwareCheck = e.LastMalwareCheck.Add(-d)
}

func (hs *recheckHarness) get(t *testing.T) *http.Response {
	t.Helper()
	resp, err := http.Get(hs.srv.URL + hs.path)
	require.NoError(t, err)
	resp.Body.Close()
	return resp
}

func TestRecheck_FreshHitSkipsScanners(t *testing.T) {
	hs := newRecheckHarness(t, time.Hour, time.Hour)
	cveCalls, avCalls := hs.cve.calls.Load(), hs.av.calls.Load()
	resp := hs.get(t)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, cveCalls, hs.cve.calls.Load(), "fresh hit must not re-run CVE")
	assert.Equal(t, avCalls, hs.av.calls.Load(), "fresh hit must not re-run AV")
}

func TestRecheck_ExpiredCVEBlocksAndEvicts(t *testing.T) {
	hs := newRecheckHarness(t, time.Hour, time.Hour)
	hs.rewind(2 * time.Hour)
	hs.cve.vulnerable.Store(true)
	artifact := hs.fc.entries[hs.ref.Key()].ArtifactPath

	resp := hs.get(t)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_, cached := hs.fc.entries[hs.ref.Key()]
	assert.False(t, cached, "entry must be evicted")
	_, statErr := os.Stat(artifact)
	assert.True(t, os.IsNotExist(statErr), "binary must be deleted")
	last := hs.rec.events[len(hs.rec.events)-1]
	assert.Equal(t, gate.VerdictBlock, last.Verdict)
	assert.Equal(t, gate.GateCVE, last.Gate)
	assert.NotEqual(t, "revalidation", last.RequestID)
}

func TestRecheck_ExpiredMalwareBlocksAndEvicts(t *testing.T) {
	hs := newRecheckHarness(t, time.Hour, time.Hour)
	hs.rewind(2 * time.Hour)
	hs.av.infected.Store(true)
	artifact := hs.fc.entries[hs.ref.Key()].ArtifactPath

	resp := hs.get(t)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_, cached := hs.fc.entries[hs.ref.Key()]
	assert.False(t, cached)
	_, statErr := os.Stat(artifact)
	assert.True(t, os.IsNotExist(statErr))
	last := hs.rec.events[len(hs.rec.events)-1]
	assert.Equal(t, gate.GateMalware, last.Gate)
	assert.Equal(t, "EICAR", last.MalwareSignature)
}

func TestRecheck_CleanRecheckBumpsAndServes(t *testing.T) {
	hs := newRecheckHarness(t, time.Hour, time.Hour)
	hs.rewind(2 * time.Hour)
	before := hs.fc.entries[hs.ref.Key()].LastCVECheck

	resp := hs.get(t)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	e := hs.fc.entries[hs.ref.Key()]
	assert.True(t, e.LastCVECheck.After(before), "clean re-check must bump last_cve_check")
	assert.True(t, e.LastMalwareCheck.After(before), "clean re-check must bump last_malware_check")
	last := hs.rec.events[len(hs.rec.events)-1]
	assert.Equal(t, gate.VerdictCache, last.Verdict, "a clean re-check still serves as a cache hit")
}

func TestRecheck_ScannerErrorServesStale(t *testing.T) {
	hs := newRecheckHarness(t, time.Hour, time.Hour)
	hs.rewind(2 * time.Hour)
	hs.cve.scanErr.Store(true)
	hs.av.scanErr.Store(true)
	beforeCVE := hs.fc.entries[hs.ref.Key()].LastCVECheck
	beforeMalware := hs.fc.entries[hs.ref.Key()].LastMalwareCheck

	resp := hs.get(t)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "scanner outage must serve the stale clean artifact")
	e := hs.fc.entries[hs.ref.Key()]
	assert.Equal(t, beforeCVE, e.LastCVECheck, "failed re-check must not bump the CVE timestamp")
	assert.Equal(t, beforeMalware, e.LastMalwareCheck, "failed re-check must not bump the malware timestamp")
}

func TestRecheck_NilScannersSkipRecheck(t *testing.T) {
	upstream := makeUpstream(t, "victim", "1.0.0", 72)
	t.Cleanup(upstream.Close)

	fc := newFakeCache()
	rec := &eventSpy{}
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:           adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:            supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:             fc,
		Logger:            zerolog.Nop(),
		CVEScanner:        nil,
		Policy:            nil,
		AVScanner:         nil,
		Recorder:          rec,
		CVERecheckTTL:     time.Hour,
		MalwareRecheckTTL: time.Hour,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	ref := gate.PackageRef{Ecosystem: "pypi", Name: "victim", Version: "1.0.0"}
	path := "/packages/py3/v/victim/victim-1.0.0-py3-none-any.whl"

	resp, err := http.Get(srv.URL + path)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed download must pass with nil scanners")

	e := fc.entries[ref.Key()]
	require.NotNil(t, e, "seed download must cache an entry")
	e.LastCVECheck = e.LastCVECheck.Add(-1000 * time.Hour)
	e.LastMalwareCheck = e.LastMalwareCheck.Add(-1000 * time.Hour)

	resp2, err := http.Get(srv.URL + path)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "nil scanners must skip recheck entirely")
	_, cached := fc.entries[ref.Key()]
	assert.True(t, cached, "entry must remain cached")
}

func TestRecheck_ZeroTTLDisables(t *testing.T) {
	hs := newRecheckHarness(t, 0, 0)
	hs.rewind(1000 * time.Hour)
	hs.cve.vulnerable.Store(true)
	hs.av.infected.Store(true)
	cveCalls, avCalls := hs.cve.calls.Load(), hs.av.calls.Load()

	resp := hs.get(t)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "TTL 0 disables re-checks entirely")
	assert.Equal(t, cveCalls, hs.cve.calls.Load())
	assert.Equal(t, avCalls, hs.av.calls.Load())
}

// gatedAV blocks every Scan until release is closed, then answers per the
// infected/scanErr flags. Lets tests hold N concurrent requests inside one
// re-check flight before letting the leader finish.
type gatedAV struct {
	infected bool
	scanErr  bool
	release  chan struct{}
	calls    atomic.Int32
}

func (s *gatedAV) Scan(context.Context, string) (*gate.AVResult, error) {
	s.calls.Add(1)
	<-s.release
	if s.scanErr {
		return nil, errors.New("clamd down")
	}
	if s.infected {
		return &gate.AVResult{Clean: false, Engine: "clamav", Signature: "EICAR"}, nil
	}
	return &gate.AVResult{Clean: true}, nil
}

// coalesceHarness is newRecheckHarness with a gated AV scanner and an
// entered-request counter for barrier synchronization.
type coalesceHarness struct {
	srv     *httptest.Server
	fc      *fakeCache
	av      *gatedAV
	rec     *eventSpy
	entered *atomic.Int32
	ref     gate.PackageRef
	path    string
}

func newCoalesceHarness(t *testing.T, infected bool) *coalesceHarness {
	t.Helper()
	upstream := makeUpstream(t, "victim", "1.0.0", 72)
	t.Cleanup(upstream.Close)

	fc := newFakeCache()
	av := &gatedAV{infected: false, release: make(chan struct{})}
	rec := &eventSpy{}
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:           adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:            supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:             fc,
		Logger:            zerolog.Nop(),
		AVScanner:         av,
		Recorder:          rec,
		MalwareRecheckTTL: time.Hour,
	})
	var entered atomic.Int32
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered.Add(1)
		h.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)

	hs := &coalesceHarness{
		srv: srv, fc: fc, av: av, rec: rec, entered: &entered,
		ref:  gate.PackageRef{Ecosystem: "pypi", Name: "victim", Version: "1.0.0"},
		path: "/packages/py3/v/victim/victim-1.0.0-py3-none-any.whl",
	}
	// Seed pull passes with the gate open (no re-check on a fresh insert; the
	// live-path AV scan still runs, so hold the gate open just for it).
	close(av.release)
	resp, err := http.Get(srv.URL + hs.path)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed download must pass")

	// Re-arm the gate and set the verdict for the re-check phase.
	av.release = make(chan struct{})
	av.infected = infected
	av.calls.Store(0)
	entered.Store(0)

	// Expire the malware check.
	e := fc.entries[hs.ref.Key()]
	e.LastMalwareCheck = e.LastMalwareCheck.Add(-2 * time.Hour)
	return hs
}

// fire launches n concurrent GETs, waits until all have entered the handler
// (plus a settle so followers reach the flight), releases the scanner, and
// returns the status codes.
func (hs *coalesceHarness) fire(t *testing.T, n int) []int {
	t.Helper()
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := http.Get(hs.srv.URL + hs.path)
			if err != nil {
				codes[i] = -1
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}(i)
	}
	require.Eventually(t, func() bool { return hs.entered.Load() == int32(n) },
		5*time.Second, 5*time.Millisecond, "all requests must enter the handler")
	time.Sleep(100 * time.Millisecond) // let followers reach the flight
	close(hs.av.release)
	wg.Wait()
	return codes
}

func TestRecheckCoalesce_CleanSingleScan(t *testing.T) {
	hs := newCoalesceHarness(t, false)
	codes := hs.fire(t, 8)
	for i, c := range codes {
		assert.Equal(t, http.StatusOK, c, "request %d", i)
	}
	assert.Equal(t, int32(1), hs.av.calls.Load(), "one flight, one scan")
	_, cached := hs.fc.entries[hs.ref.Key()]
	assert.True(t, cached, "clean re-check must keep the entry")
}

func TestRecheckCoalesce_BlockSharedByAllWaiters(t *testing.T) {
	hs := newCoalesceHarness(t, true)
	codes := hs.fire(t, 8)
	for i, c := range codes {
		assert.Equal(t, http.StatusForbidden, c, "request %d", i)
	}
	assert.Equal(t, int32(1), hs.av.calls.Load(), "one flight, one scan")
	_, cached := hs.fc.entries[hs.ref.Key()]
	assert.False(t, cached, "blocked entry must be evicted")

	// Every waiter records its own BLOCK event with a distinct request_id.
	var blocks []gate.Event
	for _, ev := range hs.rec.events {
		if ev.Verdict == gate.VerdictBlock && ev.Gate == gate.GateMalware {
			blocks = append(blocks, ev)
		}
	}
	assert.Len(t, blocks, 8, "one BLOCK event per waiter")
	ids := map[string]bool{}
	for _, ev := range blocks {
		ids[ev.RequestID] = true
	}
	assert.Len(t, ids, 8, "request_ids must be distinct")
}

func TestRecheckCoalesce_ScannerErrorAllServeStale(t *testing.T) {
	hs := newCoalesceHarness(t, false)
	hs.av.scanErr = true
	before := hs.fc.entries[hs.ref.Key()].LastMalwareCheck
	codes := hs.fire(t, 8)
	for i, c := range codes {
		assert.Equal(t, http.StatusOK, c, "request %d: scanner outage must serve stale", i)
	}
	assert.Equal(t, int32(1), hs.av.calls.Load(), "one flight, one (failed) scan")
	assert.Equal(t, before, hs.fc.entries[hs.ref.Key()].LastMalwareCheck,
		"failed re-check must not bump the timestamp")
}
