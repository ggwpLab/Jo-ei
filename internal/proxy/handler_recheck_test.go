package proxy_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
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

type eventSpy struct{ events []gate.Event }

func (r *eventSpy) Record(e gate.Event) { r.events = append(r.events, e) }

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
	before := hs.fc.entries[hs.ref.Key()].LastCVECheck

	resp := hs.get(t)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "scanner outage must serve the stale clean artifact")
	e := hs.fc.entries[hs.ref.Key()]
	assert.Equal(t, before, e.LastCVECheck, "failed re-check must not bump the timestamp")
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
