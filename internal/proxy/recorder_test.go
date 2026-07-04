package proxy_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

type fakeRecorder struct {
	mu     sync.Mutex
	events []gate.Event
}

func (f *fakeRecorder) Record(ev gate.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

func (f *fakeRecorder) last(t *testing.T) gate.Event {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.events, "expected at least one recorded event")
	return f.events[len(f.events)-1]
}

// recorderProxy builds a test proxy with a fakeRecorder attached. Extra
// scanners are optional.
func recorderProxy(t *testing.T, upstream *httptest.Server, mode string, cve gate.CVEScanner, pol gate.PolicyDecider, av gate.AVScanner) (*httptest.Server, *fakeRecorder) {
	t.Helper()
	rec := &fakeRecorder{}
	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:     supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: mode}, nil),
		Cache:      newFakeCache(),
		Logger:     zerolog.Nop(),
		CVEScanner: cve,
		Policy:     pol,
		AVScanner:  av,
		Recorder:   rec,
	})
	return httptest.NewServer(handler), rec
}

func TestRecorder_PassEvent(t *testing.T) {
	upstream := makeUpstream(t, "requests", "2.31.0", 48)
	defer upstream.Close()
	srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	ev := rec.last(t)
	assert.Equal(t, gate.VerdictPass, ev.Verdict)
	assert.Equal(t, gate.GateSupply, ev.Gate, "no scanners configured → supply is the deepest gate")
	assert.Equal(t, "ok", ev.Reason)
	assert.Equal(t, "pypi", ev.Ecosystem)
	assert.Equal(t, "requests", ev.Package)
	assert.Equal(t, "2.31.0", ev.Version)
	assert.Equal(t, http.StatusOK, ev.HTTPStatus)
	assert.NotEmpty(t, ev.RequestID)
	assert.False(t, ev.PublishedAt.IsZero())
	assert.GreaterOrEqual(t, ev.LatencyMS, int64(0))
}

func TestRecorder_CacheHitEvent(t *testing.T) {
	upstream := makeUpstream(t, "requests", "2.31.0", 48)
	defer upstream.Close()
	srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, nil)
	defer srv.Close()

	url := srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl"
	for i := 0; i < 2; i++ {
		resp, err := http.Get(url)
		require.NoError(t, err)
		resp.Body.Close()
	}

	ev := rec.last(t)
	assert.Equal(t, gate.VerdictCache, ev.Verdict)
	assert.Equal(t, gate.GateCache, ev.Gate)
	assert.Equal(t, "cache_hit", ev.Reason)
}

func TestRecorder_SupplyBlockEvent(t *testing.T) {
	upstream := makeUpstream(t, "fresh-pkg", "1.0.0", 1) // 1h old < 24h min age
	defer upstream.Close()
	srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/f/fresh-pkg/fresh_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusLocked, resp.StatusCode)

	ev := rec.last(t)
	assert.Equal(t, gate.VerdictBlock, ev.Verdict)
	assert.Equal(t, gate.GateSupply, ev.Gate)
	assert.Equal(t, http.StatusLocked, ev.HTTPStatus)
	assert.Equal(t, []string{"supply_chain"}, ev.BlockedBy)
	assert.False(t, ev.PublishedAt.IsZero())
	assert.False(t, ev.BlockUntil.IsZero())
}

func TestRecorder_CVEBlockEvent(t *testing.T) {
	upstream := makeUpstream(t, "vuln-pkg", "1.0.0", 48)
	defer upstream.Close()
	scanner := &mockScanner{result: &gate.ScanResult{
		Findings: []gate.CVEFinding{{ID: "CVE-2024-0001", Severity: gate.SeverityCritical, Summary: "bad"}},
	}}
	engine := policy.NewEngine(config.CVEConfig{BlockOn: "HIGH"}, config.PolicyProfile{CVEBlock: true})
	srv, rec := recorderProxy(t, upstream, "enforce", scanner, engine, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/v/vuln-pkg/vuln_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	ev := rec.last(t)
	assert.Equal(t, gate.VerdictBlock, ev.Verdict)
	assert.Equal(t, gate.GateCVE, ev.Gate)
	assert.Equal(t, "cve_found", ev.Reason)
	assert.Equal(t, []string{"cve"}, ev.BlockedBy)
	require.Len(t, ev.CVEs, 1)
	assert.Equal(t, "CVE-2024-0001", ev.CVEs[0].ID)
}

func TestRecorder_DenylistBlockEvent(t *testing.T) {
	upstream := makeUpstream(t, "evil-pkg", "1.0.0", 48)
	defer upstream.Close()
	scanner := &mockScanner{result: &gate.ScanResult{Clean: true}}
	engine := policy.NewEngine(config.CVEConfig{BlockOn: "HIGH"},
		config.PolicyProfile{CVEBlock: true, Denylist: []string{"pypi/evil-pkg"}})
	srv, rec := recorderProxy(t, upstream, "enforce", scanner, engine, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/e/evil-pkg/evil_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	ev := rec.last(t)
	assert.Equal(t, "denylisted", ev.Reason)
	assert.Equal(t, []string{"denylist"}, ev.BlockedBy)
}

func TestRecorder_MalwareBlockEvent(t *testing.T) {
	upstream := makeUpstream(t, "trojan", "1.0.0", 48)
	defer upstream.Close()
	av := &mockAVScanner{result: &gate.AVResult{Clean: false, Engine: "clamav", Signature: "Eicar-Test"}}
	srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, av)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/t/trojan/trojan-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	ev := rec.last(t)
	assert.Equal(t, gate.VerdictBlock, ev.Verdict)
	assert.Equal(t, gate.GateMalware, ev.Gate)
	assert.Equal(t, "malware_found", ev.Reason)
	assert.Equal(t, []string{"malware"}, ev.BlockedBy)
	assert.Equal(t, "clamav", ev.MalwareEngine)
	assert.Equal(t, "Eicar-Test", ev.MalwareSignature)
}

func TestRecorder_ErrorEvents(t *testing.T) {
	t.Run("metadata unavailable → supply", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer upstream.Close()
		srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, nil)
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/packages/py3/p/pkg/pkg-1.0.0-py3-none-any.whl")
		require.NoError(t, err)
		resp.Body.Close()

		ev := rec.last(t)
		assert.Equal(t, gate.VerdictError, ev.Verdict)
		assert.Equal(t, gate.GateSupply, ev.Gate)
		assert.Equal(t, "upstream_metadata_unavailable", ev.Reason)
	})

	t.Run("cve scanner error → cve", func(t *testing.T) {
		upstream := makeUpstream(t, "pkg", "1.0.0", 48)
		defer upstream.Close()
		scanner := &mockScanner{err: fmt.Errorf("osv.dev unavailable")}
		srv, rec := recorderProxy(t, upstream, "enforce", scanner, nil, nil)
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/packages/py3/p/pkg/pkg-1.0.0-py3-none-any.whl")
		require.NoError(t, err)
		resp.Body.Close()

		ev := rec.last(t)
		assert.Equal(t, gate.VerdictError, ev.Verdict)
		assert.Equal(t, gate.GateCVE, ev.Gate)
		assert.Equal(t, "cve_scan_error", ev.Reason)
	})

	t.Run("av scanner error → malware", func(t *testing.T) {
		upstream := makeUpstream(t, "pkg", "1.0.0", 48)
		defer upstream.Close()
		av := &mockAVScanner{err: fmt.Errorf("clamd unavailable")}
		srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, av)
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/packages/py3/p/pkg/pkg-1.0.0-py3-none-any.whl")
		require.NoError(t, err)
		resp.Body.Close()

		ev := rec.last(t)
		assert.Equal(t, gate.VerdictError, ev.Verdict)
		assert.Equal(t, gate.GateMalware, ev.Gate)
		assert.Equal(t, "av_scan_error", ev.Reason)
	})
}
