package console_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

type fakeStats struct{ stats cache.CacheStats }

func (f *fakeStats) Stats() (cache.CacheStats, error) { return f.stats, nil }

type fixture struct {
	store   *telemetry.Store
	hub     *telemetry.Hub
	runtime *policy.Runtime
	srv     *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store := telemetry.NewStore(16)
	bcast := telemetry.NewBroadcaster()
	runtime := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{Enabled: true, BlockOn: "HIGH"},
		config.PolicyProfile{CVEBlock: true},
		nil,
	)
	h := console.NewHandler(console.Config{
		Store:         store,
		Broadcaster:   bcast,
		Policy:        runtime,
		Cache:         &fakeStats{stats: cache.CacheStats{Entries: 42, SizeBytes: 1 << 30, HitRatio: 0.5, Evictions: 3}},
		CacheMaxBytes: 64 << 30,
		Registries: []console.RegistryInfo{
			{Ecosystem: "pypi", Enabled: true, Upstreams: []string{"https://pypi.org/simple"}},
		},
		Scanners: []console.ScannerInfo{{Name: "osv.dev", Detail: "https://api.osv.dev", Enabled: true}},
		Logger:   zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &fixture{store: store, hub: &telemetry.Hub{Store: store, Broadcaster: bcast}, runtime: runtime, srv: srv}
}

func getJSON(t *testing.T, url string, into any) int {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.NoError(t, json.NewDecoder(resp.Body).Decode(into))
	return resp.StatusCode
}

func blockEvent(id string, until time.Time) proxy.Event {
	return proxy.Event{
		RequestID: id, Time: time.Now(),
		Ecosystem: "npm", Package: "fresh", Version: "1.0.0",
		Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply,
		Reason: "package_younger_than_min_age", HTTPStatus: 423,
		BlockedBy:   []string{"supply_chain"},
		PublishedAt: time.Now().Add(-time.Hour), BlockUntil: until,
	}
}

func TestOverview(t *testing.T) {
	f := newFixture(t)
	f.store.Record(proxy.Event{Verdict: proxy.VerdictCache, Gate: proxy.GateCache, Time: time.Now()})

	var body struct {
		StartedAt time.Time `json:"started_at"`
		KPIs      struct {
			RequestsTotal uint64  `json:"requests_total"`
			CacheHits     uint64  `json:"cache_hits"`
			HitRate       float64 `json:"hit_rate"`
		} `json:"kpis"`
		Gates map[string]telemetry.GateCounts `json:"gates"`
		Cache struct {
			Objects  int64   `json:"objects"`
			MaxBytes int64   `json:"max_bytes"`
			HitRate  float64 `json:"hit_rate"`
		} `json:"cache"`
		Scanners []console.ScannerInfo `json:"scanners"`
	}
	code := getJSON(t, f.srv.URL+"/api/overview", &body)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, uint64(1), body.KPIs.RequestsTotal)
	assert.Equal(t, uint64(1), body.KPIs.CacheHits)
	assert.InDelta(t, 1.0, body.KPIs.HitRate, 0.001)
	assert.Equal(t, telemetry.GateCounts{Pass: 1}, body.Gates["cache"])
	assert.Equal(t, int64(42), body.Cache.Objects)
	assert.Equal(t, int64(64<<30), body.Cache.MaxBytes)
	// cache.hit_rate must equal kpis.hit_rate: LocalCache does not track
	// per-object hits, so the request-level rate is used for both.
	assert.InDelta(t, body.KPIs.HitRate, body.Cache.HitRate, 0.001)
	require.Len(t, body.Scanners, 1)
	assert.False(t, body.StartedAt.IsZero())
}

func TestRequests(t *testing.T) {
	f := newFixture(t)
	for _, id := range []string{"r1", "r2", "r3"} {
		f.store.Record(proxy.Event{RequestID: id, Verdict: proxy.VerdictPass, Gate: proxy.GateSupply, Time: time.Now(), Ecosystem: "pypi", Package: "p", Version: "1"})
	}

	var body struct {
		Requests []struct {
			RequestID string `json:"request_id"`
			Eco       string `json:"eco"`
			Verdict   string `json:"verdict"`
		} `json:"requests"`
	}
	code := getJSON(t, f.srv.URL+"/api/requests?limit=2", &body)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, body.Requests, 2)
	assert.Equal(t, "r3", body.Requests[0].RequestID, "newest first")
	assert.Equal(t, "pypi", body.Requests[0].Eco)

	resp, err := http.Get(f.srv.URL + "/api/requests?limit=abc")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestQuarantine(t *testing.T) {
	f := newFixture(t)
	f.store.Record(blockEvent("r1", time.Now().Add(6*time.Hour)))
	f.store.Record(blockEvent("r2", time.Now().Add(-time.Hour))) // expired duplicate, newest — replaces r1 (same pkg) and is expired

	var body struct {
		Quarantine []struct {
			Eco        string    `json:"eco"`
			Pkg        string    `json:"pkg"`
			BlockUntil time.Time `json:"block_until"`
		} `json:"quarantine"`
	}
	code := getJSON(t, f.srv.URL+"/api/quarantine", &body)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, body.Quarantine, 0, "newest record for the package is expired")

	f.store.Record(blockEvent("r3", time.Now().Add(6*time.Hour)))
	getJSON(t, f.srv.URL+"/api/quarantine", &body)
	require.Len(t, body.Quarantine, 1)
	assert.Equal(t, "npm", body.Quarantine[0].Eco)
	assert.Equal(t, "fresh", body.Quarantine[0].Pkg)
}

func TestPolicyGetAndPut(t *testing.T) {
	f := newFixture(t)

	var pol struct {
		Mode        string   `json:"mode"`
		MinAgeHours int      `json:"min_age_hours"`
		CVEBlockOn  string   `json:"cve_block_on"`
		Allowlist   []string `json:"allowlist"`
		Persistence string   `json:"persistence"`
	}
	code := getJSON(t, f.srv.URL+"/api/policy", &pol)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "enforce", pol.Mode)
	assert.Equal(t, 24, pol.MinAgeHours)
	assert.Equal(t, "HIGH", pol.CVEBlockOn)
	assert.Equal(t, "runtime", pol.Persistence)

	put := func(body string) *http.Response {
		req, err := http.NewRequest(http.MethodPut, f.srv.URL+"/api/policy", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		return resp
	}

	// GET → PUT round-trip: echo the GET response body back via PUT; must succeed
	// because "persistence" is a read-only field that PUT accepts and ignores.
	rawResp, err := http.Get(f.srv.URL + "/api/policy")
	require.NoError(t, err)
	var rawPolicy map[string]any
	require.NoError(t, json.NewDecoder(rawResp.Body).Decode(&rawPolicy))
	rawResp.Body.Close()
	rawBytes, err := json.Marshal(rawPolicy)
	require.NoError(t, err)
	roundTrip := put(string(rawBytes))
	defer roundTrip.Body.Close()
	require.Equal(t, http.StatusOK, roundTrip.StatusCode, "GET→PUT round-trip must succeed when persistence field is present")

	resp := put(`{"mode":"dry_run","min_age_hours":48,"cve_block_on":"CRITICAL","allowlist":["pypi/requests"],"denylist":[]}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&pol))
	assert.Equal(t, "dry_run", pol.Mode)
	assert.Equal(t, 48, pol.MinAgeHours)
	assert.Equal(t, []string{"pypi/requests"}, pol.Allowlist)
	assert.Equal(t, "dry_run", f.runtime.Current().Mode, "runtime actually swapped")

	resp = put(`{"mode":"yolo","min_age_hours":1,"cve_block_on":"HIGH","allowlist":[],"denylist":[]}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errBody struct {
		Error string `json:"error"`
		Field string `json:"field"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "invalid_policy", errBody.Error)
	assert.Equal(t, "mode", errBody.Field)
	assert.Equal(t, "dry_run", f.runtime.Current().Mode, "policy unchanged after 400")
}

func TestRegistries(t *testing.T) {
	f := newFixture(t)
	var body struct {
		Registries []console.RegistryInfo `json:"registries"`
	}
	code := getJSON(t, f.srv.URL+"/api/registries", &body)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, body.Registries, 1)
	assert.Equal(t, "pypi", body.Registries[0].Ecosystem)
}

// Regression: the SSE stream must outlive the http.Server Read/WriteTimeouts
// (cmd/jo-ei sets 120s). The deadlines are armed once at request start, so
// without per-stream deadline management the first event written after the
// timeout kills the connection and the event is silently lost.
func TestEventsSSE_OutlivesServerTimeouts(t *testing.T) {
	store := telemetry.NewStore(16)
	bcast := telemetry.NewBroadcaster()
	hub := &telemetry.Hub{Store: store, Broadcaster: bcast}
	h := console.NewHandler(console.Config{
		Store: store, Broadcaster: bcast, Logger: zerolog.Nop(),
	})
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ReadTimeout = 300 * time.Millisecond
	srv.Config.WriteTimeout = 300 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/events", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(line, ": connected"), "got %q", line)
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	// Outlive both server deadlines, then publish.
	time.Sleep(600 * time.Millisecond)
	hub.Record(proxy.Event{RequestID: "req_late", Verdict: proxy.VerdictPass, Gate: proxy.GateCache, Time: time.Now()})

	line, err = reader.ReadString('\n')
	require.NoError(t, err, "stream died after the server write deadline")
	assert.Contains(t, line, `"request_id":"req_late"`)
}

// Regression: disabled registries have no upstreams configured; the wire
// shape must stay an array — null crashes the SPA's Registries screen.
func TestRegistries_NilUpstreams(t *testing.T) {
	store := telemetry.NewStore(16)
	h := console.NewHandler(console.Config{
		Store:       store,
		Broadcaster: telemetry.NewBroadcaster(),
		Registries: []console.RegistryInfo{
			{Ecosystem: "npm", Enabled: false, Upstreams: nil},
		},
		Logger: zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/registries")
	require.NoError(t, err)
	defer resp.Body.Close()
	var raw bytes.Buffer
	_, err = raw.ReadFrom(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, raw.String(), `"upstreams":[]`)
	assert.NotContains(t, raw.String(), `"upstreams":null`)
}

func TestEventsSSE(t *testing.T) {
	f := newFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.srv.URL+"/api/events", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	reader := bufio.NewReader(resp.Body)
	// The handler sends ": connected" once the subscription is registered.
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if strings.HasPrefix(line, ": connected") {
			break
		}
	}
	// Drain the comment's trailing blank line before the first event.
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	f.hub.Record(proxy.Event{RequestID: "req_sse", Verdict: proxy.VerdictPass, Gate: proxy.GateMalware, Time: time.Now()})

	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(line, "data: "), "got %q", line)
	assert.Contains(t, line, `"request_id":"req_sse"`)
}
