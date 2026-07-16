package console_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/storage/storagetest"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func newTelemetryStore(t *testing.T) *telemetry.Store {
	t.Helper()
	db, err := storage.Open(filepath.Join(storagetest.TempDir(t), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := telemetry.Open(db, 30, 365, zerolog.Nop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

type stubHealth struct{ scanners []health.ScannerHealth }

func (s stubHealth) Snapshot() []health.ScannerHealth { return s.scanners }

type fakeStats struct{ stats cache.CacheStats }

func (f *fakeStats) Stats() (cache.CacheStats, error) { return f.stats, nil }

type fakePurger struct {
	removed, freed int64
	err            error
	calls          int
}

func (f *fakePurger) PurgeStale() (int64, int64, error) {
	f.calls++
	return f.removed, f.freed, f.err
}

type fixture struct {
	store   *telemetry.Store
	hub     *telemetry.Hub
	runtime *policy.Runtime
	srv     *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store := newTelemetryStore(t)
	bcast := telemetry.NewBroadcaster()
	runtime := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{Enabled: true, BlockOn: "HIGH"},
		config.PolicyProfile{CVEBlock: true},
		nil,
	)
	h := console.NewHandler(console.Config{
		Store:               store,
		Broadcaster:         bcast,
		Policy:              runtime,
		Cache:               &fakeStats{stats: cache.CacheStats{Entries: 42, SizeBytes: 1 << 30, HitRatio: 0.5, Evictions: 3, StaleBytes: 7 << 20}},
		CacheMaxBytes:       64 << 30,
		CacheStaleAfterDays: 30,
		Purger:              &fakePurger{removed: 12, freed: 5 << 20},
		Registries: []console.RegistryInfo{
			{Ecosystem: "pypi", Enabled: true, Upstreams: []string{"https://pypi.org/simple"}},
		},
		Health: stubHealth{scanners: []health.ScannerHealth{
			{Name: "osv.dev", Detail: "https://api.osv.dev", Enabled: true, Status: health.StatusOK, LatencyMS: 42},
		}},
		Logger: zerolog.Nop(),
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

func blockEvent(id string, until time.Time) gate.Event {
	return gate.Event{
		RequestID: id, Time: time.Now(),
		Ecosystem: "npm", Package: "fresh", Version: "1.0.0",
		Verdict: gate.VerdictBlock, Gate: gate.GateSupply,
		Reason: "package_younger_than_min_age", HTTPStatus: 423,
		BlockedBy:   []string{"supply_chain"},
		PublishedAt: time.Now().Add(-time.Hour), BlockUntil: until,
	}
}

func TestOverview(t *testing.T) {
	f := newFixture(t)
	f.store.Record(gate.Event{Verdict: gate.VerdictCache, Gate: gate.GateCache, Time: time.Now()})

	var body struct {
		StartedAt time.Time `json:"started_at"`
		KPIs      struct {
			RequestsTotal uint64  `json:"requests_total"`
			CacheHits     uint64  `json:"cache_hits"`
			HitRate       float64 `json:"hit_rate"`
		} `json:"kpis"`
		Gates map[string]telemetry.GateCounts `json:"gates"`
		Cache struct {
			Objects        int64   `json:"objects"`
			MaxBytes       int64   `json:"max_bytes"`
			HitRate        float64 `json:"hit_rate"`
			StaleBytes     int64   `json:"stale_bytes"`
			StaleAfterDays int     `json:"stale_after_days"`
		} `json:"cache"`
		Scanners []health.ScannerHealth `json:"scanners"`
	}
	code := getJSON(t, f.srv.URL+"/api/overview", &body)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, uint64(1), body.KPIs.RequestsTotal)
	assert.Equal(t, uint64(1), body.KPIs.CacheHits)
	assert.InDelta(t, 1.0, body.KPIs.HitRate, 0.001)
	assert.Equal(t, telemetry.GateCounts{Pass: 1}, body.Gates["cache"])
	assert.Equal(t, int64(42), body.Cache.Objects)
	assert.Equal(t, int64(64<<30), body.Cache.MaxBytes)
	assert.Equal(t, int64(7<<20), body.Cache.StaleBytes)
	assert.Equal(t, 30, body.Cache.StaleAfterDays)
	// cache.hit_rate must equal kpis.hit_rate: LocalCache does not track
	// per-object hits, so the request-level rate is used for both.
	assert.InDelta(t, body.KPIs.HitRate, body.Cache.HitRate, 0.001)
	require.Len(t, body.Scanners, 1)
	assert.Equal(t, health.StatusOK, body.Scanners[0].Status)
	assert.Equal(t, int64(42), body.Scanners[0].LatencyMS)
	assert.False(t, body.StartedAt.IsZero())
}

func TestRequests(t *testing.T) {
	f := newFixture(t)
	for _, id := range []string{"r1", "r2", "r3"} {
		f.store.Record(gate.Event{RequestID: id, Verdict: gate.VerdictPass, Gate: gate.GateSupply, Time: time.Now(), Ecosystem: "pypi", Package: "p", Version: "1"})
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
		Mode            string   `json:"mode"`
		MinAgeHours     int      `json:"min_age_hours"`
		CVEBlockOn      string   `json:"cve_block_on"`
		AllowlistSupply []string `json:"allowlist_supply"`
		AllowlistCVE    []string `json:"allowlist_cve"`
		Persistence     string   `json:"persistence"`
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

	resp := put(`{"mode":"dry_run","min_age_hours":48,"cve_block_on":"CRITICAL","allowlist_supply":["pypi/requests"],"allowlist_cve":["npm/left-pad"],"denylist":[]}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&pol))
	assert.Equal(t, "dry_run", pol.Mode)
	assert.Equal(t, 48, pol.MinAgeHours)
	assert.Equal(t, []string{"pypi/requests"}, pol.AllowlistSupply)
	assert.Equal(t, []string{"npm/left-pad"}, pol.AllowlistCVE)
	assert.Equal(t, "dry_run", f.runtime.Current().Mode, "runtime actually swapped")

	resp = put(`{"mode":"yolo","min_age_hours":1,"cve_block_on":"HIGH","allowlist_supply":[],"allowlist_cve":[],"denylist":[]}`)
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

	resp = put(`{"mode":"enforce","min_age_hours":1,"cve_block_on":"HIGH","allowlist":["pypi/x"],"denylist":[]}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "legacy allowlist key rejected by DisallowUnknownFields")
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
	store := newTelemetryStore(t)
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
	hub.Record(gate.Event{RequestID: "req_late", Verdict: gate.VerdictPass, Gate: gate.GateCache, Time: time.Now()})

	line, err = reader.ReadString('\n')
	require.NoError(t, err, "stream died after the server write deadline")
	assert.Contains(t, line, `"request_id":"req_late"`)
}

// An idle SSE stream must emit periodic heartbeat comments: with no traffic
// the stream is otherwise silent for hours, and idle TCP connections get
// dropped by intermediaries (Docker port-forwards, AV web filters) — the
// console then shows its "no connection" banner although the API is healthy.
func TestEventsSSE_HeartbeatOnIdleStream(t *testing.T) {
	store := newTelemetryStore(t)
	h := console.NewHandler(console.Config{
		Store:        store,
		Broadcaster:  telemetry.NewBroadcaster(),
		Logger:       zerolog.Nop(),
		SSEHeartbeat: 50 * time.Millisecond,
	})
	srv := httptest.NewServer(h)
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

	// No events are published; the next bytes on the wire must be heartbeats.
	for i := 0; i < 2; i++ {
		line, err = reader.ReadString('\n')
		require.NoError(t, err, "idle stream produced no heartbeat")
		assert.True(t, strings.HasPrefix(line, ": ping"), "got %q", line)
		_, err = reader.ReadString('\n') // trailing blank line
		require.NoError(t, err)
	}
}

// Regression: disabled registries have no upstreams configured; the wire
// shape must stay an array — null crashes the SPA's Registries screen.
func TestRegistries_NilUpstreams(t *testing.T) {
	store := newTelemetryStore(t)
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

	f.hub.Record(gate.Event{RequestID: "req_sse", Verdict: gate.VerdictPass, Gate: gate.GateMalware, Time: time.Now()})

	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(line, "data: "), "got %q", line)
	assert.Contains(t, line, `"request_id":"req_sse"`)
}

func TestDailyMetrics(t *testing.T) {
	f := newFixture(t)
	f.store.Record(gate.Event{Time: time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC), Verdict: gate.VerdictCache, Gate: gate.GateCache})
	f.store.Record(gate.Event{Time: time.Date(2026, 1, 2, 1, 0, 0, 0, time.UTC), Verdict: gate.VerdictCache, Gate: gate.GateCache})

	var body struct {
		Daily []telemetry.DailyMetric `json:"daily"`
	}
	code := getJSON(t, f.srv.URL+"/api/metrics/daily?days=1", &body)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, body.Daily, 1)
	assert.Equal(t, "2026-01-02", body.Daily[0].Day) // newest first, limited to 1
}

func TestDailyMetrics_InvalidDays(t *testing.T) {
	f := newFixture(t)
	var body map[string]any
	code := getJSON(t, f.srv.URL+"/api/metrics/daily?days=abc", &body)
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestPutPolicyLogsWithoutUserWhenContextEmpty(t *testing.T) {
	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)

	rt := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{}, config.PolicyProfile{}, nil,
	)
	h := console.NewHandler(console.Config{
		Store: newTelemetryStore(t), Broadcaster: telemetry.NewBroadcaster(),
		Policy: rt, Logger: logger,
	})

	body := `{"mode":"enforce","min_age_hours":24,"cve_block_on":"HIGH","allowlist_supply":[],"allowlist_cve":[],"denylist":[]}`
	req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	// No authenticating middleware in front, so the log line must not carry a
	// "user" field (and must not panic building it).
	assert.NotContains(t, logBuf.String(), `"user"`)
}

func TestRequestsFilterByVerdictAndPage(t *testing.T) {
	f := newFixture(t)
	f.store.Record(gate.Event{RequestID: "pass1", Verdict: gate.VerdictPass, Gate: gate.GateSupply, Time: time.Now(), Ecosystem: "pypi", Package: "p", Version: "1"})
	f.store.Record(gate.Event{RequestID: "block1", Verdict: gate.VerdictBlock, Gate: gate.GateCVE, Time: time.Now().Add(time.Second), Ecosystem: "pypi", Package: "p", Version: "1"})
	f.store.Record(gate.Event{RequestID: "block2", Verdict: gate.VerdictBlock, Gate: gate.GateSupply, Time: time.Now().Add(2 * time.Second), Ecosystem: "pypi", Package: "p", Version: "1"})

	var page1 struct {
		Requests []struct {
			RequestID string `json:"request_id"`
		} `json:"requests"`
		NextCursor string `json:"next_cursor"`
	}
	code := getJSON(t, f.srv.URL+"/api/requests?verdict=BLOCK&limit=1", &page1)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, page1.Requests, 1)
	assert.Equal(t, "block2", page1.Requests[0].RequestID, "newest blocked first")
	require.NotEmpty(t, page1.NextCursor, "more blocked rows remain")

	var page2 struct {
		Requests []struct {
			RequestID string `json:"request_id"`
		} `json:"requests"`
		NextCursor string `json:"next_cursor"`
	}
	code = getJSON(t, f.srv.URL+"/api/requests?verdict=BLOCK&limit=1&cursor="+url.QueryEscape(page1.NextCursor), &page2)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, page2.Requests, 1)
	assert.Equal(t, "block1", page2.Requests[0].RequestID)
	assert.Empty(t, page2.NextCursor, "no more pages")
}

func TestRequestsRejectsBadVerdictAndCursor(t *testing.T) {
	f := newFixture(t)

	// Assert the wire-contract error keys, not just the status code, so a future
	// rename of "invalid_verdict"/"invalid_cursor" is caught.
	badRequest := func(path, wantErr string) {
		t.Helper()
		var body struct {
			Error string `json:"error"`
		}
		resp, err := http.Get(f.srv.URL + path)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, wantErr, body.Error)
	}

	badRequest("/api/requests?verdict=BOGUS", "invalid_verdict")
	badRequest("/api/requests?cursor=not-a-cursor", "invalid_cursor")
}

func TestCacheCleanup(t *testing.T) {
	f := newFixture(t)

	resp, err := http.Post(f.srv.URL+"/api/cache/cleanup", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Removed    int64 `json:"removed"`
		FreedBytes int64 `json:"freed_bytes"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, int64(12), body.Removed)
	assert.Equal(t, int64(5<<20), body.FreedBytes)
}

func TestCacheCleanup_NoPurger(t *testing.T) {
	h := console.NewHandler(console.Config{
		Store:       newTelemetryStore(t),
		Broadcaster: telemetry.NewBroadcaster(),
		Logger:      zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/cache/cleanup", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestCacheCleanup_PurgeError(t *testing.T) {
	h := console.NewHandler(console.Config{
		Store:       newTelemetryStore(t),
		Broadcaster: telemetry.NewBroadcaster(),
		Purger:      &fakePurger{err: errors.New("db locked")},
		Logger:      zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/cache/cleanup", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
