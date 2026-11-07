//go:build integration

package integration_test

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/metrics"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type asyncHeldRepo struct {
	telemetry.Repo
	entered, release chan struct{}
	once             sync.Once
}

func (r *asyncHeldRepo) RecordBatch(ctx context.Context, token string, events []telemetry.BatchEvent) error {
	r.once.Do(func() { close(r.entered) })
	select {
	case <-r.release:
		return r.Repo.RecordBatch(ctx, token, events)
	case <-ctx.Done():
		return ctx.Err()
	}
}
func heldAsyncStore(t *testing.T) (*telemetry.Store, <-chan struct{}, func()) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "events.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	real, err := telemetry.NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)
	r := &asyncHeldRepo{Repo: real, entered: make(chan struct{}), release: make(chan struct{})}
	s := telemetry.New(r, zerolog.Nop())
	var once sync.Once
	release := func() { once.Do(func() { close(r.release) }) }
	t.Cleanup(func() { release(); require.NoError(t, s.Close()) })
	return s, r.entered, release
}
func asyncAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("async handshake timed out")
	}
}

type asyncCVE struct {
	blocked bool
	calls   *atomic.Int64
}

func (s asyncCVE) Scan(context.Context, *gate.PackageRef) (*gate.ScanResult, error) {
	if s.calls != nil {
		s.calls.Add(1)
	}
	r := &gate.ScanResult{}
	if s.blocked {
		r.Findings = []gate.CVEFinding{{ID: "CVE-test", Severity: gate.SeverityHigh}}
	}
	return r, nil
}

type asyncAV struct {
	infected, incomplete, failed bool
	calls                        *atomic.Int64
}

func (s asyncAV) Scan(context.Context, string) (*gate.AVResult, error) {
	if s.calls != nil {
		s.calls.Add(1)
	}
	if s.failed {
		return nil, errors.New("scanner unavailable")
	}
	return &gate.AVResult{Clean: !s.infected && !s.incomplete, Incomplete: s.incomplete, Engine: "test", Signature: "detected"}, nil
}

func TestAsyncTelemetry_OverflowDoesNotWaitOrChangeEnforcement(t *testing.T) {
	s, entered, release := heldAsyncStore(t)
	b := telemetry.NewBroadcaster()
	hub := telemetry.NewHub(s, b)
	m := metrics.New(metrics.BuildInfo{}, zerolog.Nop())
	m.RegisterAsyncWriter("telemetry", s.WriterStats)
	rec := m.WrapRecorder(hub)
	s.Record(gate.Event{RequestID: "seed-active", Time: time.Now()})
	s.RequestFlush()
	asyncAwait(t, entered)
	for i := int64(0); i < s.WriterStats().Capacity; i++ {
		s.Record(gate.Event{RequestID: fmt.Sprintf("seed-%d", i), Time: time.Now()})
	}
	require.Equal(t, s.WriterStats().Capacity, s.WriterStats().Queued)
	before := s.WriterStats()
	ch, cancel := b.Subscribe()
	defer cancel()
	cases := []struct {
		name        string
		status, age int
		warm, cve   bool
		av          asyncAV
	}{
		{name: "warm", status: 200, age: 48, warm: true}, {name: "pass", status: 200, age: 48},
		{name: "supply", status: 423, age: 1}, {name: "cve", status: 403, age: 48, cve: true},
		{name: "averror", status: 503, age: 48, av: asyncAV{failed: true}},
		{name: "infected", status: 403, age: 48, av: asyncAV{infected: true}},
		{name: "incomplete", status: 403, age: 48, av: asyncAV{incomplete: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, tc.name, "1.0.0", tc.age)
			defer registry.Close()
			lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir()})
			require.NoError(t, err)
			defer lc.Close()
			ref := &gate.PackageRef{Ecosystem: "pypi", Name: tc.name, Version: "1.0.0", Classifier: tc.name + "-1.0.0-py3-none-any.whl"}
			if tc.warm {
				p := filepath.Join(t.TempDir(), "warm")
				require.NoError(t, os.WriteFile(p, []byte("verified-warm-payload"), 0600))
				require.NoError(t, lc.Put(ref, p, true, "clean"))
			}
			h := proxy.NewHandler(proxy.HandlerConfig{Adapter: adapters.NewPyPIAdapter([]string{registry.URL}), Cache: cache.AsArtifactCache(lc), Filter: supplychain.NewFilter(config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24}, nil), CVEScanner: asyncCVE{blocked: tc.cve}, AVScanner: tc.av, Policy: policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, config.PolicyProfile{CVEBlock: true}), Recorder: rec, Logger: zerolog.Nop()})
			response := httptest.NewRecorder()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/packages/py3/p/"+tc.name+"/"+tc.name+"-1.0.0-py3-none-any.whl", nil))
			}()
			asyncAwait(t, finished)
			require.Equal(t, tc.status, response.Code, response.Body.String())
			entry, found := lc.Get(ref)
			if tc.status != 200 {
				assert.False(t, found, "denied artifact must not be published clean")
				assert.NotContains(t, response.Body.String(), "fake-wheel-content-for-"+tc.name+"-1.0.0")
			} else {
				require.True(t, found)
				assert.True(t, entry.ScanClean)
				if tc.warm {
					assert.Equal(t, "verified-warm-payload", response.Body.String())
				}
			}
		})
	}
	require.Equal(t, before.DroppedFullItems+uint64(len(cases)), s.WriterStats().DroppedFullItems)
	assert.Zero(t, s.Snapshot(context.Background()).Requests)
	assert.Empty(t, s.Recent(context.Background(), 0))
	select {
	case <-ch:
		t.Fatal("uncommitted event published")
	default:
	}
	families, err := m.Registry.Gather()
	require.NoError(t, err)
	var verdicts float64
	for _, f := range families {
		if f.GetName() == "jo_ei_verdicts_total" {
			for _, v := range f.Metric {
				verdicts += v.Counter.GetValue()
			}
		}
	}
	assert.Equal(t, float64(len(cases)), verdicts)
	release()
	require.NoError(t, s.Flush(context.Background()))
	snapshot := s.Snapshot(context.Background())
	assert.Equal(t, before.AcceptedItems, snapshot.Requests)
	assert.Equal(t, before.AcceptedItems, s.WriterStats().CommittedItems)
	history := s.Recent(context.Background(), 0)
	require.Len(t, history, int(before.AcceptedItems))
	for _, ev := range history {
		assert.True(t, strings.HasPrefix(ev.RequestID, "seed-"), "dropped request entered durable history")
	}
	for len(ch) > 0 {
		ev := <-ch
		assert.True(t, strings.HasPrefix(ev.RequestID, "seed-"), "dropped request entered SSE")
	}
	hub.Record(gate.Event{RequestID: "post-drain", Time: time.Now(), Verdict: gate.VerdictCache, Gate: gate.GateCache})
	require.NoError(t, s.Flush(context.Background()))
	select {
	case ev := <-ch:
		assert.Equal(t, "post-drain", ev.RequestID)
	default:
		t.Fatal("confirmed event missing from SSE")
	}
	snapshot = s.Snapshot(context.Background())
	assert.Equal(t, before.AcceptedItems+1, snapshot.Requests)
	assert.Equal(t, uint64(1), snapshot.CacheHits)
	daily, err := s.DailyMetrics(context.Background(), 0)
	require.NoError(t, err)
	var requests uint64
	for _, day := range daily {
		requests += day.Requests
	}
	assert.Equal(t, snapshot.Requests, requests)
}

type cancelAfterAdmission struct {
	inner  gate.Recorder
	cancel context.CancelFunc
}

func (r cancelAfterAdmission) Record(ev gate.Event) { r.inner.Record(ev); r.cancel() }
func TestAsyncTelemetry_CancelledClientKeepsAdmittedEvent(t *testing.T) {
	s, entered, release := heldAsyncStore(t)
	s.Record(gate.Event{RequestID: "hold"})
	s.RequestFlush()
	asyncAwait(t, entered)
	registry := newTestRegistry(t, "cancelled", "1.0.0", 1)
	defer registry.Close()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir()})
	require.NoError(t, err)
	defer lc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := proxy.NewHandler(proxy.HandlerConfig{Adapter: adapters.NewPyPIAdapter([]string{registry.URL}), Filter: supplychain.NewFilter(config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24}, nil), Cache: cache.AsArtifactCache(lc), Recorder: cancelAfterAdmission{inner: s, cancel: cancel}, Logger: zerolog.Nop()})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/packages/py3/c/cancelled/cancelled-1.0.0-py3-none-any.whl", nil).WithContext(ctx))
	require.Equal(t, 423, w.Code)
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	release()
	require.NoError(t, s.Flush(context.Background()))
	events := s.Recent(context.Background(), 0)
	require.Len(t, events, 2)
	found := false
	for _, ev := range events {
		if ev.Package == "cancelled" {
			found = true
			assert.Equal(t, gate.VerdictBlock, ev.Verdict)
		}
	}
	assert.True(t, found)
}

// This helper is invoked only by the parent test in the Docker test binary.
func TestAsyncTelemetry_CrashChild(t *testing.T) {
	root := os.Getenv("JOEI_ASYNC_CRASH_TEST_ROOT")
	if root == "" {
		t.Skip("child only")
	}
	db, err := storage.Open(filepath.Join(root, "state.db"))
	require.NoError(t, err)
	repo, err := telemetry.NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)
	require.NoError(t, repo.RecordEvent(gate.Event{RequestID: "committed", Time: time.Now(), Verdict: gate.VerdictCache}))
	held := &asyncHeldRepo{Repo: repo, entered: make(chan struct{}), release: make(chan struct{})}
	store := telemetry.New(held, zerolog.Nop())
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: filepath.Join(root, "cache")})
	require.NoError(t, err)
	p := filepath.Join(root, "checked")
	require.NoError(t, os.WriteFile(p, []byte("checked"), 0600))
	ref := &gate.PackageRef{Ecosystem: "pypi", Name: "checked", Version: "1.0.0"}
	require.NoError(t, lc.Put(ref, p, true, "clean"))
	_, ok := lc.Get(ref)
	require.True(t, ok)
	require.NoError(t, lc.FlushUsage(context.Background()))
	lock, err := sql.Open("sqlite", filepath.Join(root, "cache/index.db"))
	require.NoError(t, err)
	_, err = lock.Exec(`BEGIN IMMEDIATE`)
	require.NoError(t, err)
	_, ok = lc.Get(ref)
	require.True(t, ok)
	lc.RequestUsageFlush()
	store.Record(gate.Event{RequestID: "lost-tail", Time: time.Now(), Verdict: gate.VerdictPass})
	store.RequestFlush()
	asyncAwait(t, held.entered)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "cache/tmp"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cache/tmp/jo-ei-unchecked"), []byte("unchecked bytes"), 0600))
	require.Equal(t, int64(1), lc.UsageWriterStats().UnsavedItems)
	fmt.Println("READY: uncommitted telemetry and usage; unchecked temporary file")
	select {}
}

func TestAsyncTelemetry_CrashTailDoesNotAuthorizeArtifact(t *testing.T) {
	root := t.TempDir()
	child := exec.Command(os.Args[0], "-test.run=^TestAsyncTelemetry_CrashChild$", "-test.v") // #nosec G204 -- current test binary, fixed test name
	child.Env = append(os.Environ(), "JOEI_ASYNC_CRASH_TEST_ROOT="+root)
	stdout, err := child.StdoutPipe()
	require.NoError(t, err)
	var stderr strings.Builder
	child.Stderr = &stderr
	require.NoError(t, child.Start())
	t.Cleanup(func() { _ = child.Process.Kill() })
	ready := make(chan struct{})
	readErr := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "READY:") {
				close(ready)
				return
			}
		}
		readErr <- fmt.Errorf("child readiness failed: %v", scanner.Err())
	}()
	select {
	case <-ready:
	case err := <-readErr:
		_ = child.Wait()
		t.Fatalf("%v: %s", err, stderr.String())
	case <-time.After(10 * time.Second):
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatalf("child did not reach crash handshake: %s", stderr.String())
	}
	require.NoError(t, child.Process.Kill())
	require.Error(t, child.Wait())
	db, err := storage.Open(filepath.Join(root, "state.db"))
	require.NoError(t, err)
	defer db.Close()
	s, err := telemetry.Open(db, 30, 365, zerolog.Nop())
	require.NoError(t, err)
	defer s.Close()
	assert.Equal(t, uint64(1), s.Snapshot(context.Background()).Requests)
	events := s.Recent(context.Background(), 0)
	require.Len(t, events, 1)
	assert.Equal(t, "committed", events[0].RequestID)
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: filepath.Join(root, "cache")})
	require.NoError(t, err)
	defer lc.Close()
	checked, ok := lc.Get(&gate.PackageRef{Ecosystem: "pypi", Name: "checked", Version: "1.0.0"})
	require.True(t, ok)
	assert.Equal(t, int64(1), checked.HitCount)
	ref := &gate.PackageRef{Ecosystem: "pypi", Name: "unchecked", Version: "1.0.0", Classifier: "unchecked-1.0.0-py3-none-any.whl"}
	_, ok = lc.Get(ref)
	assert.False(t, ok)
	require.FileExists(t, filepath.Join(root, "cache/tmp/jo-ei-unchecked"))
	registry := newTestRegistry(t, "unchecked", "1.0.0", 48)
	defer registry.Close()
	var scans atomic.Int64
	h := proxy.NewHandler(proxy.HandlerConfig{Adapter: adapters.NewPyPIAdapter([]string{registry.URL}), Filter: supplychain.NewFilter(config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24}, nil), Cache: cache.AsArtifactCache(lc), AVScanner: asyncAV{infected: true, calls: &scans}, Recorder: s, Logger: zerolog.Nop()})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/packages/py3/u/unchecked/unchecked-1.0.0-py3-none-any.whl", nil))
	assert.Equal(t, 403, w.Code)
	assert.Equal(t, int64(1), scans.Load())
	_, ok = lc.Get(ref)
	assert.False(t, ok)
}
