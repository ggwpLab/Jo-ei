package dockerproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

type dockerHeldRepo struct {
	telemetry.Repo
	entered, release chan struct{}
	once             sync.Once
}

func (r *dockerHeldRepo) RecordBatch(ctx context.Context, token string, events []telemetry.BatchEvent) error {
	r.once.Do(func() { close(r.entered) })
	select {
	case <-r.release:
		return r.Repo.RecordBatch(ctx, token, events)
	case <-ctx.Done():
		return ctx.Err()
	}
}

type pausedImageScanner struct {
	stubScanner
	entered, release chan struct{}
}

func (s pausedImageScanner) ScanImage(ctx context.Context, image string) (*ImageScanResult, error) {
	close(s.entered)
	select {
	case <-s.release:
		return s.stubScanner.ScanImage(ctx, image)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestAsyncTelemetry_DockerVerdictsRemainSynchronous(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "telemetry.db"))
	require.NoError(t, err)
	defer db.Close()
	real, err := telemetry.NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)
	r := &dockerHeldRepo{Repo: real, entered: make(chan struct{}), release: make(chan struct{})}
	store := telemetry.New(r, zerolog.Nop())
	defer store.Close()
	defer close(r.release)
	store.Record(gate.Event{})
	store.RequestFlush()
	select {
	case <-r.entered:
	case <-time.After(time.Second):
		t.Fatal("telemetry not held")
	}
	for i := int64(0); i < store.WriterStats().Capacity; i++ {
		store.Record(gate.Event{})
	}
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir()})
	require.NoError(t, err)
	defer lc.Close()
	verdicts := newVerdictStore(lc)
	upstream, repo, tag := newGateTestServer(t)
	scanner := pausedImageScanner{stubScanner: stubScanner{findings: []gate.CVEFinding{{ID: "CVE-block", Severity: gate.SeverityHigh}}}, entered: make(chan struct{}), release: make(chan struct{})}
	defer close(scanner.release)
	mg := newManifestGate(gateDeps{adapter: NewAdapter([]string{upstream}, nil), scanner: scanner, av: stubAV{}, filter: allowFilter{}, policy: findingPolicy{}, store: verdicts, logger: zerolog.Nop()})
	h := NewHandler(Config{Adapter: mg.adapter, Gate: mg, Store: verdicts, Recorder: store, ClientWait: 10 * time.Millisecond, Logger: zerolog.Nop()})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+tag, nil))
	require.Equal(t, 503, w.Code)
	assert.NotContains(t, w.Body.String(), "schemaVersion")
	allowed, _, _, found := verdicts.GetImageVerdict(repo, "sha256:img")
	assert.False(t, found)
	assert.False(t, allowed)
	scanner.release <- struct{}{}
	require.Eventually(t, func() bool { clean, _, _, ok := verdicts.GetImageVerdict(repo, "sha256:img"); return ok && !clean }, 5*time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return store.WriterStats().DroppedFullItems >= 2 }, time.Second, time.Millisecond)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+tag, nil))
	assert.Equal(t, 403, w.Code)
	assert.NotContains(t, w.Body.String(), "schemaVersion")
	allowed, reason, _, found := verdicts.GetImageVerdict(repo, "sha256:img")
	require.True(t, found)
	assert.False(t, allowed)
	assert.Equal(t, "cve_found", reason)
	assert.Empty(t, store.Recent(context.Background(), 0))
}
