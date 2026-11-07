package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShutdown_HealthyDrainsBothWriters(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, err)
	defer db.Close()
	store, err := telemetry.Open(db, 30, 365, zerolog.Nop())
	require.NoError(t, err)
	defer store.Close()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir()})
	require.NoError(t, err)
	defer lc.Close()
	ref := &gate.PackageRef{Ecosystem: "npm", Name: "p", Version: "1"}
	p := filepath.Join(t.TempDir(), "artifact")
	require.NoError(t, os.WriteFile(p, []byte("checked"), 0600))
	require.NoError(t, lc.Put(ref, p, true, "clean"))
	_, ok := lc.Get(ref)
	require.True(t, ok)
	store.Record(gate.Event{Verdict: gate.VerdictCache})
	st := state{store: store, cache: lc}
	group := newShutdownGroup(5*time.Second, st.requestWriterFlush)
	defer group.Close()
	ctx := group.Begin()
	require.NoError(t, st.shutdownWriters(ctx, zerolog.Nop()))
	assert.Equal(t, uint64(1), store.Snapshot(context.Background()).Requests)
	entry, ok := lc.Get(ref)
	require.True(t, ok)
	assert.Equal(t, int64(1), entry.HitCount)
	assert.True(t, entry.ScanClean)
	store.Record(gate.Event{})
	assert.Equal(t, uint64(1), store.WriterStats().DroppedClosedItems)
	assert.Equal(t, uint64(1), lc.UsageWriterStats().DroppedClosedItems)
	require.NoError(t, st.shutdownWriters(ctx, zerolog.Nop()))
}

type deadlineUsage struct {
	cache.Cache
	received chan context.Context
}

func (d *deadlineUsage) RequestUsageFlush()               {}
func (d *deadlineUsage) FlushUsage(context.Context) error { return nil }
func (d *deadlineUsage) UsageWriterStats() storage.WriterStats {
	return storage.WriterStats{AbandonedItems: 2}
}
func (d *deadlineUsage) Shutdown(ctx context.Context) error {
	d.received <- ctx
	<-ctx.Done()
	return ctx.Err()
}

type heldTelemetryRepo struct {
	telemetry.Repo
	entered chan struct{}
}

func (r heldTelemetryRepo) RecordBatch(ctx context.Context, _ string, _ []telemetry.BatchEvent) error {
	r.entered <- struct{}{}
	<-ctx.Done()
	return ctx.Err()
}

func TestShutdown_OneDeadlineForHTTPAndWriters(t *testing.T) {
	enableLogs(t)
	entered := make(chan struct{}, 1)
	store := telemetry.New(heldTelemetryRepo{entered: entered}, zerolog.Nop())
	store.Record(gate.Event{})
	store.RequestFlush()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer not active")
	}
	usage := &deadlineUsage{received: make(chan context.Context, 1)}
	st := state{store: store, cache: usage}
	group := newShutdownGroup(100*time.Millisecond, st.requestWriterFlush)
	defer group.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	block := make(chan struct{})
	defer close(block)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.(http.Flusher).Flush(); <-block })}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- serveListener(ctx, srv, ln, time.Second, zerolog.Nop(), group) }()
	resp, err := http.Get("http://" + ln.Addr().String())
	require.NoError(t, err)
	defer resp.Body.Close()
	drainCtx := group.Begin()
	httpCtx, stopHTTP := group.httpContext(time.Second)
	defer stopHTTP()
	primaryDeadline, ok := httpCtx.Deadline()
	require.True(t, ok)
	telemetryDeadline, ok := drainCtx.Deadline()
	require.True(t, ok)
	assert.Equal(t, primaryDeadline, telemetryDeadline)
	cancel()
	select {
	case err := <-served:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP shutdown exceeded shared budget")
	}
	var logs bytes.Buffer
	err = st.shutdownWriters(drainCtx, zerolog.New(zerolog.SyncWriter(&logs)))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	usageCtx := <-usage.received
	usageDeadline, ok := usageCtx.Deadline()
	require.True(t, ok)
	assert.Equal(t, primaryDeadline, usageDeadline)
	assert.Contains(t, logs.String(), "abandoned_items")
	assert.Equal(t, uint64(1), store.WriterStats().AbandonedItems)
}

func TestShutdown_BeginHasOneDeadlineAndFlush(t *testing.T) {
	var calls atomic.Int32
	g := newShutdownGroup(time.Second, func() { calls.Add(1) })
	defer g.Close()
	first := g.Begin()
	for range 10 {
		assert.Same(t, first, g.Begin())
	}
	assert.Equal(t, int32(1), calls.Load())
	short, cancel := g.httpContext(time.Millisecond)
	defer cancel()
	shortDeadline, _ := short.Deadline()
	sharedDeadline, _ := first.Deadline()
	assert.True(t, shortDeadline.Before(sharedDeadline))
}

func TestShutdown_StartupFailureJoinsWriters(t *testing.T) {
	cfgPath := writeTestConfig(t, freeAddr(t), "tls:\n  ca_files: [missing-startup-ca.pem]\nmetrics:\n  enabled: false\n")
	err := run(context.Background(), cfgPath)
	require.ErrorContains(t, err, "missing-startup-ca.pem")
	require.Eventually(t, func() bool {
		var stacks bytes.Buffer
		if err := pprof.Lookup("goroutine").WriteTo(&stacks, 1); err != nil {
			return false
		}
		text := stacks.String()
		return !strings.Contains(text, "telemetry.(*telemetryWriter).run") && !strings.Contains(text, "cache.(*usageWriter).run")
	}, time.Second, time.Millisecond)
}
