package cache

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func usageOptions() usageWriterOptions {
	return usageWriterOptions{PendingCapacity: 4, BatchSize: 256, FlushInterval: time.Hour, RetryInterval: time.Millisecond}
}
func usageSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("usage writer missed handshake")
	}
}
func flushUsage(t *testing.T, w *usageWriter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, w.flush(ctx))
}
func usageIndex(t *testing.T) (*Index, *gate.PackageRef, int64) {
	t.Helper()
	idx, err := NewIndex(filepath.Join(t.TempDir(), "index.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = idx.Close() })
	ref := &gate.PackageRef{Ecosystem: "npm", Name: "p", Version: "1"}
	require.NoError(t, idx.Insert(ref, &CacheEntry{ArtifactPath: "artifact", StoredAt: time.Now(), ScanClean: true}))
	_, id, ok := idx.GetWithID(ref)
	require.True(t, ok)
	return idx, ref, id
}

func TestUsageWriter_CoalescesHits(t *testing.T) {
	idx, ref, id := usageIndex(t)
	var applied []UsageDelta
	w := newUsageWriter(func(ctx context.Context, token string, d []UsageDelta) error {
		applied = append(applied, d...)
		return idx.ApplyUsageBatch(ctx, token, d)
	}, usageOptions())
	defer w.shutdown(context.Background())
	now := time.Now()
	for i := range 100 {
		w.record(id, now.Add(time.Duration(99-i)*time.Second))
	}
	flushUsage(t, w)
	require.Len(t, applied, 1)
	assert.Equal(t, int64(100), applied[0].Hits)
	assert.Equal(t, now.Unix()+99, applied[0].LastHit)
	got, ok := idx.Get(ref)
	require.True(t, ok)
	assert.Equal(t, int64(100), got.HitCount)
	assert.Equal(t, uint64(100), w.stats().CommittedItems)
}

func TestUsageWriter_FullMapDropsNewKeyWithoutWaiting(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir()})
	require.NoError(t, err)
	defer lc.Close()
	refs := make([]*gate.PackageRef, 4)
	for i := range refs {
		refs[i] = &gate.PackageRef{Ecosystem: "npm", Name: fmt.Sprint(i), Version: "1"}
		require.NoError(t, lc.Put(refs[i], writeTemp(t, "data"), true, "scan"))
	}
	require.NoError(t, lc.usage.shutdown(context.Background()))
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	opts := usageOptions()
	opts.PendingCapacity = 2
	opts.BatchSize = 1
	lc.usage = newUsageWriter(func(ctx context.Context, token string, d []UsageDelta) error {
		once.Do(func() { entered <- struct{}{} })
		select {
		case <-release:
			return lc.index.ApplyUsageBatch(ctx, token, d)
		case <-ctx.Done():
			return ctx.Err()
		}
	}, opts)
	defer close(release)
	_, ok := lc.Get(refs[0])
	require.True(t, ok)
	usageSignal(t, entered)
	for _, ref := range refs[1:3] {
		_, ok = lc.Get(ref)
		require.True(t, ok)
	}
	original, ok := lc.index.Get(refs[3])
	require.True(t, ok)
	done := make(chan struct{})
	go func() {
		defer close(done)
		got, found := lc.Get(refs[3])
		assert.True(t, found)
		assert.Equal(t, original, got)
		_, found = lc.Get(refs[1])
		assert.True(t, found)
	}()
	usageSignal(t, done)
	stats := lc.UsageWriterStats()
	assert.Equal(t, int64(2), stats.Queued)
	assert.Equal(t, int64(1), stats.InFlight)
	assert.Equal(t, uint64(1), stats.DroppedFullItems)
	release <- struct{}{}
	release <- struct{}{}
	release <- struct{}{}
	require.NoError(t, lc.FlushUsage(context.Background()))
	for i, ref := range refs {
		entry, ok := lc.index.Get(ref)
		require.True(t, ok)
		assert.Equal(t, []int64{1, 2, 1, 0}[i], entry.HitCount)
	}
	require.NoError(t, lc.Shutdown(context.Background()))
	_, ok = lc.Get(refs[3])
	require.True(t, ok)
	assert.Equal(t, uint64(1), lc.UsageWriterStats().DroppedClosedItems)
}

func TestUsageWriter_AmbiguousCommitAndInflightHit(t *testing.T) {
	idx, ref, id := usageIndex(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var tokens []string
	var batches [][]UsageDelta
	opts := usageOptions()
	opts.BatchSize = 1
	w := newUsageWriter(func(ctx context.Context, token string, d []UsageDelta) error {
		tokens = append(tokens, token)
		batches = append(batches, append([]UsageDelta(nil), d...))
		if len(tokens) == 1 {
			entered <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		err := idx.ApplyUsageBatch(ctx, token, d)
		if len(tokens) == 1 && err == nil {
			return errors.New("lost acknowledgement")
		}
		return err
	}, opts)
	defer w.shutdown(context.Background())
	defer close(release)
	w.record(id, time.Now())
	usageSignal(t, entered)
	w.record(id, time.Now().Add(time.Second))
	release <- struct{}{}
	flushUsage(t, w)
	require.Len(t, tokens, 3)
	assert.Equal(t, tokens[0], tokens[1])
	assert.NotEqual(t, tokens[1], tokens[2])
	assert.Equal(t, batches[0], batches[1])
	assert.Equal(t, int64(1), batches[0][0].Hits)
	assert.Equal(t, int64(1), batches[2][0].Hits)
	got, ok := idx.Get(ref)
	require.True(t, ok)
	assert.Equal(t, int64(2), got.HitCount)
	assert.Equal(t, uint64(1), w.stats().Retries)
}

type usageWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *usageWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestUsageWriter_FlushWatermarkSurvivesCoalescing(t *testing.T) {
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	opts := usageOptions()
	opts.BatchSize = 1
	w := newUsageWriter(func(ctx context.Context, _ string, _ []UsageDelta) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, opts)
	defer w.shutdown(context.Background())
	defer close(release)
	w.record(1, time.Now())
	usageSignal(t, entered)
	w.record(2, time.Now())
	w.record(3, time.Now())
	ctx := &usageWaitContext{Context: context.Background(), entered: make(chan struct{})}
	flushed := make(chan struct{})
	go func() { _ = w.flush(ctx); close(flushed) }()
	usageSignal(t, ctx.entered)
	for range 98 {
		w.record(2, time.Now())
	}
	w.record(4, time.Now())
	release <- struct{}{}
	usageSignal(t, entered)
	release <- struct{}{}
	usageSignal(t, entered)
	select {
	case <-flushed:
		t.Fatal("coalesced later hits hid an earlier uncommitted row")
	default:
	}
	release <- struct{}{}
	usageSignal(t, entered)
	usageSignal(t, flushed)
	assert.Equal(t, int64(1), w.stats().UnsavedItems)
}

func TestLocalCache_PurgeFlushesPendingHits(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), StaleAfter: time.Hour})
	require.NoError(t, err)
	defer lc.Close()
	ref := &gate.PackageRef{Ecosystem: "npm", Name: "hot", Version: "1"}
	require.NoError(t, lc.Put(ref, writeTemp(t, "hot"), true, ""))
	_, err = lc.index.db.Exec(`UPDATE artifacts SET last_hit=?`, time.Now().Add(-2*time.Hour).Unix())
	require.NoError(t, err)
	entry, ok := lc.Get(ref)
	require.True(t, ok)
	assert.True(t, entry.ScanClean)
	removed, _, err := lc.PurgeStale(context.Background())
	require.NoError(t, err)
	assert.Zero(t, removed)
	require.FileExists(t, entry.ArtifactPath)
	got, ok := lc.index.Get(ref)
	require.True(t, ok)
	assert.Equal(t, int64(1), got.HitCount)
}

func TestLocalCache_CleanupAbortsOnFlushFailure(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), StaleAfter: time.Hour})
	require.NoError(t, err)
	defer lc.Close()
	ref := &gate.PackageRef{Ecosystem: "npm", Name: "hot", Version: "1"}
	require.NoError(t, lc.Put(ref, writeTemp(t, "hot"), true, ""))
	_, err = lc.index.db.Exec(`UPDATE artifacts SET last_hit=?`, time.Now().Add(-2*time.Hour).Unix())
	require.NoError(t, err)
	_, err = lc.index.db.Exec(`CREATE TRIGGER fail_usage BEFORE UPDATE OF hit_count ON artifacts BEGIN SELECT RAISE(ABORT,'test full'); END`)
	require.NoError(t, err)
	e, ok := lc.Get(ref)
	require.True(t, ok)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	removed, _, err := lc.PurgeStale(ctx)
	require.Error(t, err)
	assert.Zero(t, removed)
	require.FileExists(t, e.ArtifactPath)
	assert.Equal(t, int64(1), lc.UsageWriterStats().UnsavedItems)
	_, err = lc.index.db.Exec(`DROP TRIGGER fail_usage`)
	require.NoError(t, err)
	require.NoError(t, lc.FlushUsage(context.Background()))
	removed, _, err = lc.PurgeStale(context.Background())
	require.NoError(t, err)
	assert.Zero(t, removed)
}

func TestLocalCache_LRUFlushesPendingHits(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir()})
	require.NoError(t, err)
	defer lc.Close()
	var hot *gate.PackageRef
	for i := range 11 {
		ref := &gate.PackageRef{Ecosystem: "npm", Name: fmt.Sprint(i), Version: "1"}
		require.NoError(t, lc.Put(ref, writeTemp(t, "x"), true, ""))
		_, err = lc.index.db.Exec(`UPDATE artifacts SET last_hit=? WHERE name=?`, time.Now().Add(time.Duration(i-20)*time.Hour).Unix(), ref.Name)
		require.NoError(t, err)
		if i == 0 {
			hot = ref
		}
	}
	_, ok := lc.Get(hot)
	require.True(t, ok)
	lc.evictToSize(context.Background(), 10)
	_, ok = lc.index.Get(hot)
	assert.True(t, ok, "the pending hit must refresh LRU before selecting rows")
}

func TestUsageWriter_TimerAndPrecommitRetry(t *testing.T) {
	idx, ref, id := usageIndex(t)
	opts := usageOptions()
	opts.FlushInterval = time.Millisecond
	committed := make(chan struct{}, 1)
	attempt := 0
	w := newUsageWriter(func(ctx context.Context, token string, d []UsageDelta) error {
		attempt++
		if attempt == 1 {
			return errors.New("before commit")
		}
		err := idx.ApplyUsageBatch(ctx, token, d)
		if err == nil {
			committed <- struct{}{}
		}
		return err
	}, opts)
	defer w.shutdown(context.Background())
	w.record(id, time.Now())
	usageSignal(t, committed)
	flushUsage(t, w)
	got, ok := idx.Get(ref)
	require.True(t, ok)
	assert.Equal(t, int64(1), got.HitCount)
	assert.Equal(t, uint64(1), w.stats().Failures)
	assert.Equal(t, uint64(1), w.stats().Retries)
}

func TestUsageWriter_ShutdownCancelsAndCountsUnconfirmed(t *testing.T) {
	entered := make(chan struct{}, 1)
	opts := usageOptions()
	opts.BatchSize = 1
	w := newUsageWriter(func(ctx context.Context, _ string, _ []UsageDelta) error {
		entered <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}, opts)
	w.record(1, time.Now())
	usageSignal(t, entered)
	w.record(2, time.Now())
	w.record(2, time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.Error(t, w.shutdown(ctx))
	s := w.stats()
	assert.Equal(t, uint64(3), s.AbandonedItems)
	assert.Zero(t, s.UnsavedItems)
	w.record(1, time.Now())
	assert.Equal(t, uint64(1), w.stats().DroppedClosedItems)
}

func TestLocalCache_StatsUsesOneReadDeadline(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir()})
	require.NoError(t, err)
	defer lc.Close()
	conn, err := lc.index.db.Conn(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	_, err = lc.Stats()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Zero(t, lc.UsageWriterStats().AttemptedItems)
}
