package telemetry_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func TestSQLiteRepo_RecordBatchAtomicCountersAndDays(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	events := []telemetry.BatchEvent{
		{Event: gate.Event{RequestID: "cache", Time: time.Date(2026, 11, 6, 23, 59, 59, 0, time.UTC), Verdict: gate.VerdictCache, Gate: gate.GateCache}, Day: "2026-11-06"},
		{Event: gate.Event{RequestID: "block", Time: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), Verdict: gate.VerdictBlock, Gate: gate.GateSupply}, Day: "2026-11-07"},
	}
	for range 2 {
		require.NoError(t, r.RecordBatch(ctx, "batch-1", events))
		got, err := r.Recent(ctx, 0)
		require.NoError(t, err)
		require.Len(t, got, 2)
		s, err := r.Snapshot(ctx, time.Time{})
		require.NoError(t, err)
		assert.Equal(t, uint64(2), s.Requests)
		assert.Equal(t, uint64(1), s.CacheHits)
		assert.Equal(t, uint64(1), s.Blocked)
		days, err := r.DailyMetrics(ctx, 0)
		require.NoError(t, err)
		require.Len(t, days, 2)
		for _, d := range days {
			assert.Equal(t, uint64(1), d.Requests)
		}
	}
}

func TestSQLiteRepo_BatchReceiptSurvivesPrune(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	old := time.Now().AddDate(-2, 0, 0)
	ev := []telemetry.BatchEvent{{Event: gate.Event{Time: old, Verdict: gate.VerdictCache}, Day: old.UTC().Format(time.DateOnly)}}
	require.NoError(t, r.RecordBatch(ctx, "old", ev))
	require.NoError(t, r.Prune(ctx))
	require.NoError(t, r.RecordBatch(ctx, "old", ev))
	got, err := r.Recent(ctx, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
	snap, err := r.Snapshot(ctx, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), snap.Requests)
}

func TestSQLiteRepo_BatchRollback(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(filepath.Join(t.TempDir(), "batch.db"))
	require.NoError(t, err)
	defer db.Close()
	r, err := telemetry.NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)
	_, err = db.SQL().Exec(`CREATE TRIGGER fail_second BEFORE INSERT ON events WHEN NEW.request_id='second' BEGIN SELECT RAISE(ABORT, 'injected'); END`)
	require.NoError(t, err)
	events := []telemetry.BatchEvent{{Event: gate.Event{RequestID: "first", Verdict: gate.VerdictCache}, Day: "2026-11-07"}, {Event: gate.Event{RequestID: "second", Verdict: gate.VerdictBlock}, Day: "2026-11-07"}}
	require.Error(t, r.RecordBatch(ctx, "retry", events))
	got, err := r.Recent(ctx, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
	snap, err := r.Snapshot(ctx, time.Time{})
	require.NoError(t, err)
	assert.Zero(t, snap.Requests)
	var n int
	require.NoError(t, db.SQL().QueryRow(`SELECT COUNT(*) FROM async_write_state`).Scan(&n))
	assert.Zero(t, n)
	_, err = db.SQL().Exec(`DROP TRIGGER fail_second`)
	require.NoError(t, err)
	require.NoError(t, r.RecordBatch(ctx, "retry", events))
	got, err = r.Recent(ctx, 0)
	require.NoError(t, err)
	assert.Len(t, got, 2)
}
