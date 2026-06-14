package telemetry_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func newRepo(t *testing.T) telemetry.Repo {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo, err := telemetry.NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)
	return repo
}

func TestSQLiteRepo_AppendAndLoadEvents(t *testing.T) {
	repo := newRepo(t)
	ev := proxy.Event{
		RequestID: "r1", Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Ecosystem: "npm", Package: "left-pad", Version: "1.0.0",
		Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply, Reason: "package_younger_than_min_age",
		HTTPStatus: 423, BlockedBy: []string{"supply_chain"},
		PublishedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		BlockUntil:  time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC),
	}
	require.NoError(t, repo.AppendEvents([]proxy.Event{ev}))

	st, err := repo.LoadState(100)
	require.NoError(t, err)
	require.Len(t, st.Events, 1)
	got := st.Events[0]
	assert.Equal(t, "r1", got.RequestID)
	assert.Equal(t, "left-pad", got.Package)
	assert.Equal(t, proxy.VerdictBlock, got.Verdict)
	assert.Equal(t, []string{"supply_chain"}, got.BlockedBy)
	assert.True(t, got.Time.Equal(ev.Time))
	assert.True(t, got.BlockUntil.Equal(ev.BlockUntil))
}

func TestSQLiteRepo_FlushAndLoadCountersAndDaily(t *testing.T) {
	repo := newRepo(t)
	lifetime := telemetry.Snapshot{
		Requests: 10, CacheHits: 4, Blocked: 3, Errors: 1,
		SupplyBlocked: 2, CVEBlocked: 1,
		Gates: map[string]telemetry.GateCounts{
			proxy.GateSupply: {Pass: 7, Block: 2},
			proxy.GateCVE:    {Pass: 5, Block: 1},
		},
	}
	today := time.Now().UTC().Format("2006-01-02")
	daily := []telemetry.DailyMetric{{
		Day: today, Requests: 10, CacheHits: 4, Blocked: 3,
		Gates: map[string]telemetry.GateCounts{proxy.GateSupply: {Pass: 7, Block: 2}},
	}}
	require.NoError(t, repo.Flush(lifetime, daily))

	st, err := repo.LoadState(100)
	require.NoError(t, err)
	require.True(t, st.HasLifetime)
	assert.Equal(t, uint64(10), st.Lifetime.Requests)
	assert.Equal(t, uint64(2), st.Lifetime.SupplyBlocked)
	assert.Equal(t, telemetry.GateCounts{Pass: 7, Block: 2}, st.Lifetime.Gates[proxy.GateSupply])
	require.NotNil(t, st.Today)
	assert.Equal(t, today, st.Today.Day)
	assert.Equal(t, uint64(10), st.Today.Requests)

	lifetime.Requests = 20
	daily[0].Requests = 20
	require.NoError(t, repo.Flush(lifetime, daily))
	rows, err := repo.DailyMetrics(0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, uint64(20), rows[0].Requests)

	st, err = repo.LoadState(100)
	require.NoError(t, err)
	assert.Equal(t, uint64(20), st.Lifetime.Requests)
}

func TestSQLiteRepo_LoadEmptyIsZeroValue(t *testing.T) {
	repo := newRepo(t)
	st, err := repo.LoadState(100)
	require.NoError(t, err)
	assert.False(t, st.HasLifetime)
	assert.Nil(t, st.Today)
	assert.Empty(t, st.Events)
}

func TestSQLiteRepo_DailyMetricsLimit(t *testing.T) {
	repo := newRepo(t)
	d := []telemetry.DailyMetric{
		{Day: "2026-01-01", Requests: 1},
		{Day: "2026-01-02", Requests: 2},
		{Day: "2026-01-03", Requests: 3},
	}
	require.NoError(t, repo.Flush(telemetry.Snapshot{}, d))
	rows, err := repo.DailyMetrics(2)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "2026-01-03", rows[0].Day)
	assert.Equal(t, "2026-01-02", rows[1].Day)
}

func TestSQLiteRepo_PruneRemovesOldEvents(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo, err := telemetry.NewSQLiteRepo(db, 1, 1) // 1-day retention
	require.NoError(t, err)

	old := proxy.Event{RequestID: "old", Time: time.Now().Add(-72 * time.Hour), Verdict: proxy.VerdictPass, Gate: proxy.GateMalware}
	fresh := proxy.Event{RequestID: "fresh", Time: time.Now(), Verdict: proxy.VerdictPass, Gate: proxy.GateMalware}
	require.NoError(t, repo.AppendEvents([]proxy.Event{old, fresh}))
	require.NoError(t, repo.Prune())

	st, err := repo.LoadState(100)
	require.NoError(t, err)
	require.Len(t, st.Events, 1)
	assert.Equal(t, "fresh", st.Events[0].RequestID)
}
