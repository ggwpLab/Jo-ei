package cache_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
)

func TestIndex_UsageBatchReplayAndRowIdentity(t *testing.T) {
	idx, closeIndex := newTestIndex(t)
	defer closeIndex()
	ctx := context.Background()
	ref := &gate.PackageRef{Ecosystem: "maven", Name: "g:a", Version: "1", Classifier: "sources"}
	e := &cache.CacheEntry{ArtifactPath: "artifact", ScanClean: true, StoredAt: time.Now()}
	require.NoError(t, idx.Insert(ref, e))
	_, id, ok := idx.GetWithID(ref)
	require.True(t, ok)
	require.NoError(t, idx.ApplyUsageBatch(ctx, "one", []cache.UsageDelta{{RowID: id, Hits: 3, LastHit: time.Now().Unix()}}))
	for range 2 {
		require.NoError(t, idx.ApplyUsageBatch(ctx, "two", []cache.UsageDelta{{RowID: id, Hits: 2, LastHit: time.Now().Unix()}}))
	}
	got, ok := idx.Get(ref)
	require.True(t, ok)
	assert.Equal(t, int64(5), got.HitCount)
	_, err := idx.Delete(ref)
	require.NoError(t, err)
	require.NoError(t, idx.Insert(ref, e))
	_, newID, ok := idx.GetWithID(ref)
	require.True(t, ok)
	require.NotEqual(t, id, newID)
	require.NoError(t, idx.ApplyUsageBatch(ctx, "retired", []cache.UsageDelta{{RowID: id, Hits: 9, LastHit: time.Now().Unix()}}))
	got, ok = idx.Get(ref)
	require.True(t, ok)
	assert.Zero(t, got.HitCount)
}

func TestIndex_UsageBatchUpsertKeepsIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.db")
	idx, err := cache.NewIndex(path)
	require.NoError(t, err)
	defer idx.Close()
	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer raw.Close()
	ctx := context.Background()
	ref := &gate.PackageRef{Ecosystem: "maven", Name: "g:a", Version: "1"}
	other := *ref
	other.Classifier = "sources"
	e := &cache.CacheEntry{ArtifactPath: "a", ScanClean: true, StoredAt: time.Now().Truncate(time.Second)}
	require.NoError(t, idx.Insert(ref, e))
	require.NoError(t, idx.Insert(&other, e))
	_, id, ok := idx.GetWithID(ref)
	require.True(t, ok)
	_, otherID, ok := idx.GetWithID(&other)
	require.True(t, ok)
	require.NoError(t, idx.ApplyUsageBatch(ctx, "first", []cache.UsageDelta{{RowID: id, Hits: 3, LastHit: e.StoredAt.Unix() + 100}}))
	require.NoError(t, idx.Insert(ref, e))
	got, sameID, ok := idx.GetWithID(ref)
	require.True(t, ok)
	assert.Equal(t, id, sameID)
	assert.Equal(t, int64(3), got.HitCount)
	// The transaction must roll back both rows and the receipt on an error.
	_, err = raw.Exec(`CREATE TRIGGER reject_usage BEFORE UPDATE OF hit_count ON artifacts WHEN NEW.classifier='sources' BEGIN SELECT RAISE(ABORT,'injected'); END`)
	require.NoError(t, err)
	deltas := []cache.UsageDelta{{RowID: id, Hits: 2, LastHit: e.StoredAt.Unix() - 10}, {RowID: otherID, Hits: 4, LastHit: e.StoredAt.Unix()}}
	require.Error(t, idx.ApplyUsageBatch(ctx, "retry", deltas))
	got, ok = idx.Get(ref)
	require.True(t, ok)
	assert.Equal(t, int64(3), got.HitCount)
	_, err = raw.Exec(`DROP TRIGGER reject_usage`)
	require.NoError(t, err)
	require.NoError(t, idx.ApplyUsageBatch(ctx, "retry", deltas))
	got, ok = idx.Get(ref)
	require.True(t, ok)
	assert.Equal(t, int64(5), got.HitCount)
	got, ok = idx.Get(&other)
	require.True(t, ok)
	assert.Equal(t, int64(4), got.HitCount)
	var last int64
	require.NoError(t, raw.QueryRow(`SELECT last_hit FROM artifacts WHERE id=?`, id).Scan(&last))
	assert.GreaterOrEqual(t, last, e.StoredAt.Unix())
}
