package cache_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestIndex(t *testing.T) (*cache.Index, func()) {
	t.Helper()
	dir := t.TempDir()
	idx, err := cache.NewIndex(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	return idx, func() { idx.Close() }
}

func TestIndex_InsertAndGet(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}
	entry := cache.CacheEntry{
		ArtifactPath: "/cache/pypi/requests-2.31.0.whl",
		ScanClean:    true,
		ScanJSON:     `{"clean":true}`,
		StoredAt:     time.Now().UTC().Truncate(time.Second),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second),
		SizeBytes:    4096,
	}

	err := idx.Insert(&ref, &entry)
	require.NoError(t, err)

	got, found := idx.Get(&ref)
	require.True(t, found)
	assert.Equal(t, entry.ArtifactPath, got.ArtifactPath)
	assert.True(t, got.ScanClean)
	assert.Equal(t, int64(4096), got.SizeBytes)
}

func TestIndex_GetMissing(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "nonexistent", Version: "9.9.9"}
	_, found := idx.Get(&ref)
	assert.False(t, found)
}

func TestIndex_IncrementHitCount(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "flask", Version: "3.0.0"}
	entry := cache.CacheEntry{
		ArtifactPath: "/cache/flask.whl",
		ScanClean:    true,
		StoredAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
		SizeBytes:    1024,
	}
	require.NoError(t, idx.Insert(&ref, &entry))

	require.NoError(t, idx.IncrementHit(&ref))
	require.NoError(t, idx.IncrementHit(&ref))

	got, found := idx.Get(&ref)
	require.True(t, found)
	assert.Equal(t, int64(2), got.HitCount)
}

func TestIndex_Delete(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "boto3", Version: "1.34.0"}
	entry := cache.CacheEntry{
		ArtifactPath: "/cache/boto3.whl",
		ScanClean:    true,
		StoredAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
		SizeBytes:    512,
	}
	require.NoError(t, idx.Insert(&ref, &entry))

	require.NoError(t, idx.Delete(&ref))

	_, found := idx.Get(&ref)
	assert.False(t, found)
}

func TestIndex_LRUCandidates(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	refs := []proxy.PackageRef{
		{Ecosystem: "pypi", Name: "a", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "b", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "c", Version: "1.0.0"},
	}
	base := time.Now().UTC()
	for i, ref := range refs {
		r := ref
		entry := cache.CacheEntry{
			ArtifactPath: "/cache/" + ref.Name + ".whl",
			ScanClean:    true,
			StoredAt:     base.Add(time.Duration(i) * time.Minute),
			ExpiresAt:    base.Add(24 * time.Hour),
			SizeBytes:    1024,
		}
		require.NoError(t, idx.Insert(&r, &entry))
	}

	// LRUCandidates should return entries ordered oldest-first.
	candidates, err := idx.LRUCandidates(2)
	require.NoError(t, err)
	require.Len(t, candidates, 2)
	assert.Equal(t, "a", candidates[0].Name)
	assert.Equal(t, "b", candidates[1].Name)
}
