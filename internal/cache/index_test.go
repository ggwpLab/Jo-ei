package cache_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
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

	ref := gate.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}
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

func TestIndex_ClassifierIsDistinctEntry(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	main := gate.PackageRef{Ecosystem: "maven", Name: "g:a", Version: "1.0"}
	sources := gate.PackageRef{Ecosystem: "maven", Name: "g:a", Version: "1.0", Classifier: "sources"}

	mainEntry := cache.CacheEntry{
		ArtifactPath: "/cache/a-1.0.jar",
		ScanClean:    true,
		StoredAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
		SizeBytes:    100,
	}
	srcEntry := cache.CacheEntry{
		ArtifactPath: "/cache/a-1.0-sources.jar",
		ScanClean:    true,
		StoredAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
		SizeBytes:    200,
	}

	require.NoError(t, idx.Insert(&main, &mainEntry))
	require.NoError(t, idx.Insert(&sources, &srcEntry))

	// The classifier must not collide with the main artifact: each ref keeps
	// its own row and file path.
	gotMain, found := idx.Get(&main)
	require.True(t, found)
	assert.Equal(t, "/cache/a-1.0.jar", gotMain.ArtifactPath)

	gotSrc, found := idx.Get(&sources)
	require.True(t, found)
	assert.Equal(t, "/cache/a-1.0-sources.jar", gotSrc.ArtifactPath)

	// Deleting the sources entry must leave the main entry intact.
	require.NoError(t, idx.Delete(&sources))
	_, found = idx.Get(&sources)
	assert.False(t, found)
	_, found = idx.Get(&main)
	assert.True(t, found)
}

func TestIndex_GetMissing(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	ref := gate.PackageRef{Ecosystem: "pypi", Name: "nonexistent", Version: "9.9.9"}
	_, found := idx.Get(&ref)
	assert.False(t, found)
}

func TestIndex_IncrementHitCount(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	ref := gate.PackageRef{Ecosystem: "pypi", Name: "flask", Version: "3.0.0"}
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

	ref := gate.PackageRef{Ecosystem: "pypi", Name: "boto3", Version: "1.34.0"}
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

func TestIndex_DueForRevalidationAndMarkValidated(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	now := time.Now().UTC()
	// stored_at drives initial last_validated (set by Insert).
	old := gate.PackageRef{Ecosystem: "pypi", Name: "old", Version: "1.0"}
	fresh := gate.PackageRef{Ecosystem: "pypi", Name: "fresh", Version: "1.0"}
	expired := gate.PackageRef{Ecosystem: "pypi", Name: "expired", Version: "1.0"}

	require.NoError(t, idx.Insert(&old, &cache.CacheEntry{
		ArtifactPath: "/c/old", ScanClean: true, ScanJSON: `{"clean":true}`,
		StoredAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(24 * time.Hour), SizeBytes: 1,
	}))
	require.NoError(t, idx.Insert(&fresh, &cache.CacheEntry{
		ArtifactPath: "/c/fresh", ScanClean: true,
		StoredAt: now, ExpiresAt: now.Add(24 * time.Hour), SizeBytes: 1,
	}))
	require.NoError(t, idx.Insert(&expired, &cache.CacheEntry{
		ArtifactPath: "/c/expired", ScanClean: true,
		StoredAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-1 * time.Hour), SizeBytes: 1,
	}))

	// Due = last_validated older than 24h ago AND not expired → only "old".
	cutoff := now.Add(-24 * time.Hour).Unix()
	due, err := idx.DueForRevalidation(cutoff, 10)
	require.NoError(t, err)
	require.Len(t, due, 1)
	assert.Equal(t, "old", due[0].Ref.Name)
	assert.Equal(t, "/c/old", due[0].FilePath)
	assert.True(t, due[0].ScanClean)
	assert.Equal(t, `{"clean":true}`, due[0].ScanJSON)

	// After marking validated now, it is no longer due.
	require.NoError(t, idx.MarkValidated(&old, now.Unix()))
	due, err = idx.DueForRevalidation(cutoff, 10)
	require.NoError(t, err)
	assert.Empty(t, due)
}

func TestIndex_LRUCandidates(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	refs := []gate.PackageRef{
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
