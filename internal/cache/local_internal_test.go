package cache

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// legacySchema is the pre-classifier table definition shipped in production.
const legacySchema = `
CREATE TABLE artifacts (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	ecosystem    TEXT    NOT NULL,
	name         TEXT    NOT NULL,
	version      TEXT    NOT NULL,
	file_path    TEXT    NOT NULL,
	scan_clean   INTEGER NOT NULL DEFAULT 0,
	scan_json    TEXT    NOT NULL DEFAULT '',
	stored_at    INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	last_hit     INTEGER NOT NULL DEFAULT 0,
	hit_count    INTEGER NOT NULL DEFAULT 0,
	size_bytes   INTEGER NOT NULL DEFAULT 0,
	UNIQUE(ecosystem, name, version)
);
CREATE INDEX idx_last_hit ON artifacts(last_hit);
`

func TestNewIndex_MigratesLegacyDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")

	// Seed a legacy DB with one row, as a pre-upgrade deployment would have.
	seed, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = seed.Exec(legacySchema)
	require.NoError(t, err)
	now := time.Now().Unix()
	_, err = seed.Exec(`INSERT INTO artifacts
		(ecosystem, name, version, file_path, scan_clean, scan_json, stored_at, expires_at, last_hit, hit_count, size_bytes)
		VALUES ('maven','g:a','1.0','/cache/a-1.0.jar',1,'',?,?,?,5,123)`,
		now, now+86400, now)
	require.NoError(t, err)
	require.NoError(t, seed.Close())

	// Opening through NewIndex must migrate in place without losing data.
	idx, err := NewIndex(dbPath)
	require.NoError(t, err)
	defer idx.Close()

	main := gate.PackageRef{Ecosystem: "maven", Name: "g:a", Version: "1.0"}
	got, found := idx.Get(&main)
	require.True(t, found, "legacy row must survive migration")
	assert.Equal(t, "/cache/a-1.0.jar", got.ArtifactPath)
	assert.Equal(t, int64(123), got.SizeBytes)

	// And the classifier column now works: a sources jar is a distinct row.
	sources := gate.PackageRef{Ecosystem: "maven", Name: "g:a", Version: "1.0", Classifier: "sources"}
	require.NoError(t, idx.Insert(&sources, &CacheEntry{
		ArtifactPath: "/cache/a-1.0-sources.jar",
		ScanClean:    true,
		StoredAt:     time.Now().UTC(),
		SizeBytes:    456,
	}))
	gotSrc, found := idx.Get(&sources)
	require.True(t, found)
	assert.Equal(t, "/cache/a-1.0-sources.jar", gotSrc.ArtifactPath)

	// Main row stays intact alongside the new sources row.
	_, found = idx.Get(&main)
	assert.True(t, found)
}

func TestIndex_GetIgnoresLegacyExpiry(t *testing.T) {
	idx, err := NewIndex(filepath.Join(t.TempDir(), "i.db"))
	require.NoError(t, err)
	defer idx.Close()

	ref := gate.PackageRef{Ecosystem: "pypi", Name: "legacy", Version: "1.0"}
	require.NoError(t, idx.Insert(&ref, &CacheEntry{
		ArtifactPath: "/c/legacy", StoredAt: time.Now().UTC().Add(-48 * time.Hour), SizeBytes: 1,
	}))
	// Simulate a row written by a pre-stale binary whose TTL has lapsed.
	_, err = idx.db.Exec(`UPDATE artifacts SET expires_at = ? WHERE name = 'legacy'`,
		time.Now().Add(-time.Hour).Unix())
	require.NoError(t, err)

	_, found := idx.Get(&ref)
	assert.True(t, found, "expiry is gone; old expires_at values must not hide entries")
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "art.bin")
	require.NoError(t, os.WriteFile(p, []byte(content), 0644))
	return p
}

func TestLocalCache_EvictToSizeRemovesEntries(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	for _, n := range []string{"a", "b", "c"} {
		ref := &gate.PackageRef{Ecosystem: "pypi", Name: n, Version: "1.0"}
		require.NoError(t, lc.Put(ref, writeTemp(t, "data-"+n), true, ""))
	}
	before, err := lc.index.Count()
	require.NoError(t, err)
	require.Equal(t, int64(3), before)

	// 1-byte budget forces eviction of everything over the limit.
	lc.evictToSize(1)

	after, err := lc.index.Count()
	require.NoError(t, err)
	require.Less(t, after, before)
}

func TestLocalCache_StatsReportsStaleBytes(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	fresh := &gate.PackageRef{Ecosystem: "pypi", Name: "fresh", Version: "1.0"}
	require.NoError(t, lc.Put(fresh, writeTemp(t, "fresh-data"), true, ""))

	// Insert an already-idle entry directly; Insert seeds last_hit from StoredAt.
	stale := &gate.PackageRef{Ecosystem: "pypi", Name: "stale", Version: "1.0"}
	require.NoError(t, lc.index.Insert(stale, &CacheEntry{
		ArtifactPath: filepath.Join(lc.cfg.RootPath, "gone.bin"),
		StoredAt:     time.Now().UTC().Add(-2 * time.Hour),
		SizeBytes:    123,
	}))

	stats, err := lc.Stats()
	require.NoError(t, err)
	assert.Equal(t, int64(123), stats.StaleBytes, "only the idle entry's bytes are reclaimable")
}

func TestLocalCache_ConcurrentPutsAreSafe(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	const n = 20
	paths := make([]string, n)
	for i := range paths {
		paths[i] = writeTemp(t, "data")
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ref := &gate.PackageRef{Ecosystem: "pypi", Name: fmt.Sprintf("pkg%d", i), Version: "1.0"}
			_ = lc.Put(ref, paths[i], true, "")
		}(i)
	}
	wg.Wait()

	count, err := lc.index.Count()
	require.NoError(t, err)
	require.Equal(t, int64(n), count)
}

func TestLocalCache_CloseIsIdempotent(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	require.NoError(t, lc.Close())
	require.NoError(t, lc.Close())
}

func TestLocalCache_EvictionsAreCounted(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	for _, n := range []string{"a", "b", "c"} {
		ref := &gate.PackageRef{Ecosystem: "pypi", Name: n, Version: "1.0"}
		require.NoError(t, lc.Put(ref, writeTemp(t, "data-"+n), true, ""))
	}
	before, err := lc.index.Count()
	require.NoError(t, err)

	lc.evictToSize(1)

	after, err := lc.index.Count()
	require.NoError(t, err)
	evicted := before - after
	require.Positive(t, evicted, "eviction must have removed entries")

	stats, err := lc.Stats()
	require.NoError(t, err)
	assert.Equal(t, evicted, stats.Evictions)
}

func TestLocalCache_PurgeStale(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	fresh := &gate.PackageRef{Ecosystem: "pypi", Name: "fresh", Version: "1.0"}
	require.NoError(t, lc.Put(fresh, writeTemp(t, "fresh-data"), true, ""))

	// Two idle entries with real files on disk; Insert seeds last_hit from StoredAt.
	var stalePaths []string
	for i, n := range []string{"s1", "s2"} {
		p := filepath.Join(lc.cfg.RootPath, n+".bin")
		require.NoError(t, os.WriteFile(p, []byte("stale-data"), 0644))
		stalePaths = append(stalePaths, p)
		ref := &gate.PackageRef{Ecosystem: "pypi", Name: n, Version: "1.0"}
		require.NoError(t, lc.index.Insert(ref, &CacheEntry{
			ArtifactPath: p,
			StoredAt:     time.Now().UTC().Add(-time.Duration(2+i) * time.Hour),
			SizeBytes:    50,
		}))
	}

	removed, freed, err := lc.PurgeStale()
	require.NoError(t, err)
	assert.Equal(t, int64(2), removed)
	assert.Equal(t, int64(100), freed)
	for _, p := range stalePaths {
		_, statErr := os.Stat(p)
		assert.True(t, os.IsNotExist(statErr), "purged artifact %s must be deleted", p)
	}

	// The fresh entry survives, and nothing is stale anymore.
	_, found := lc.Get(fresh)
	assert.True(t, found)
	stats, err := lc.Stats()
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.StaleBytes)
	assert.Equal(t, int64(0), stats.Evictions, "manual purge must not count as LRU eviction")
}

func TestLocalCache_EvictToSizeBailsOnZeroProgress(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	for _, n := range []string{"a", "b", "c"} {
		ref := &gate.PackageRef{Ecosystem: "pypi", Name: n, Version: "1.0"}
		require.NoError(t, lc.Put(ref, writeTemp(t, "data-"+n), true, ""))
	}
	before, err := lc.index.Count()
	require.NoError(t, err)
	require.Equal(t, int64(3), before)

	// Make every DELETE on the artifacts table fail, so invalidate() always
	// errors even though LRUCandidates keeps returning the same rows. Before
	// the zero-progress bail this spun evictToSize's loop forever.
	_, err = lc.index.db.Exec(`
		CREATE TRIGGER block_delete BEFORE DELETE ON artifacts
		BEGIN SELECT RAISE(ABORT, 'delete blocked for test'); END;`)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		lc.evictToSize(1) // 1-byte budget: every entry is over budget, forcing eviction attempts.
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("evictToSize did not return — zero-progress bail is missing (infinite spin)")
	}

	after, err := lc.index.Count()
	require.NoError(t, err)
	assert.Equal(t, before, after, "no rows should have been removed since every delete failed")
}

func TestNewLocalCache_DefaultsStaleAfterWhenUnset(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1}) // StaleAfter left zero
	require.NoError(t, err)
	defer lc.Close()

	assert.Equal(t, time.Duration(DefaultStaleAfterDays)*24*time.Hour, lc.cfg.StaleAfter,
		"StaleAfter<=0 must default rather than making staleCutoff() == now (which would mark the whole cache stale)")

	// Defense-in-depth check: an entry stored moments ago must not be
	// immediately reported as stale.
	ref := &gate.PackageRef{Ecosystem: "pypi", Name: "fresh", Version: "1.0"}
	require.NoError(t, lc.Put(ref, writeTemp(t, "data"), true, ""))
	stats, err := lc.Stats()
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.StaleBytes)
}

func TestLocalCache_PurgeStaleSkipsAlreadyGoneRows(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	ref := &gate.PackageRef{Ecosystem: "pypi", Name: "gone", Version: "1.0"}
	ok, err := lc.invalidate(ref)
	require.NoError(t, err)
	assert.False(t, ok, "deleting a nonexistent row must report no deletion")
}
