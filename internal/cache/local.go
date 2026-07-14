package cache

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// LocalCacheConfig configures the local filesystem cache.
type LocalCacheConfig struct {
	RootPath  string
	MaxSizeGB int
	// StaleAfter is the idle threshold: entries not hit for this long count
	// as stale (reclaimable via PurgeStale / the console Clean up button).
	StaleAfter time.Duration
}

// LocalCache implements Cache using the local filesystem with a SQLite index.
type LocalCache struct {
	cfg       LocalCacheConfig
	index     *Index
	evictCh   chan struct{}
	evictions atomic.Int64 // entries evicted by evictToSize since process start
	workerWG  sync.WaitGroup
	closeOnce sync.Once
}

// NewLocalCache creates a LocalCache rooted at cfg.RootPath.
func NewLocalCache(cfg LocalCacheConfig) (*LocalCache, error) {
	if err := os.MkdirAll(cfg.RootPath, 0755); err != nil { // #nosec G301 -- cache of public package artifacts
		return nil, fmt.Errorf("creating cache dir %q: %w", cfg.RootPath, err)
	}

	dbPath := filepath.Join(cfg.RootPath, "index.db")
	idx, err := NewIndex(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening cache index: %w", err)
	}

	lc := &LocalCache{cfg: cfg, index: idx, evictCh: make(chan struct{}, 1)}
	lc.workerWG.Add(1)
	go lc.evictWorker()
	return lc, nil
}

// artifactPath returns the deterministic on-disk path for a cached artifact.
// Uses SHA256(key) to avoid filesystem name collisions and long paths.
func (lc *LocalCache) artifactPath(ref *gate.PackageRef) string {
	hash := sha256.Sum256([]byte(ref.Key()))
	hex := fmt.Sprintf("%x", hash)
	return filepath.Join(lc.cfg.RootPath, "artifacts", hex[:2], hex)
}

// Get returns a cached entry, or (nil, false) on miss.
func (lc *LocalCache) Get(ref *gate.PackageRef) (*CacheEntry, bool) {
	entry, found := lc.index.Get(ref)
	if !found {
		return nil, false
	}

	// Verify the artifact file still exists on disk.
	if _, err := os.Stat(entry.ArtifactPath); err != nil {
		_ = lc.index.Delete(ref)
		return nil, false
	}

	_ = lc.index.IncrementHit(ref)
	return entry, true
}

// Put copies the artifact from tmpPath into the cache store and records scan results.
func (lc *LocalCache) Put(ref *gate.PackageRef, tmpPath string, scanClean bool, scanJSON string) error {
	destPath := lc.artifactPath(ref)
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil { // #nosec G301 -- cache of public package artifacts
		return fmt.Errorf("creating artifact dir: %w", err)
	}

	srcFile, err := os.Open(tmpPath) // #nosec G304 -- tmpPath is our own just-downloaded temp file, not user input
	if err != nil {
		return fmt.Errorf("opening temp file %q: %w", tmpPath, err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(destPath) // #nosec G304 -- destPath is RootPath/artifacts/<sha256 of the key>; no user-controlled path segments
	if err != nil {
		return fmt.Errorf("creating cached file %q: %w", destPath, err)
	}
	defer dstFile.Close()

	written, err := io.Copy(dstFile, srcFile)
	if err != nil {
		_ = os.Remove(destPath)
		return fmt.Errorf("copying artifact to cache: %w", err)
	}

	entry := &CacheEntry{
		ArtifactPath: destPath,
		ScanClean:    scanClean,
		ScanJSON:     scanJSON,
		StoredAt:     time.Now().UTC(),
		SizeBytes:    written,
	}

	if err := lc.index.Insert(ref, entry); err != nil {
		_ = os.Remove(destPath)
		return fmt.Errorf("indexing cached artifact: %w", err)
	}

	// Signal the eviction worker (non-blocking; bursts coalesce).
	select {
	case lc.evictCh <- struct{}{}:
	default:
	}

	return nil
}

// Invalidate removes an entry from both the index and disk.
func (lc *LocalCache) Invalidate(ref *gate.PackageRef) error {
	entry, found := lc.index.Get(ref)
	if found {
		_ = os.Remove(entry.ArtifactPath)
	}
	return lc.index.Delete(ref)
}

// staleCutoff is the last_hit unix timestamp below which an entry is stale.
func (lc *LocalCache) staleCutoff() int64 {
	return time.Now().Add(-lc.cfg.StaleAfter).Unix()
}

// Stats returns aggregate cache statistics.
func (lc *LocalCache) Stats() (CacheStats, error) {
	size, err := lc.index.TotalSizeBytes()
	if err != nil {
		return CacheStats{}, err
	}
	count, err := lc.index.Count()
	if err != nil {
		return CacheStats{}, err
	}
	stale, err := lc.index.StaleSizeBytes(lc.staleCutoff())
	if err != nil {
		return CacheStats{}, err
	}
	return CacheStats{Entries: count, SizeBytes: size, Evictions: lc.evictions.Load(), StaleBytes: stale}, nil
}

// purgeBatch is how many stale candidates PurgeStale fetches per round.
const purgeBatch = 100

// PurgeStale removes every entry idle longer than cfg.StaleAfter and returns
// how many entries were removed and their total size. Individual failures are
// skipped (same policy as evictToSize); a round that makes no progress aborts
// instead of spinning on undeletable rows.
func (lc *LocalCache) PurgeStale() (removed, freedBytes int64, err error) {
	cutoff := lc.staleCutoff()
	for {
		candidates, err := lc.index.StaleCandidates(cutoff, purgeBatch)
		if err != nil {
			return removed, freedBytes, err
		}
		if len(candidates) == 0 {
			return removed, freedBytes, nil
		}
		progress := false
		for _, cand := range candidates {
			c := cand
			if lc.Invalidate(&c.Ref) == nil {
				removed++
				freedBytes += c.SizeBytes
				progress = true
			}
		}
		if !progress {
			return removed, freedBytes, fmt.Errorf("cache purge: no progress on %d stale entries", len(candidates))
		}
	}
}

// evictWorker drains eviction triggers until the channel is closed.
func (lc *LocalCache) evictWorker() {
	defer lc.workerWG.Done()
	for range lc.evictCh {
		lc.evictIfNeeded()
	}
}

// evictIfNeeded evicts LRU entries until the cache is under MaxSizeGB.
func (lc *LocalCache) evictIfNeeded() {
	maxBytes := int64(lc.cfg.MaxSizeGB) * 1024 * 1024 * 1024
	if maxBytes == 0 {
		return
	}
	lc.evictToSize(maxBytes)
}

// evictToSize removes LRU entries until total size is at or below maxBytes.
func (lc *LocalCache) evictToSize(maxBytes int64) {
	total, err := lc.index.TotalSizeBytes()
	if err != nil || total <= maxBytes {
		return
	}
	for total > maxBytes {
		candidates, err := lc.index.LRUCandidates(10)
		if err != nil || len(candidates) == 0 {
			return
		}
		for _, ref := range candidates {
			r := ref
			if lc.Invalidate(&r) == nil {
				lc.evictions.Add(1)
			}
		}
		total, _ = lc.index.TotalSizeBytes()
	}
}

// DueForRevalidation returns cached entries due for re-validation. See Index.
func (lc *LocalCache) DueForRevalidation(before int64, limit int) ([]RevalEntry, error) {
	return lc.index.DueForRevalidation(before, limit)
}

// MarkValidated records that ref passed re-validation at ts (unix seconds).
func (lc *LocalCache) MarkValidated(ref *gate.PackageRef, ts int64) error {
	return lc.index.MarkValidated(ref, ts)
}

// Close stops the eviction worker and closes the index. Safe to call twice.
func (lc *LocalCache) Close() error {
	var closeErr error
	lc.closeOnce.Do(func() {
		close(lc.evictCh)
		lc.workerWG.Wait()
		closeErr = lc.index.Close()
	})
	return closeErr
}
