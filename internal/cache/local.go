package cache

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// LocalCacheConfig configures the local filesystem cache.
type LocalCacheConfig struct {
	RootPath  string
	MaxSizeGB int
	TTL       time.Duration
}

// LocalCache implements Cache using the local filesystem with a SQLite index.
type LocalCache struct {
	cfg       LocalCacheConfig
	index     *Index
	evictCh   chan struct{}
	workerWG  sync.WaitGroup
	closeOnce sync.Once
}

// NewLocalCache creates a LocalCache rooted at cfg.RootPath.
func NewLocalCache(cfg LocalCacheConfig) (*LocalCache, error) {
	if err := os.MkdirAll(cfg.RootPath, 0755); err != nil {
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
func (lc *LocalCache) artifactPath(ref *proxy.PackageRef) string {
	hash := sha256.Sum256([]byte(ref.Key()))
	hex := fmt.Sprintf("%x", hash)
	return filepath.Join(lc.cfg.RootPath, "artifacts", hex[:2], hex)
}

// Get returns a cached entry, or (nil, false) on miss or expiry.
func (lc *LocalCache) Get(ref *proxy.PackageRef) (*CacheEntry, bool) {
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
func (lc *LocalCache) Put(ref *proxy.PackageRef, tmpPath string, scanClean bool, scanJSON string) error {
	destPath := lc.artifactPath(ref)
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("creating artifact dir: %w", err)
	}

	srcFile, err := os.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("opening temp file %q: %w", tmpPath, err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("creating cached file %q: %w", destPath, err)
	}
	defer dstFile.Close()

	written, err := io.Copy(dstFile, srcFile)
	if err != nil {
		_ = os.Remove(destPath)
		return fmt.Errorf("copying artifact to cache: %w", err)
	}

	ttl := lc.cfg.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	entry := &CacheEntry{
		ArtifactPath: destPath,
		ScanClean:    scanClean,
		ScanJSON:     scanJSON,
		StoredAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(ttl),
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
func (lc *LocalCache) Invalidate(ref *proxy.PackageRef) error {
	entry, found := lc.index.Get(ref)
	if found {
		_ = os.Remove(entry.ArtifactPath)
	}
	return lc.index.Delete(ref)
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
	return CacheStats{Entries: count, SizeBytes: size}, nil
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
			_ = lc.Invalidate(&r)
		}
		total, _ = lc.index.TotalSizeBytes()
	}
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
