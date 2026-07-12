// Package cache stores downloaded artifacts and their scan results.
package cache

import (
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// CacheEntry stores an artifact path and its scan results.
type CacheEntry struct {
	// ArtifactPath is the absolute path to the cached file on disk.
	ArtifactPath string
	// ScanClean is true if all scanners passed.
	ScanClean bool
	// ScanJSON stores the serialized ScanResult for future inspection.
	ScanJSON  string
	StoredAt  time.Time
	ExpiresAt time.Time
	HitCount  int64
	SizeBytes int64
}

// IsExpired returns true if the entry TTL has elapsed.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// CacheStats holds aggregate statistics about the cache.
type CacheStats struct {
	Entries   int64
	SizeBytes int64
	HitRatio  float64
	Evictions int64
	// ExpiredBytes is the total size of entries past their TTL — reclaimable
	// space, since expired entries are dropped on access.
	ExpiredBytes int64
}

// Cache is the storage interface for package artifacts and scan results.
type Cache interface {
	// Get returns the cached entry for ref, or (nil, false) on miss or expiry.
	Get(ref *gate.PackageRef) (*CacheEntry, bool)
	// Put copies the artifact at tmpPath into the cache store and records the scan result.
	Put(ref *gate.PackageRef, tmpPath string, scanClean bool, scanJSON string) error
	// Invalidate removes the cached entry and its artifact file for ref.
	Invalidate(ref *gate.PackageRef) error
	// Stats returns aggregate cache statistics.
	Stats() (CacheStats, error)
	// Close stops background workers and releases the index.
	Close() error
}
