package gate

import "time"

// ArtifactEntry is a minimal view of a cached artifact, avoiding an import
// cycle with the cache package (which itself imports gate for PackageRef).
type ArtifactEntry struct {
	// ArtifactPath is the absolute path to the cached file on disk.
	ArtifactPath string
	// ScanClean is true if all scanners passed.
	ScanClean bool
	// LastCVECheck / LastMalwareCheck record when each gate last confirmed the
	// entry clean; the handler re-runs a gate when its TTL has lapsed.
	LastCVECheck     time.Time
	LastMalwareCheck time.Time
}

// ArtifactCache is the storage interface used by the proxy handler.
// The real cache.LocalCache satisfies this interface via the cacheAdapter in
// cmd/jo-ei.
type ArtifactCache interface {
	Get(ref *PackageRef) (*ArtifactEntry, bool)
	Put(ref *PackageRef, tmpPath string, scanClean bool, scanJSON string) error
	Invalidate(ref *PackageRef) error
	// MarkCVEChecked / MarkMalwareChecked record a passed lazy re-check at ts.
	MarkCVEChecked(ref *PackageRef, ts time.Time) error
	MarkMalwareChecked(ref *PackageRef, ts time.Time) error
}
