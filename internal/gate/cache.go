package gate

// ArtifactEntry is a minimal view of a cached artifact, avoiding an import
// cycle with the cache package (which itself imports gate for PackageRef).
type ArtifactEntry struct {
	// ArtifactPath is the absolute path to the cached file on disk.
	ArtifactPath string
	// ScanClean is true if all scanners passed.
	ScanClean bool
}

// ArtifactCache is the storage interface used by the proxy handler.
// The real cache.LocalCache satisfies this interface via structural typing.
type ArtifactCache interface {
	Get(ref *PackageRef) (*ArtifactEntry, bool)
	Put(ref *PackageRef, tmpPath string, scanClean bool, scanJSON string) error
	Invalidate(ref *PackageRef) error
}
