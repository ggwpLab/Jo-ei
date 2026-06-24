package dockerproxy

import (
	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// verdictStore is a thin digest-keyed facade over the shared cache.Cache. Blob
// bodies, manifest bodies, and gate verdicts are all stored as cache entries
// under docker-shaped PackageRefs, reusing the cache's disk store, size
// accounting, and LRU eviction.
type verdictStore struct {
	c cache.Cache
}

func newVerdictStore(c cache.Cache) *verdictStore { return &verdictStore{c: c} }

func blobRef(digest string) *proxy.PackageRef {
	return &proxy.PackageRef{Ecosystem: "docker", Name: "blobs", Version: digest}
}

func imageRefKey(repo, digest string) *proxy.PackageRef {
	return &proxy.PackageRef{Ecosystem: "docker", Name: repo, Version: digest}
}

// GetBlob returns the cached path and clean flag for a layer/config blob.
func (v *verdictStore) GetBlob(digest string) (string, bool, bool) {
	e, ok := v.c.Get(blobRef(digest))
	if !ok {
		return "", false, false
	}
	return e.ArtifactPath, e.ScanClean, true
}

// PutBlob stores a blob body with its ClamAV clean verdict.
func (v *verdictStore) PutBlob(digest, tmpPath string, clean bool) error {
	return v.c.Put(blobRef(digest), tmpPath, clean, "")
}

// GetImageVerdict returns the cached gate verdict for an image digest. The block
// reason is stored in the entry's ScanJSON field.
func (v *verdictStore) GetImageVerdict(repo, digest string) (bool, string, bool) {
	e, ok := v.c.Get(imageRefKey(repo, digest))
	if !ok {
		return false, "", false
	}
	return e.ScanClean, e.ScanJSON, true
}

// PutImageVerdict caches the gate verdict together with the manifest body.
func (v *verdictStore) PutImageVerdict(repo, digest, manifestTmpPath string, clean bool, reason string) error {
	return v.c.Put(imageRefKey(repo, digest), manifestTmpPath, clean, reason)
}

// GetManifestBody returns the cached manifest file path for an approved image.
func (v *verdictStore) GetManifestBody(repo, digest string) (string, bool) {
	e, ok := v.c.Get(imageRefKey(repo, digest))
	if !ok {
		return "", false
	}
	return e.ArtifactPath, true
}
