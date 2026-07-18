package cache

import (
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// AsArtifactCache bridges a Cache to the narrower gate.ArtifactCache the
// proxy handler consumes (gate cannot import cache — see gate.ArtifactEntry).
func AsArtifactCache(c Cache) gate.ArtifactCache { return &artifactCacheAdapter{c: c} }

type artifactCacheAdapter struct{ c Cache }

func (a *artifactCacheAdapter) Get(ref *gate.PackageRef) (*gate.ArtifactEntry, bool) {
	entry, found := a.c.Get(ref)
	if !found {
		return nil, false
	}
	return &gate.ArtifactEntry{
		ArtifactPath:     entry.ArtifactPath,
		ScanClean:        entry.ScanClean,
		LastCVECheck:     entry.LastCVECheck,
		LastMalwareCheck: entry.LastMalwareCheck,
	}, true
}

func (a *artifactCacheAdapter) Put(ref *gate.PackageRef, tmpPath string, scanClean bool, scanJSON string) error {
	return a.c.Put(ref, tmpPath, scanClean, scanJSON)
}

func (a *artifactCacheAdapter) Invalidate(ref *gate.PackageRef) error {
	return a.c.Invalidate(ref)
}

func (a *artifactCacheAdapter) MarkCVEChecked(ref *gate.PackageRef, ts time.Time) error {
	return a.c.MarkCVEChecked(ref, ts)
}

func (a *artifactCacheAdapter) MarkMalwareChecked(ref *gate.PackageRef, ts time.Time) error {
	return a.c.MarkMalwareChecked(ref, ts)
}
