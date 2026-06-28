package cache

import "github.com/ggwpLab/Jo-ei/internal/proxy"

// RevalEntry is a cached entry presented to the re-validation sweep. It carries
// just enough to re-run the gates: the package ref, the artifact bytes on disk,
// and the prior verdict.
type RevalEntry struct {
	Ref       proxy.PackageRef
	FilePath  string
	ScanClean bool
	ScanJSON  string
}
