// Package dockerproxy implements a pull-through Docker Registry V2 proxy that
// gates images on Trivy (CVE/secrets) and ClamAV (signature malware) before
// serving them. It is isolated from proxy.Handler and reuses Jōei's existing
// policy, supply-chain, cache, and telemetry subsystems via their interfaces.
package dockerproxy

import (
	"context"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
)

// ImageScanResult holds the vulnerability findings for a scanned image.
type ImageScanResult struct {
	Findings []gate.CVEFinding
}

// ImageScanner scans a container image for vulnerabilities/secrets. imageRef is
// "<host>/<repo>@<digest>". Implementations must be safe for concurrent use and
// expose a passive health sample for the console.
type ImageScanner interface {
	ScanImage(ctx context.Context, imageRef string) (*ImageScanResult, error)
	Health() health.Sample
}
