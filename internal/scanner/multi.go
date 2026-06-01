package scanner

import (
	"context"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// MultiScanner runs several AV engines sequentially in order. It implements
// proxy.AVScanner. It short-circuits on the first detection or first error
// (fail-closed): any engine reporting malware or failing blocks the artifact.
type MultiScanner struct {
	scanners []proxy.AVScanner
}

// NewMultiScanner wraps the given scanners. They run in the order supplied.
func NewMultiScanner(scanners ...proxy.AVScanner) *MultiScanner {
	return &MultiScanner{scanners: scanners}
}

// Scan runs each engine until one errors or reports an infection.
func (m *MultiScanner) Scan(ctx context.Context, filePath string) (*proxy.AVResult, error) {
	for _, s := range m.scanners {
		res, err := s.Scan(ctx, filePath)
		if err != nil {
			return nil, err
		}
		if !res.Clean {
			return res, nil
		}
	}
	return &proxy.AVResult{Clean: true}, nil
}
