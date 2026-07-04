package scanner

import (
	"context"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// MultiScanner runs several AV engines sequentially in order. It implements
// gate.AVScanner. It short-circuits on the first detection or first error
// (fail-closed): any engine reporting malware or failing blocks the artifact.
type MultiScanner struct {
	scanners []gate.AVScanner
}

// NewMultiScanner wraps the given scanners. They run in the order supplied.
func NewMultiScanner(scanners ...gate.AVScanner) *MultiScanner {
	return &MultiScanner{scanners: scanners}
}

// Scan runs each engine until one errors or reports an infection.
func (m *MultiScanner) Scan(ctx context.Context, filePath string) (*gate.AVResult, error) {
	for _, s := range m.scanners {
		res, err := s.Scan(ctx, filePath)
		if err != nil {
			return nil, err
		}
		if !res.Clean {
			return res, nil
		}
	}
	return &gate.AVResult{Clean: true}, nil
}
