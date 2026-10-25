package scanner

import (
	"context"
	"sync"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// MultiScanner runs several AV engines concurrently on the same file, so a
// scan takes as long as the slowest engine rather than the sum of all of them.
// It implements gate.AVScanner and fails closed: any engine reporting malware
// or failing blocks the artifact.
type MultiScanner struct {
	scanners []gate.AVScanner
}

// NewMultiScanner wraps the given scanners. Their order decides which result
// is reported when several engines detect or fail on the same file.
func NewMultiScanner(scanners ...gate.AVScanner) *MultiScanner {
	return &MultiScanner{scanners: scanners}
}

// Scan runs every engine at once and waits for all of them, so no engine is
// still reading the file (or holding a concurrency slot) once Scan returns. A
// detection cancels the others' context. The verdict is the first detection in
// engine order; failing that, the first error in engine order; else clean. A
// detection outranks an error because both block and the detection says why.
func (m *MultiScanner) Scan(ctx context.Context, filePath string) (*gate.AVResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([]*gate.AVResult, len(m.scanners))
	errs := make([]error, len(m.scanners))
	var wg sync.WaitGroup
	for i, s := range m.scanners {
		wg.Go(func() {
			results[i], errs[i] = s.Scan(ctx, filePath)
			if errs[i] == nil && results[i] != nil && !results[i].Clean {
				cancel()
			}
		})
	}
	wg.Wait()

	for _, res := range results {
		if res != nil && !res.Clean {
			return res, nil
		}
	}
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return &gate.AVResult{Clean: true}, nil
}
