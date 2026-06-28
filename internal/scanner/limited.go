package scanner

import (
	"context"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// LimitedScanner caps the number of concurrent scans run against the wrapped
// engine. It exists to apply backpressure: clamd (and ICAP servers) have a
// bounded worker pool, so firing more concurrent INSTREAM/RESPMOD requests than
// the engine can serve makes responses queue past the per-scan deadline and
// surface as "i/o timeout". Bounding in-flight scans keeps each one fast enough
// to beat its deadline. It implements proxy.AVScanner.
type LimitedScanner struct {
	inner proxy.AVScanner
	sem   chan struct{}
}

// NewLimitedScanner wraps inner so that at most limit scans run concurrently.
// A limit <= 0 disables limiting and returns inner unchanged.
func NewLimitedScanner(inner proxy.AVScanner, limit int) proxy.AVScanner {
	if limit <= 0 {
		return inner
	}
	return &LimitedScanner{inner: inner, sem: make(chan struct{}, limit)}
}

// Scan acquires a concurrency slot (honouring context cancellation while it
// waits) then delegates to the wrapped scanner.
func (l *LimitedScanner) Scan(ctx context.Context, filePath string) (*proxy.AVResult, error) {
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-l.sem }()
	return l.inner.Scan(ctx, filePath)
}
