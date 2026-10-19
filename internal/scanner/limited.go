package scanner

import (
	"context"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// LimitedScanner caps the number of concurrent scans run against the wrapped
// engine. It exists to apply backpressure: clamd (and ICAP servers) have a
// bounded worker pool, so firing more concurrent INSTREAM/RESPMOD requests than
// the engine can serve makes responses queue past the per-scan deadline and
// surface as "i/o timeout". Bounding in-flight scans keeps each one fast enough
// to beat its deadline. It implements gate.AVScanner.
type LimitedScanner struct {
	inner gate.AVScanner
	sem   chan struct{}
	// onWait, when non-nil, receives how long each Scan waited for a slot.
	onWait func(time.Duration)
}

// LimitedOption customises a LimitedScanner.
type LimitedOption func(*LimitedScanner)

// WithWaitObserver reports, once per Scan that acquires a slot, how long it
// waited in the queue. A nil f is a no-op and skips timing entirely.
func WithWaitObserver(f func(time.Duration)) LimitedOption {
	return func(l *LimitedScanner) { l.onWait = f }
}

// NewLimitedScanner wraps inner so that at most limit scans run concurrently.
// A limit <= 0 disables limiting and returns inner unchanged.
func NewLimitedScanner(inner gate.AVScanner, limit int, opts ...LimitedOption) gate.AVScanner {
	if limit <= 0 {
		return inner
	}
	l := &LimitedScanner{inner: inner, sem: make(chan struct{}, limit)}
	for _, o := range opts {
		o(l)
	}
	return l
}

// Scan acquires a concurrency slot (honouring context cancellation while it
// waits) then delegates to the wrapped scanner.
func (l *LimitedScanner) Scan(ctx context.Context, filePath string) (*gate.AVResult, error) {
	var start time.Time
	if l.onWait != nil {
		start = time.Now()
	}
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if l.onWait != nil {
		l.onWait(time.Since(start))
	}
	defer func() { <-l.sem }()
	return l.inner.Scan(ctx, filePath)
}
