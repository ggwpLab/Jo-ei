package cache

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/storage"
)

type usageWriterOptions struct {
	PendingCapacity, BatchSize   int
	FlushInterval, RetryInterval time.Duration
}

var defaultUsageWriterOptions = usageWriterOptions{4096, 256, 10 * time.Second, time.Second}

type pendingUsage struct {
	UsageDelta
	firstSeq uint64
	admitted time.Time
}

type usageWriter struct {
	mu                  sync.Mutex
	pending             map[int64]*pendingUsage
	order               []int64
	inFlight            []pendingUsage
	opts                usageWriterOptions
	counts              storage.WriterStats
	closed              bool
	flushTo             uint64
	wake, done, changed chan struct{}
	ctx                 context.Context
	cancel              context.CancelFunc
	err                 error
	lastSuccess         time.Time
}

func newUsageWriter(apply func(context.Context, string, []UsageDelta) error, opts usageWriterOptions) *usageWriter {
	w := &usageWriter{opts: opts, pending: make(map[int64]*pendingUsage), order: make([]int64, 0, opts.PendingCapacity), wake: make(chan struct{}, 1), done: make(chan struct{}), changed: make(chan struct{})}
	w.ctx, w.cancel = context.WithCancel(context.Background())
	go w.run(apply)
	return w
}

func (w *usageWriter) record(rowID int64, at time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.counts.AttemptedItems++
	if w.closed {
		w.counts.DroppedClosedItems++
		return
	}
	if p := w.pending[rowID]; p != nil {
		p.Hits++
		p.LastHit = max(p.LastHit, at.Unix())
		w.counts.AcceptedItems++
		return
	}
	if len(w.pending) == w.opts.PendingCapacity {
		w.counts.DroppedFullItems++
		w.flushTo = w.counts.AcceptedItems
		w.signal()
		return
	}
	w.counts.AcceptedItems++
	w.pending[rowID] = &pendingUsage{UsageDelta: UsageDelta{RowID: rowID, Hits: 1, LastHit: at.Unix()}, firstSeq: w.counts.AcceptedItems, admitted: time.Now()}
	w.order = append(w.order, rowID)
	if len(w.pending) >= w.opts.BatchSize {
		w.signal()
	}
}

func (w *usageWriter) signal() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}
func (w *usageWriter) requestFlush() {
	w.mu.Lock()
	w.flushTo = w.counts.AcceptedItems
	w.signal()
	w.mu.Unlock()
}

// Coalescing may commit later hits before an earlier distinct row. A barrier
// therefore follows admission sequence, never the cumulative committed count.
func (w *usageWriter) unfinished(target uint64) bool {
	return (len(w.inFlight) > 0 && w.inFlight[0].firstSeq <= target) || (len(w.order) > 0 && w.pending[w.order[0]].firstSeq <= target)
}

func (w *usageWriter) flush(ctx context.Context) error {
	w.mu.Lock()
	target := w.counts.AcceptedItems
	w.flushTo = target
	w.signal()
	for w.unfinished(target) {
		if w.err != nil {
			err := w.err
			w.mu.Unlock()
			return err
		}
		changed := w.changed
		w.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
		w.mu.Lock()
	}
	err := w.err
	w.mu.Unlock()
	return err
}

func (w *usageWriter) shutdown(ctx context.Context) error {
	w.mu.Lock()
	w.closed = true
	w.flushTo = w.counts.AcceptedItems
	w.signal()
	w.mu.Unlock()
	select {
	case <-w.done:
	case <-ctx.Done():
		w.cancel()
		<-w.done
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *usageWriter) stats() storage.WriterStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.counts
	s.Capacity = int64(w.opts.PendingCapacity)
	s.Queued = int64(len(w.pending))
	s.InFlight = int64(len(w.inFlight))
	s.UnsavedItems = int64(s.AcceptedItems - s.CommittedItems - s.AbandonedItems)
	var oldest time.Time
	if len(w.inFlight) > 0 {
		oldest = w.inFlight[0].admitted
	} else if len(w.order) > 0 {
		oldest = w.pending[w.order[0]].admitted
	}
	if !oldest.IsZero() {
		s.OldestAge = time.Since(oldest)
	}
	if !w.lastSuccess.IsZero() {
		s.LastSuccessAge = time.Since(w.lastSuccess)
	}
	return s
}

func (w *usageWriter) run(apply func(context.Context, string, []UsageDelta) error) {
	defer close(w.done)
	defer w.cancel()
	defer func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		left := w.counts.AcceptedItems - w.counts.CommittedItems
		if left > 0 {
			w.counts.AbandonedItems = left
			w.err = fmt.Errorf("cache usage drain incomplete: %d unsaved or unconfirmed hits: %w", left, w.ctx.Err())
		}
		w.pending = nil
		w.order = nil
		w.inFlight = nil
		close(w.changed)
	}()
	ticker := time.NewTicker(w.opts.FlushInterval)
	defer ticker.Stop()
	prefix := rand.Text()
	var seq uint64
	for {
		force := false
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			force = true
		case <-w.wake:
		}
		for {
			if w.ctx.Err() != nil {
				return
			}
			w.mu.Lock()
			if w.closed && len(w.order) == 0 {
				w.mu.Unlock()
				return
			}
			if len(w.order) == 0 || (!force && !w.closed && !w.unfinished(w.flushTo) && len(w.order) < w.opts.BatchSize) {
				w.mu.Unlock()
				break
			}
			n := min(len(w.order), w.opts.BatchSize)
			deltas := make([]UsageDelta, n)
			w.inFlight = make([]pendingUsage, n)
			var hits uint64
			for i, id := range w.order[:n] {
				p := w.pending[id]
				deltas[i] = p.UsageDelta
				w.inFlight[i] = *p
				hits += uint64(p.Hits)
				delete(w.pending, id)
			}
			copy(w.order, w.order[n:])
			w.order = w.order[:len(w.order)-n]
			w.mu.Unlock()
			seq++
			token := fmt.Sprintf("%s-%d", prefix, seq)
			for attempt := 0; ; attempt++ {
				if w.ctx.Err() != nil {
					return
				}
				if attempt > 0 {
					w.mu.Lock()
					w.counts.Retries++
					w.mu.Unlock()
				}
				started := time.Now()
				err := apply(w.ctx, token, deltas)
				elapsed := time.Since(started)
				w.mu.Lock()
				w.counts.CommitTimeTotal += elapsed
				if err != nil {
					w.counts.Failures++
				}
				w.mu.Unlock()
				if err == nil {
					w.mu.Lock()
					w.counts.CommittedItems += hits
					w.counts.Batches++
					w.counts.LastBatchSize = int64(n)
					w.counts.LastCommitDuration = elapsed
					w.lastSuccess = time.Now()
					w.inFlight = nil
					close(w.changed)
					w.changed = make(chan struct{})
					w.mu.Unlock()
					break
				}
				timer := time.NewTimer(w.opts.RetryInterval)
				select {
				case <-w.ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
	}
}
