package telemetry

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

type writerOptions struct {
	QueueCapacity, BatchSize     int
	FlushInterval, RetryInterval time.Duration
}

var defaultWriterOptions = writerOptions{1024, 128, 10 * time.Second, time.Second}

type queuedEvent struct {
	BatchEvent
	admitted time.Time
}

type telemetryWriter struct {
	mu              sync.Mutex
	queue, inFlight []queuedEvent
	opts            writerOptions
	counts          storage.WriterStats
	closed          bool
	flushTo         uint64
	changed         chan struct{}
	wake            chan struct{}
	done            chan struct{}
	ctx             context.Context
	cancel          context.CancelFunc
	err             error
	lastSuccess     time.Time
	publish         func(gate.Event)
}

func newTelemetryWriter(repo Repo, opts writerOptions) *telemetryWriter {
	w := &telemetryWriter{opts: opts, queue: make([]queuedEvent, 0, opts.QueueCapacity), changed: make(chan struct{}), wake: make(chan struct{}, 1), done: make(chan struct{})}
	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.lastSuccess = time.Now()
	go w.run(repo)
	return w
}

// record never holds the admission lock across I/O, logging or publication.
// The capacity check precedes copying variable-sized event findings.
func (w *telemetryWriter) record(ev gate.Event) {
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.counts.AttemptedItems++
	if w.closed {
		w.counts.DroppedClosedItems++
		return
	}
	if len(w.queue) == w.opts.QueueCapacity {
		w.counts.DroppedFullItems++
		w.flushTo = w.counts.AcceptedItems
		w.signal()
		return
	}
	ev.BlockedBy = slices.Clone(ev.BlockedBy)
	ev.CVEs = slices.Clone(ev.CVEs)
	for i := range ev.CVEs {
		ev.CVEs[i].Aliases = slices.Clone(ev.CVEs[i].Aliases)
	}
	dayTime := ev.Time
	if dayTime.IsZero() {
		dayTime = now
	}
	w.queue = append(w.queue, queuedEvent{BatchEvent: BatchEvent{Event: ev, Day: dayTime.UTC().Format(time.DateOnly)}, admitted: now})
	w.counts.AcceptedItems++
	if len(w.queue) >= w.opts.BatchSize {
		w.signal()
	}
}

func (w *telemetryWriter) signal() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}
func (w *telemetryWriter) requestFlush() {
	w.mu.Lock()
	w.flushTo = w.counts.AcceptedItems
	w.signal()
	w.mu.Unlock()
}

func (w *telemetryWriter) flush(ctx context.Context) error {
	w.mu.Lock()
	target := w.counts.AcceptedItems
	w.flushTo = target
	w.signal()
	for w.counts.CommittedItems < target {
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
	w.mu.Unlock()
	return nil
}

func (w *telemetryWriter) shutdown(ctx context.Context) error {
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

func (w *telemetryWriter) stats() storage.WriterStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.counts
	s.Capacity = int64(w.opts.QueueCapacity)
	s.Queued = int64(len(w.queue))
	s.InFlight = int64(len(w.inFlight))
	s.UnsavedItems = int64(s.AcceptedItems - s.CommittedItems - s.AbandonedItems)
	var oldest time.Time
	if len(w.inFlight) > 0 {
		oldest = w.inFlight[0].admitted
	} else if len(w.queue) > 0 {
		oldest = w.queue[0].admitted
	}
	if !oldest.IsZero() {
		s.OldestAge = time.Since(oldest)
	}
	if !w.lastSuccess.IsZero() {
		s.LastSuccessAge = time.Since(w.lastSuccess)
	}
	return s
}

func (w *telemetryWriter) run(repo Repo) {
	defer close(w.done)
	defer w.cancel()
	defer func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		left := w.counts.AcceptedItems - w.counts.CommittedItems
		if left > 0 {
			w.counts.AbandonedItems = left
			w.err = fmt.Errorf("telemetry drain incomplete: %d unsaved or unconfirmed events: %w", left, w.ctx.Err())
		}
		clear(w.queue)
		w.queue = nil
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
			if w.closed && len(w.queue) == 0 {
				w.mu.Unlock()
				return
			}
			if len(w.queue) == 0 || (!force && !w.closed && w.flushTo <= w.counts.CommittedItems && len(w.queue) < w.opts.BatchSize) {
				w.mu.Unlock()
				break
			}
			n := min(len(w.queue), w.opts.BatchSize)
			batch := make([]BatchEvent, n)
			w.inFlight = append([]queuedEvent(nil), w.queue[:n]...)
			for i := range batch {
				batch[i] = w.inFlight[i].BatchEvent
			}
			copy(w.queue, w.queue[n:])
			clear(w.queue[len(w.queue)-n:])
			w.queue = w.queue[:len(w.queue)-n]
			publish := w.publish
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
				err := repo.RecordBatch(w.ctx, token, batch)
				elapsed := time.Since(started)
				w.mu.Lock()
				w.counts.CommitTimeTotal += elapsed
				if err != nil {
					w.counts.Failures++
				}
				w.mu.Unlock()
				if err == nil {
					if publish != nil {
						for _, item := range batch {
							publish(item.Event)
						}
					}
					w.mu.Lock()
					w.counts.CommittedItems += uint64(n)
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
