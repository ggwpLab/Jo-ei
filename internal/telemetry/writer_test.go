package telemetry

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

type batchDecorator struct {
	Repo
	write func(context.Context, string, []BatchEvent) error
}

func (r batchDecorator) RecordBatch(ctx context.Context, token string, events []BatchEvent) error {
	return r.write(ctx, token, events)
}
func writerRepo(t *testing.T) Repo {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "events.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	r, err := NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)
	return r
}
func writerTestOptions() writerOptions {
	return writerOptions{QueueCapacity: 2, BatchSize: 1, FlushInterval: time.Hour, RetryInterval: time.Millisecond}
}
func awaitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not reach handshake")
	}
}
func flushWriter(t *testing.T, s *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, s.Flush(ctx))
}

func TestWriter_FullQueueDropsIncomingWithoutWaiting(t *testing.T) {
	for _, verdict := range []string{gate.VerdictPass, gate.VerdictCache, gate.VerdictBlock, gate.VerdictError} {
		t.Run(verdict, func(t *testing.T) {
			real := writerRepo(t)
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			var once sync.Once
			r := batchDecorator{Repo: real, write: func(ctx context.Context, token string, ev []BatchEvent) error {
				once.Do(func() { entered <- struct{}{} })
				select {
				case <-release:
					return real.RecordBatch(ctx, token, ev)
				case <-ctx.Done():
					return ctx.Err()
				}
			}}
			s := newWithWriterOptions(r, zerolog.Nop(), writerTestOptions())
			t.Cleanup(func() { _ = s.Close() })
			defer close(release)
			b := NewBroadcaster()
			hub := NewHub(s, b)
			ch, unsubscribe := b.Subscribe()
			defer unsubscribe()
			hub.Record(gate.Event{RequestID: "one", Verdict: verdict})
			awaitSignal(t, entered)
			select {
			case <-ch:
				t.Fatal("published before commit")
			default:
			}
			for _, id := range []string{"two", "three"} {
				hub.Record(gate.Event{RequestID: id, Verdict: verdict})
			}
			returned := make(chan struct{})
			go func() { hub.Record(gate.Event{RequestID: "dropped", Verdict: verdict}); close(returned) }()
			awaitSignal(t, returned)
			stats := s.WriterStats()
			assert.Equal(t, int64(2), stats.Queued)
			assert.Equal(t, int64(1), stats.InFlight)
			assert.Equal(t, uint64(1), stats.DroppedFullItems)
			// Flush cancellation cancels the waiter, never accepted work.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			require.ErrorIs(t, s.Flush(ctx), context.Canceled)
			release <- struct{}{}
			release <- struct{}{}
			release <- struct{}{}
			flushWriter(t, s)
			for _, id := range []string{"one", "two", "three"} {
				select {
				case ev := <-ch:
					assert.Equal(t, id, ev.RequestID)
				case <-time.After(time.Second):
					t.Fatal("missing committed publication")
				}
			}
			got, err := real.Recent(context.Background(), 0)
			require.NoError(t, err)
			assert.Len(t, got, 3)
			stats = s.WriterStats()
			assert.Equal(t, uint64(4), stats.AttemptedItems)
			assert.Equal(t, uint64(3), stats.CommittedItems)
			assert.Zero(t, stats.UnsavedItems)
		})
	}
}

func TestWriter_OwnsNestedEventDataAndDay(t *testing.T) {
	real := writerRepo(t)
	opts := writerTestOptions()
	opts.BatchSize = 10
	s := newWithWriterOptions(real, zerolog.Nop(), opts)
	defer s.Close()
	ev := gate.Event{RequestID: "owned", Time: time.Date(2026, 11, 6, 23, 59, 59, 0, time.UTC), BlockedBy: []string{"cve"}, CVEs: []gate.CVEFinding{{ID: "original", Aliases: []string{"alias"}}}}
	s.Record(ev)
	ev.BlockedBy[0] = "changed"
	ev.CVEs[0].ID = "changed"
	ev.CVEs[0].Aliases[0] = "changed"
	s.Record(gate.Event{RequestID: "zero"})
	flushWriter(t, s)
	got, err := real.Recent(context.Background(), 0)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, []string{"cve"}, got[0].BlockedBy)
	assert.Equal(t, "original", got[0].CVEs[0].ID)
	assert.Equal(t, []string{"alias"}, got[0].CVEs[0].Aliases)
	assert.True(t, got[1].Time.IsZero())
	days, err := real.DailyMetrics(context.Background(), 0)
	require.NoError(t, err)
	require.Len(t, days, 2)
	assert.Equal(t, "2026-11-06", days[1].Day)
}

func TestWriter_AmbiguousCommitRetriesSameToken(t *testing.T) {
	real := writerRepo(t)
	var tokens []string
	r := batchDecorator{Repo: real, write: func(ctx context.Context, token string, ev []BatchEvent) error {
		tokens = append(tokens, token)
		err := real.RecordBatch(ctx, token, ev)
		if len(tokens) == 1 && err == nil {
			return errors.New("acknowledgement lost")
		}
		return err
	}}
	s := newWithWriterOptions(r, zerolog.Nop(), writerTestOptions())
	defer s.Close()
	b := NewBroadcaster()
	h := NewHub(s, b)
	ch, cancel := b.Subscribe()
	defer cancel()
	h.Record(gate.Event{RequestID: "once", Verdict: gate.VerdictCache})
	flushWriter(t, s)
	require.Len(t, tokens, 2)
	assert.Equal(t, tokens[0], tokens[1])
	assert.Equal(t, uint64(1), s.Snapshot(context.Background()).Requests)
	assert.Equal(t, uint64(1), s.WriterStats().Retries)
	select {
	case e := <-ch:
		assert.Equal(t, "once", e.RequestID)
	default:
		t.Fatal("missing publication")
	}
	select {
	case <-ch:
		t.Fatal("duplicate publication")
	default:
	}
}

func TestWriter_TimerAndClosedAdmission(t *testing.T) {
	real := writerRepo(t)
	opts := writerTestOptions()
	opts.BatchSize = 10
	opts.FlushInterval = time.Millisecond
	s := newWithWriterOptions(real, zerolog.Nop(), opts)
	defer s.Close()
	b := NewBroadcaster()
	h := NewHub(s, b)
	ch, cancel := b.Subscribe()
	defer cancel()
	h.Record(gate.Event{RequestID: "timer"})
	select {
	case ev := <-ch:
		assert.Equal(t, "timer", ev.RequestID)
	case <-time.After(5 * time.Second):
		t.Fatal("timer never flushed")
	}
	require.NoError(t, s.Shutdown(context.Background()))
	s.Record(gate.Event{})
	assert.Equal(t, uint64(1), s.WriterStats().DroppedClosedItems)
	require.NoError(t, s.Close())
}

func TestWriter_ShutdownCancelsFailedCommitAndCountsAbandoned(t *testing.T) {
	entered := make(chan struct{}, 1)
	r := batchDecorator{write: func(ctx context.Context, _ string, _ []BatchEvent) error {
		entered <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}}
	s := newWithWriterOptions(r, zerolog.Nop(), writerTestOptions())
	s.Record(gate.Event{})
	awaitSignal(t, entered)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.Error(t, s.Shutdown(ctx))
	stats := s.WriterStats()
	assert.Equal(t, uint64(1), stats.AbandonedItems)
	assert.Zero(t, stats.UnsavedItems)
	returned := make(chan struct{})
	go func() { s.Record(gate.Event{}); close(returned) }()
	awaitSignal(t, returned)
	assert.Equal(t, uint64(1), s.WriterStats().DroppedClosedItems)
}

func TestWriter_OverflowRequestsFlushBelowBatchSize(t *testing.T) {
	real := writerRepo(t)
	opts := writerTestOptions()
	opts.QueueCapacity = 1
	opts.BatchSize = 128
	s := newWithWriterOptions(real, zerolog.Nop(), opts)
	defer s.Close()
	b := NewBroadcaster()
	h := NewHub(s, b)
	ch, cancel := b.Subscribe()
	defer cancel()
	h.Record(gate.Event{RequestID: "accepted"})
	h.Record(gate.Event{RequestID: "overflow"})
	select {
	case ev := <-ch:
		assert.Equal(t, "accepted", ev.RequestID)
	case <-time.After(time.Second):
		t.Fatal("overflow did not prompt a flush")
	}
	assert.Equal(t, uint64(1), s.WriterStats().DroppedFullItems)
}

type observedWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *observedWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestWriter_FlushFencesAcceptedWatermark(t *testing.T) {
	real := writerRepo(t)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	r := batchDecorator{Repo: real, write: func(ctx context.Context, token string, events []BatchEvent) error {
		entered <- struct{}{}
		select {
		case <-release:
			return real.RecordBatch(ctx, token, events)
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	s := newWithWriterOptions(r, zerolog.Nop(), writerTestOptions())
	defer s.Close()
	defer close(release)
	s.Record(gate.Event{RequestID: "first"})
	awaitSignal(t, entered)
	ctx := &observedWaitContext{Context: context.Background(), entered: make(chan struct{})}
	flushed := make(chan struct{})
	go func() { defer close(flushed); _ = s.Flush(ctx) }()
	awaitSignal(t, ctx.entered)
	s.Record(gate.Event{RequestID: "later"})
	release <- struct{}{}
	awaitSignal(t, entered)
	awaitSignal(t, flushed)
	assert.Equal(t, int64(1), s.WriterStats().UnsavedItems)
}

type blockedProducerLog struct {
	release chan struct{}
	calls   atomic.Int32
}

func (l *blockedProducerLog) Write(p []byte) (int, error) {
	l.calls.Add(1)
	<-l.release
	return len(p), nil
}

func TestWriter_RejectedLargeEventDoesNotCopyOrLog(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	log := &blockedProducerLog{release: make(chan struct{})}
	r := batchDecorator{write: func(ctx context.Context, _ string, _ []BatchEvent) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	opts := writerTestOptions()
	opts.QueueCapacity = 1
	s := newWithWriterOptions(r, zerolog.New(log), opts)
	defer s.Close()
	defer close(release)
	defer close(log.release)
	s.Record(gate.Event{})
	awaitSignal(t, entered)
	s.Record(gate.Event{})
	large := gate.Event{Verdict: gate.VerdictBlock, BlockedBy: make([]string, 1000), CVEs: make([]gate.CVEFinding, 1000)}
	for i := range large.CVEs {
		large.CVEs[i].Aliases = make([]string, 10)
	}
	returned := make(chan struct{})
	go func() { s.Record(large); close(returned) }()
	awaitSignal(t, returned)
	assert.Zero(t, testing.AllocsPerRun(100, func() { s.Record(large) }), "rejected payload must not be cloned or delegated to another goroutine")
	assert.Zero(t, log.calls.Load(), "drop path attempted synchronous logging")
}
