// Package telemetry collects per-request events from the proxy handlers for the
// admin console and persists them to SQLite, the single source of truth. Every
// admitted event is persisted in a background batch; reads query committed
// SQLite state directly. Full or closed queues drop and count incoming events.
package telemetry

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

// GateCounts is the pass/block tally for one gate.
type GateCounts struct {
	Pass  uint64 `json:"pass"`
	Block uint64 `json:"block"`
}

// Snapshot is a point-in-time copy of all counters since process start.
type Snapshot struct {
	StartedAt      time.Time
	Requests       uint64
	CacheHits      uint64
	Blocked        uint64
	Errors         uint64
	SupplyBlocked  uint64
	CVEBlocked     uint64
	MalwareBlocked uint64
	Denylisted     uint64
	Gates          map[string]GateCounts // keys: cache, supply, cve, malware
}

// DailyMetric is one UTC calendar day's tallies.
type DailyMetric struct {
	Day            string                `json:"day"` // UTC YYYY-MM-DD
	Requests       uint64                `json:"requests"`
	CacheHits      uint64                `json:"cache_hits"`
	Blocked        uint64                `json:"blocked"`
	Errors         uint64                `json:"errors"`
	SupplyBlocked  uint64                `json:"supply_blocked"`
	CVEBlocked     uint64                `json:"cve_blocked"`
	MalwareBlocked uint64                `json:"malware_blocked"`
	Denylisted     uint64                `json:"denylisted"`
	Gates          map[string]GateCounts `json:"gates"`
}

// pruneInterval is how often the background loop deletes rows past retention.
// Retention is measured in days, so hourly is ample and cheap.
const pruneInterval = time.Hour

// Store admits owned observations to a bounded writer. Committed state lives
// in the Repo (SQLite); reads never flush pending work. Store also owns uptime
// and periodic retention pruning.
type Store struct {
	repo    Repo
	logger  zerolog.Logger
	started time.Time

	stop chan struct{}
	// pruneCtx is cancelled by Close, aborting a prune in progress.
	pruneCtx    context.Context
	cancelPrune context.CancelFunc
	wg          sync.WaitGroup
	closeOnce   sync.Once
	writer      *telemetryWriter
}

// New returns a Store backed by repo and starts its background prune loop.
func New(repo Repo, logger zerolog.Logger) *Store {
	return newWithWriterOptions(repo, logger, defaultWriterOptions)
}

func newWithWriterOptions(repo Repo, logger zerolog.Logger, opts writerOptions) *Store {
	s := &Store{
		repo:    repo,
		logger:  logger.With().Str("component", "telemetry").Logger(),
		started: time.Now(),
		stop:    make(chan struct{}),
	}
	s.pruneCtx, s.cancelPrune = context.WithCancel(context.Background())
	s.writer = newTelemetryWriter(repo, opts)
	s.wg.Add(1)
	go s.pruneLoop()
	return s
}

// Open builds a SQLite-backed Store on db, applying the telemetry schema.
// Retention values ≤ 0 fall back to defaults (30/365 days).
func Open(db *storage.DB, eventRetentionDays, dailyRetentionDays int, logger zerolog.Logger) (*Store, error) {
	repo, err := NewSQLiteRepo(db, eventRetentionDays, dailyRetentionDays)
	if err != nil {
		return nil, err
	}
	return New(repo, logger), nil
}

// Record admits an owned event without waiting for storage. Full or closed
// queues reject the incoming event and increment in-memory loss counters.
func (s *Store) Record(ev gate.Event) {
	s.writer.record(ev)
}

// RequestFlush wakes the writer without waiting for it.
func (s *Store) RequestFlush() { s.writer.requestFlush() }

// Flush waits for all events accepted before this call, including publication.
// Cancelling the waiter does not cancel admitted work.
func (s *Store) Flush(ctx context.Context) error { return s.writer.flush(ctx) }

// WriterStats reads only in-memory counters, even when SQLite is unavailable.
func (s *Store) WriterStats() storage.WriterStats { return s.writer.stats() }

// Snapshot returns the cumulative counters. A read error logs and yields a
// zero snapshot (the overview must not 500 on a transient read failure).
func (s *Store) Snapshot(ctx context.Context) Snapshot {
	snap, err := s.repo.Snapshot(ctx, s.started)
	if err != nil {
		s.readFailed(err, "reading snapshot")
		return Snapshot{StartedAt: s.started, Gates: map[string]GateCounts{}}
	}
	return snap
}

// Recent returns up to limit events, newest first (limit ≤ 0 → all). A read
// error logs and yields nil.
func (s *Store) Recent(ctx context.Context, limit int) []gate.Event {
	evs, err := s.repo.Recent(ctx, limit)
	if err != nil {
		s.readFailed(err, "reading recent events")
		return nil
	}
	return evs
}

// Page returns up to limit events matching verdict (empty = any) and text (a
// case-insensitive substring of "package@version" or request_id; empty = any), newest-first,
// older than cursor (zero cursor = newest), plus the cursor for the next call
// (zero when there are no more pages). A read error logs and yields nil with a
// zero cursor, so the console degrades to an empty page rather than failing.
func (s *Store) Page(ctx context.Context, verdict, text string, cursor Cursor, limit int) ([]gate.Event, Cursor) {
	evs, next, err := s.repo.Page(ctx, verdict, text, cursor, limit)
	if err != nil {
		s.readFailed(err, "paging events")
		return nil, Cursor{}
	}
	return evs, next
}

// Quarantine returns the active supply-chain holds. A read error logs and
// yields nil.
func (s *Store) Quarantine(ctx context.Context, now time.Time) []gate.Event {
	evs, err := s.repo.Quarantine(ctx, now)
	if err != nil {
		s.readFailed(err, "reading quarantine")
		return nil
	}
	return evs
}

// DailyMetrics returns per-UTC-day tallies, newest first (days ≤ 0 → all).
func (s *Store) DailyMetrics(ctx context.Context, days int) ([]DailyMetric, error) {
	return s.repo.DailyMetrics(ctx, days)
}

// readFailed logs a failed console read. A cancelled request — the console
// aborts in-flight fetches on navigation and while the user types — is not
// worth a warning.
func (s *Store) readFailed(err error, msg string) {
	ev := s.logger.Warn()
	if errors.Is(err, context.Canceled) {
		ev = s.logger.Debug()
	}
	ev.Err(err).Msg(msg)
}

func (s *Store) pruneLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(pruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			// A prune cut short by Close is not a failure.
			if err := s.repo.Prune(s.pruneCtx); err != nil && s.pruneCtx.Err() == nil {
				s.logger.Warn().Err(err).Msg("pruning")
			}
		}
	}
}

// Shutdown stops admissions, drains within ctx, and joins both workers. On
// expiry the error reports admitted events whose commit was not confirmed.
func (s *Store) Shutdown(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.cancelPrune()
		close(s.stop)
		s.wg.Wait()
	})
	return s.writer.shutdown(ctx)
}

// Close uses a bounded drain when application shutdown has not run already.
func (s *Store) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.Shutdown(ctx)
}
