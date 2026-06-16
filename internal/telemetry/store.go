// Package telemetry collects per-request events from the proxy handlers for the
// admin console and persists them to SQLite, the single source of truth. Every
// Record is durable at write time; reads query SQLite directly. There is no
// in-memory mode.
package telemetry

import (
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
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

// Store is a thin façade over a Repo. All telemetry state lives in the Repo
// (SQLite). Store adds the process start time (for uptime) and a periodic prune.
type Store struct {
	repo    Repo
	logger  zerolog.Logger
	started time.Time

	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// New returns a Store backed by repo and starts its background prune loop.
func New(repo Repo, logger zerolog.Logger) *Store {
	s := &Store{
		repo:    repo,
		logger:  logger,
		started: time.Now(),
		stop:    make(chan struct{}),
	}
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

// Record durably persists ev (insert + counter/daily increments) synchronously.
// Telemetry must never fail a proxy request: on error it logs and returns,
// losing at most this one event (not a flush window).
func (s *Store) Record(ev proxy.Event) {
	if err := s.repo.RecordEvent(ev); err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: recording event")
	}
}

// Snapshot returns the cumulative counters. A read error logs and yields a
// zero snapshot (the overview must not 500 on a transient read failure).
func (s *Store) Snapshot() Snapshot {
	snap, err := s.repo.Snapshot(s.started)
	if err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: reading snapshot")
		return Snapshot{StartedAt: s.started, Gates: map[string]GateCounts{}}
	}
	return snap
}

// Recent returns up to limit events, newest first (limit ≤ 0 → all). A read
// error logs and yields nil.
func (s *Store) Recent(limit int) []proxy.Event {
	evs, err := s.repo.Recent(limit)
	if err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: reading recent events")
		return nil
	}
	return evs
}

// Quarantine returns the active supply-chain holds. A read error logs and
// yields nil.
func (s *Store) Quarantine(now time.Time) []proxy.Event {
	evs, err := s.repo.Quarantine(now)
	if err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: reading quarantine")
		return nil
	}
	return evs
}

// DailyMetrics returns per-UTC-day tallies, newest first (days ≤ 0 → all).
func (s *Store) DailyMetrics(days int) ([]DailyMetric, error) {
	return s.repo.DailyMetrics(days)
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
			if err := s.repo.Prune(); err != nil {
				s.logger.Warn().Err(err).Msg("telemetry: pruning")
			}
		}
	}
}

// Close stops the prune loop. Safe to call multiple times.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
	})
	return nil
}
