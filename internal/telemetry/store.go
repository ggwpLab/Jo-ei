// Package telemetry collects per-request events from the proxy handlers for
// the admin console: an in-memory ring buffer plus aggregate counters.
// When a Repo is provided via NewPersistentStore, history is seeded from and
// persisted to the backing store across restarts.
package telemetry

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
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

// Store keeps the last N events in a ring buffer plus aggregate counters.
// Record never returns an error and never blocks beyond the mutex.
type Store struct {
	mu      sync.RWMutex
	buf     []proxy.Event
	next    int // next write index
	count   int // filled slots, ≤ len(buf)
	started time.Time

	lifetime *aggregate
	daily    map[string]*aggregate // key: UTC YYYY-MM-DD

	// Persistence (nil repo ⇒ in-memory only).
	repo       Repo
	logger     zerolog.Logger
	eventCh    chan proxy.Event
	stop       chan struct{}
	wg         sync.WaitGroup
	closeOnce  sync.Once
	flushEvery time.Duration
}

// NewStore creates a Store holding the last capacity events.
func NewStore(capacity int) *Store {
	if capacity < 1 {
		capacity = 1
	}
	return &Store{
		buf:      make([]proxy.Event, capacity),
		started:  time.Now(),
		lifetime: newAggregate(),
		daily:    map[string]*aggregate{},
	}
}

const (
	persistFlushInterval = 10 * time.Second
	persistEventBuffer   = 1024
)

// NewPersistentStore creates a Store backed by repo: it seeds in-memory state
// from repo.LoadState, then runs a background writer that batches event inserts
// and periodically flushes counters + daily rows. Close performs a final flush.
func NewPersistentStore(capacity int, repo Repo, logger zerolog.Logger) (*Store, error) {
	s := NewStore(capacity)
	s.repo = repo
	s.logger = logger
	s.eventCh = make(chan proxy.Event, persistEventBuffer)
	s.stop = make(chan struct{})
	s.flushEvery = persistFlushInterval

	state, err := repo.LoadState(capacity)
	if err != nil {
		return nil, fmt.Errorf("loading telemetry state: %w", err)
	}
	s.seed(state)

	s.wg.Add(1)
	go s.writer()
	return s, nil
}

// seed loads persisted state into the in-memory model without re-counting.
func (s *Store) seed(state State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.HasLifetime {
		s.lifetime = aggregateFromSnapshot(state.Lifetime)
	}
	if state.Today != nil {
		s.daily[state.Today.Day] = aggregateFromDaily(*state.Today)
	}
	for _, ev := range state.Events { // oldest first
		s.buf[s.next] = ev
		s.next = (s.next + 1) % len(s.buf)
		if s.count < len(s.buf) {
			s.count++
		}
	}
}

// Record stores ev and updates counters. Safe for concurrent use.
func (s *Store) Record(ev proxy.Event) {
	s.mu.Lock()
	s.buf[s.next] = ev
	s.next = (s.next + 1) % len(s.buf)
	if s.count < len(s.buf) {
		s.count++
	}
	s.lifetime.record(ev)
	day := dayKey(ev)
	d := s.daily[day]
	if d == nil {
		d = newAggregate()
		s.daily[day] = d
	}
	d.record(ev)
	s.mu.Unlock()

	if s.repo != nil {
		select {
		case s.eventCh <- ev:
		default: // queue full: event counted in memory; skip persistence
		}
	}
}

// Recent returns up to limit events, newest first. limit ≤ 0 means all.
func (s *Store) Recent(limit int) []proxy.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > s.count {
		limit = s.count
	}
	out := make([]proxy.Event, 0, limit)
	for i := 1; i <= limit; i++ {
		out = append(out, s.buf[(s.next-i+len(s.buf))%len(s.buf)])
	}
	return out
}

// Snapshot returns a copy of all counters.
func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lifetime.snapshot(s.started)
}

// DailyMetrics returns per-UTC-day tallies, newest day first. days<=0 returns
// all known days; otherwise the most recent days. When a repo is present its
// data is preferred (it includes rows flushed by previous processes).
// When persistence is enabled, today's row is read from storage and may lag the
// live Snapshot total by up to one flush interval (10s); that is by design.
func (s *Store) DailyMetrics(days int) ([]DailyMetric, error) {
	if s.repo != nil {
		return s.repo.DailyMetrics(days)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DailyMetric, 0, len(s.daily))
	for day, a := range s.daily {
		out = append(out, a.dailyMetric(day))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day > out[j].Day })
	if days > 0 && len(out) > days {
		out = out[:days]
	}
	return out, nil
}

// Quarantine derives the active supply-chain holds from the buffer: BLOCK
// events at the supply gate whose BlockUntil is still in the future, newest
// first. Deduplication by eco/pkg@ver happens before the expiry filter, so
// the newest record for a package decides whether it is held at all.
// Quarantine is derived, not stored — expired entries simply stop matching.
func (s *Store) Quarantine(now time.Time) []proxy.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	var out []proxy.Event
	for i := 1; i <= s.count; i++ {
		ev := s.buf[(s.next-i+len(s.buf))%len(s.buf)]
		if ev.Verdict != proxy.VerdictBlock || ev.Gate != proxy.GateSupply {
			continue
		}
		key := ev.Ecosystem + "/" + ev.Package + "@" + ev.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		if !ev.BlockUntil.After(now) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// inMemoryDaily returns all in-memory day buckets as DailyMetric (for flushing).
func (s *Store) inMemoryDaily() []DailyMetric {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DailyMetric, 0, len(s.daily))
	for day, a := range s.daily {
		out = append(out, a.dailyMetric(day))
	}
	return out
}

// evictOldDaily drops in-memory day buckets other than today after they are
// durably flushed, bounding memory for long-running processes.
func (s *Store) evictOldDaily() {
	today := time.Now().UTC().Format("2006-01-02")
	s.mu.Lock()
	defer s.mu.Unlock()
	for day := range s.daily {
		if day != today {
			delete(s.daily, day)
		}
	}
}

func (s *Store) flush(pending []proxy.Event) {
	if len(pending) > 0 {
		if err := s.repo.AppendEvents(pending); err != nil {
			s.logger.Warn().Err(err).Msg("telemetry: persisting events")
		}
	}
	if err := s.repo.Flush(s.Snapshot(), s.inMemoryDaily()); err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: flushing counters/daily")
	}
	if err := s.repo.Prune(); err != nil {
		s.logger.Warn().Err(err).Msg("telemetry: pruning")
	}
	s.evictOldDaily()
}

func (s *Store) writer() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.flushEvery)
	defer ticker.Stop()
	var pending []proxy.Event
	for {
		select {
		case <-s.stop:
			for {
				select {
				case ev := <-s.eventCh:
					pending = append(pending, ev)
					continue
				default:
				}
				break
			}
			s.flush(pending)
			return
		case ev := <-s.eventCh:
			pending = append(pending, ev)
		case <-ticker.C:
			s.flush(pending)
			pending = nil
		}
	}
}

// Close stops the writer after a final flush. Safe to call once; extra calls are
// no-ops. In-memory-only stores (no repo) need no Close, but calling it is safe.
func (s *Store) Close() error {
	if s.repo == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
	})
	return nil
}
