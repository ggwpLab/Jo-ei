package telemetry

import (
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// Repo persists and retrieves telemetry. SQLite is the single source of truth;
// there is no in-memory implementation. Implementations are safe for concurrent
// use (calls serialize on a single SQLite connection).
type Repo interface {
	// RecordEvent durably persists one event and applies its tallies to the
	// cumulative counters and the event's UTC-day metrics row, atomically.
	RecordEvent(ev proxy.Event) error
	// Snapshot returns the cumulative counters, stamped with started as StartedAt.
	Snapshot(started time.Time) (Snapshot, error)
	// Recent returns up to limit events, newest first. limit <= 0 means all.
	Recent(limit int) ([]proxy.Event, error)
	// Quarantine returns active supply-chain holds (newest BLOCK@supply per
	// eco/pkg@ver whose block_until is after now), newest first.
	Quarantine(now time.Time) ([]proxy.Event, error)
	// DailyMetrics returns per-UTC-day rows, newest first (days <= 0 → all).
	DailyMetrics(days int) ([]DailyMetric, error)
	// Prune deletes events and daily rows older than the configured retention.
	Prune() error
}
