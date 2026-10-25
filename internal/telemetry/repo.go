package telemetry

import (
	"context"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// Cursor is a keyset position in the event log — the (ts, id) of a row under
// the canonical ORDER BY ts DESC, id DESC. The zero Cursor means "start from
// the newest event". id is the SQLite rowid (>= 1), so ID == 0 is the sentinel.
type Cursor struct {
	TS time.Time
	ID int64
}

// Zero reports whether c is the start-from-newest sentinel.
func (c Cursor) Zero() bool { return c.ID == 0 }

// Repo persists and retrieves telemetry. SQLite is the single source of truth;
// there is no in-memory implementation. Implementations are safe for concurrent
// use (calls serialize on a single SQLite connection).
type Repo interface {
	// RecordEvent durably persists one event and applies its tallies to the
	// cumulative counters and the event's UTC-day metrics row, atomically.
	RecordEvent(ev gate.Event) error
	// Snapshot returns the cumulative counters, stamped with started as StartedAt.
	Snapshot(ctx context.Context, started time.Time) (Snapshot, error)
	// Recent returns up to limit events, newest first. limit <= 0 means all.
	Recent(ctx context.Context, limit int) ([]gate.Event, error)
	// Page returns up to limit events with the given verdict (empty = any)
	// whose "package@version" or request_id contains text (case-insensitive,
	// literal substring; empty = any), newest-first, strictly older than cursor. A zero cursor starts at the
	// newest matching event. The second return is the cursor of the last row
	// returned; it is the zero Cursor when there are no more pages.
	// When limit <= 0 all matching rows are returned in one call; the second
	// return is then the cursor of the last row (non-zero if any rows exist),
	// but no further rows exist beyond it.
	Page(ctx context.Context, verdict, text string, cursor Cursor, limit int) ([]gate.Event, Cursor, error)
	// Quarantine returns active supply-chain holds (newest BLOCK@supply per
	// eco/pkg@ver whose block_until is after now), newest first.
	Quarantine(ctx context.Context, now time.Time) ([]gate.Event, error)
	// DailyMetrics returns per-UTC-day rows, newest first (days <= 0 → all).
	DailyMetrics(ctx context.Context, days int) ([]DailyMetric, error)
	// Prune deletes events and daily rows older than the configured retention.
	Prune(ctx context.Context) error
}
