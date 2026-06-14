package telemetry

import "github.com/ggwpLab/Jo-ei/internal/proxy"

// State is the persisted telemetry restored at startup.
type State struct {
	// Lifetime holds the cumulative counters. Its StartedAt is ignored on load
	// (uptime tracks the current process, not stored time).
	Lifetime Snapshot
	// HasLifetime is false when no counters row existed yet (fresh DB).
	HasLifetime bool
	// Today is the current UTC day's row if one was already persisted, else nil.
	Today *DailyMetric
	// Events are the most recent events, oldest first, to reseed the ring buffer.
	Events []proxy.Event
}

// Repo persists and restores telemetry. A nil Repo means in-memory only.
// Implementations must be safe for use from the Store's single writer goroutine
// and concurrent DailyMetrics reads from HTTP handlers.
type Repo interface {
	// LoadState restores counters, today's daily row, and up to eventLimit recent
	// events (oldest first).
	LoadState(eventLimit int) (State, error)
	// AppendEvents persists a batch of events.
	AppendEvents(evs []proxy.Event) error
	// Flush upserts the cumulative counters row and the given daily rows.
	Flush(lifetime Snapshot, daily []DailyMetric) error
	// Prune deletes events and daily rows older than the configured retention.
	Prune() error
	// DailyMetrics returns per-UTC-day rows, newest first (days<=0 → all).
	DailyMetrics(days int) ([]DailyMetric, error)
}
