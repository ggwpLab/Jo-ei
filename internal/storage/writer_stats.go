package storage

import "time"

// WriterStats is an in-memory observation of a background writer. Item counts
// mean events for telemetry and hits for usage; queue/batch sizes mean rows.
type WriterStats struct {
	Capacity, Queued, InFlight, UnsavedItems, LastBatchSize             int64
	AttemptedItems, AcceptedItems, DroppedFullItems, DroppedClosedItems uint64
	AbandonedItems, CommittedItems, Batches, Failures, Retries          uint64
	OldestAge, LastSuccessAge, CommitTimeTotal, LastCommitDuration      time.Duration
}
