// Package revalidate periodically re-runs the gates over cached artifacts and
// evicts any that now produce a definitive block verdict.
package revalidate

import (
	"context"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// Outcome is the per-entry decision a Revalidator returns.
type Outcome int

const (
	Keep  Outcome = iota // still clean → bump last_validated
	Evict                // definitive non-clean verdict → remove + record event
	Retry                // could not check (scanner down) → leave untouched
)

// EvictReason carries why an entry was evicted, for telemetry.
type EvictReason struct {
	Gate      string // gate.GateCVE | GateMalware | GateImageScan | GateSupply
	Reason    string // "cve_found" | "malware_found" | "denylisted" | ...
	BlockedBy string // "cve" | "malware" | "denylist" | "supply_chain"
	Engine    string // malware engine, when applicable
	Signature string // malware signature, when applicable
	Findings  []gate.CVEFinding
}

// Revalidator re-runs the applicable checks for one cached entry.
type Revalidator interface {
	Revalidate(ctx context.Context, e cache.RevalEntry) (Outcome, *EvictReason)
}

// RevalidationStore is the slice of the cache the sweep depends on.
// *cache.LocalCache satisfies it.
type RevalidationStore interface {
	DueForRevalidation(before int64, limit int) ([]cache.RevalEntry, error)
	MarkValidated(ref *gate.PackageRef, ts int64) error
	Invalidate(ref *gate.PackageRef) error
}

// Config tunes the sweep loop.
type Config struct {
	Interval        time.Duration // how often the sweep ticks
	RevalidateAfter time.Duration // an entry is due when now-last_validated > this
	BatchSize       int           // max entries processed per tick
}
