// Package health probes scan engines for liveness and latency and exposes a
// snapshot for the admin console. It is protocol-agnostic: liveness checks are
// injected as closures, so this package does not import internal/scanner.
package health

import "time"

// Status is a scan engine's health classification.
type Status string

const (
	StatusOK      Status = "ok"      // reachable, latency within threshold
	StatusWarn    Status = "warn"    // reachable but slow (latency over threshold)
	StatusDown    Status = "down"    // last check failed
	StatusUnknown Status = "unknown" // not checked yet / no traffic yet
	StatusOff     Status = "off"     // configured but not attached by the active profile
)

// Sample is one raw liveness observation, before classification.
type Sample struct {
	OK      bool          // last check/scan succeeded
	Latency time.Duration // observed round-trip
	HasData bool          // false means "never checked" → unknown
}

// ScannerHealth is the per-engine record surfaced in GET /api/overview.
type ScannerHealth struct {
	Name      string `json:"name"`
	Detail    string `json:"detail"`
	Enabled   bool   `json:"enabled"`
	Status    Status `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
}

// classify maps a raw Sample to a Status + latency in milliseconds. A slow
// threshold of zero disables the warn state.
func classify(s Sample, slow time.Duration) (Status, int64) {
	if !s.HasData {
		return StatusUnknown, 0
	}
	ms := s.Latency.Milliseconds()
	if !s.OK {
		return StatusDown, ms
	}
	if slow > 0 && s.Latency > slow {
		return StatusWarn, ms
	}
	return StatusOK, ms
}
