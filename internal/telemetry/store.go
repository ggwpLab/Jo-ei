// Package telemetry collects per-request events from the proxy handlers for
// the admin console: an in-memory ring buffer plus aggregate counters.
// History is process-lifetime only and is lost on restart by design.
package telemetry

import (
	"sync"
	"time"

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

// Store keeps the last N events in a ring buffer plus aggregate counters.
// Record never returns an error and never blocks beyond the mutex.
type Store struct {
	mu      sync.RWMutex
	buf     []proxy.Event
	next    int // next write index
	count   int // filled slots, ≤ len(buf)
	started time.Time

	requests, cacheHits, blocked, errors                  uint64
	supplyBlocked, cveBlocked, malwareBlocked, denylisted uint64
	gates                                                 map[string]*GateCounts
}

// NewStore creates a Store holding the last capacity events.
func NewStore(capacity int) *Store {
	return &Store{
		buf:     make([]proxy.Event, capacity),
		started: time.Now(),
		gates: map[string]*GateCounts{
			proxy.GateCache:   {},
			proxy.GateSupply:  {},
			proxy.GateCVE:     {},
			proxy.GateMalware: {},
		},
	}
}

// gatePipeline is the order an artifact clears the scanning gates. A verdict
// at gate i implies a pass at every earlier pipeline gate.
var gatePipeline = []string{proxy.GateSupply, proxy.GateCVE, proxy.GateMalware}

func pipelineIndex(gate string) int {
	for i, g := range gatePipeline {
		if g == gate {
			return i
		}
	}
	return -1
}

// Record stores ev and updates counters. Safe for concurrent use.
func (s *Store) Record(ev proxy.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.buf[s.next] = ev
	s.next = (s.next + 1) % len(s.buf)
	if s.count < len(s.buf) {
		s.count++
	}

	s.requests++
	switch ev.Verdict {
	case proxy.VerdictCache:
		s.cacheHits++
		s.gates[proxy.GateCache].Pass++
	case proxy.VerdictPass:
		idx := pipelineIndex(ev.Gate)
		if idx < 0 {
			idx = len(gatePipeline) - 1
		}
		for _, g := range gatePipeline[:idx+1] {
			s.gates[g].Pass++
		}
	case proxy.VerdictBlock:
		s.blocked++
		if c, ok := s.gates[ev.Gate]; ok {
			c.Block++
		}
		if idx := pipelineIndex(ev.Gate); idx > 0 {
			for _, g := range gatePipeline[:idx] {
				s.gates[g].Pass++
			}
		}
		switch {
		case ev.Reason == "denylisted":
			s.denylisted++
		case ev.Gate == proxy.GateSupply:
			s.supplyBlocked++
		case ev.Gate == proxy.GateCVE:
			s.cveBlocked++
		case ev.Gate == proxy.GateMalware:
			s.malwareBlocked++
		}
	case proxy.VerdictError:
		s.errors++
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
	gates := make(map[string]GateCounts, len(s.gates))
	for k, v := range s.gates {
		gates[k] = *v
	}
	return Snapshot{
		StartedAt:      s.started,
		Requests:       s.requests,
		CacheHits:      s.cacheHits,
		Blocked:        s.blocked,
		Errors:         s.errors,
		SupplyBlocked:  s.supplyBlocked,
		CVEBlocked:     s.cveBlocked,
		MalwareBlocked: s.malwareBlocked,
		Denylisted:     s.denylisted,
		Gates:          gates,
	}
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
