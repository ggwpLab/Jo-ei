package telemetry

import (
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// aggregate holds the counter tallies shared by lifetime totals and per-day
// buckets. Not safe for concurrent use.
type aggregate struct {
	requests, cacheHits, blocked, errors                  uint64
	supplyBlocked, cveBlocked, malwareBlocked, denylisted uint64
	gates                                                 map[string]*GateCounts
}

func newAggregate() *aggregate {
	return &aggregate{gates: map[string]*GateCounts{
		gate.GateCache:   {},
		gate.GateSupply:  {},
		gate.GateCVE:     {},
		gate.GateMalware: {},
	}}
}

// gatePipeline is the order an artifact clears the scanning gates. A verdict
// at gate i implies a pass at every earlier pipeline gate.
var gatePipeline = []string{gate.GateSupply, gate.GateCVE, gate.GateMalware}

func pipelineIndex(gate string) int {
	for i, g := range gatePipeline {
		if g == gate {
			return i
		}
	}
	return -1
}

// record applies one event to the tallies.
func (a *aggregate) record(ev gate.Event) {
	a.requests++
	switch ev.Verdict {
	case gate.VerdictCache:
		a.cacheHits++
		a.gates[gate.GateCache].Pass++
	case gate.VerdictPass:
		idx := pipelineIndex(ev.Gate)
		if idx < 0 {
			idx = len(gatePipeline) - 1
		}
		for _, g := range gatePipeline[:idx+1] {
			a.gates[g].Pass++
		}
	case gate.VerdictBlock:
		a.blocked++
		if c, ok := a.gates[ev.Gate]; ok {
			c.Block++
		}
		// Pass++ for pipeline gates cleared before the blocking gate.
		// idx > 0 also correctly skips non-pipeline gates (cache → idx -1):
		// a cache-gate block implies no pipeline gate was reached at all.
		if idx := pipelineIndex(ev.Gate); idx > 0 {
			for _, g := range gatePipeline[:idx] {
				a.gates[g].Pass++
			}
		}
		switch {
		case ev.Reason == gate.ReasonDenylisted:
			a.denylisted++
		case ev.Gate == gate.GateSupply:
			a.supplyBlocked++
		case ev.Gate == gate.GateCVE:
			a.cveBlocked++
		case ev.Gate == gate.GateMalware:
			a.malwareBlocked++
		}
	case gate.VerdictError:
		// Errors are infrastructure failures, not gate verdicts: they count
		// toward Errors only and intentionally leave gate tallies untouched.
		a.errors++
	}
}

// add merges o's tallies into a (a += o).
func (a *aggregate) add(o *aggregate) {
	a.requests += o.requests
	a.cacheHits += o.cacheHits
	a.blocked += o.blocked
	a.errors += o.errors
	a.supplyBlocked += o.supplyBlocked
	a.cveBlocked += o.cveBlocked
	a.malwareBlocked += o.malwareBlocked
	a.denylisted += o.denylisted
	for k, v := range o.gates {
		c, ok := a.gates[k]
		if !ok {
			c = &GateCounts{}
			a.gates[k] = c
		}
		c.Pass += v.Pass
		c.Block += v.Block
	}
}

func gatesCopy(src map[string]*GateCounts) map[string]GateCounts {
	out := make(map[string]GateCounts, len(src))
	for k, v := range src {
		out[k] = *v
	}
	return out
}

func (a *aggregate) snapshot(started time.Time) Snapshot {
	return Snapshot{
		StartedAt:      started,
		Requests:       a.requests,
		CacheHits:      a.cacheHits,
		Blocked:        a.blocked,
		Errors:         a.errors,
		SupplyBlocked:  a.supplyBlocked,
		CVEBlocked:     a.cveBlocked,
		MalwareBlocked: a.malwareBlocked,
		Denylisted:     a.denylisted,
		Gates:          gatesCopy(a.gates),
	}
}

func (a *aggregate) dailyMetric(day string) DailyMetric {
	return DailyMetric{
		Day:            day,
		Requests:       a.requests,
		CacheHits:      a.cacheHits,
		Blocked:        a.blocked,
		Errors:         a.errors,
		SupplyBlocked:  a.supplyBlocked,
		CVEBlocked:     a.cveBlocked,
		MalwareBlocked: a.malwareBlocked,
		Denylisted:     a.denylisted,
		Gates:          gatesCopy(a.gates),
	}
}

func gatesToPtr(src map[string]GateCounts) map[string]*GateCounts {
	out := map[string]*GateCounts{
		gate.GateCache: {}, gate.GateSupply: {}, gate.GateCVE: {}, gate.GateMalware: {},
	}
	for k, v := range src {
		vv := v
		out[k] = &vv
	}
	return out
}

func aggregateFromSnapshot(s Snapshot) *aggregate {
	return &aggregate{
		requests: s.Requests, cacheHits: s.CacheHits, blocked: s.Blocked, errors: s.Errors,
		supplyBlocked: s.SupplyBlocked, cveBlocked: s.CVEBlocked,
		malwareBlocked: s.MalwareBlocked, denylisted: s.Denylisted,
		gates: gatesToPtr(s.Gates),
	}
}

func aggregateFromDaily(d DailyMetric) *aggregate {
	return &aggregate{
		requests: d.Requests, cacheHits: d.CacheHits, blocked: d.Blocked, errors: d.Errors,
		supplyBlocked: d.SupplyBlocked, cveBlocked: d.CVEBlocked,
		malwareBlocked: d.MalwareBlocked, denylisted: d.Denylisted,
		gates: gatesToPtr(d.Gates),
	}
}

// dayKey is the UTC calendar-day bucket for an event. A zero event time falls
// back to the current time so malformed events still bucket somewhere.
func dayKey(ev gate.Event) string {
	t := ev.Time
	if t.IsZero() {
		t = time.Now()
	}
	return t.UTC().Format("2006-01-02")
}
