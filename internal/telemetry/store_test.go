package telemetry_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func evt(id, verdict, gate, reason string) proxy.Event {
	return proxy.Event{
		RequestID: id, Time: time.Now(),
		Ecosystem: "pypi", Package: "requests", Version: "2.31.0",
		Verdict: verdict, Gate: gate, Reason: reason,
	}
}

func TestStoreRingOverflowAndOrder(t *testing.T) {
	s := telemetry.NewStore(4)
	for i := 1; i <= 6; i++ {
		s.Record(evt(fmt.Sprintf("r%d", i), proxy.VerdictPass, proxy.GateSupply, "ok"))
	}

	got := s.Recent(10)
	require.Len(t, got, 4, "ring keeps only the last 4")
	assert.Equal(t, "r6", got[0].RequestID, "newest first")
	assert.Equal(t, "r5", got[1].RequestID)
	assert.Equal(t, "r4", got[2].RequestID)
	assert.Equal(t, "r3", got[3].RequestID)

	got = s.Recent(2)
	require.Len(t, got, 2)
	assert.Equal(t, "r6", got[0].RequestID)
}

func TestStoreCounters(t *testing.T) {
	s := telemetry.NewStore(16)
	s.Record(evt("r1", proxy.VerdictCache, proxy.GateCache, "cache_hit"))
	s.Record(evt("r2", proxy.VerdictPass, proxy.GateMalware, "ok"))
	s.Record(evt("r3", proxy.VerdictBlock, proxy.GateCVE, "cve_found"))
	s.Record(evt("r4", proxy.VerdictBlock, proxy.GateCVE, "denylisted"))
	s.Record(evt("r5", proxy.VerdictBlock, proxy.GateSupply, "package_younger_than_min_age"))
	s.Record(evt("r6", proxy.VerdictBlock, proxy.GateMalware, "malware_found"))
	s.Record(evt("r7", proxy.VerdictError, proxy.GateSupply, "upstream_metadata_unavailable"))

	snap := s.Snapshot()
	assert.Equal(t, uint64(7), snap.Requests)
	assert.Equal(t, uint64(1), snap.CacheHits)
	assert.Equal(t, uint64(4), snap.Blocked)
	assert.Equal(t, uint64(1), snap.Errors)
	assert.Equal(t, uint64(1), snap.CVEBlocked)
	assert.Equal(t, uint64(1), snap.Denylisted)
	assert.Equal(t, uint64(1), snap.SupplyBlocked)
	assert.Equal(t, uint64(1), snap.MalwareBlocked)
	assert.False(t, snap.StartedAt.IsZero())

	// Per-gate pipeline accounting (supply → cve → malware):
	// r2 PASS@malware: supply+1 cve+1 malware+1 pass
	// r3,r4 BLOCK@cve: supply+1 each pass, cve+2 block
	// r5 BLOCK@supply: supply+1 block
	// r6 BLOCK@malware: supply+1 cve+1 pass, malware+1 block
	assert.Equal(t, telemetry.GateCounts{Pass: 1, Block: 0}, snap.Gates[proxy.GateCache])
	assert.Equal(t, telemetry.GateCounts{Pass: 4, Block: 1}, snap.Gates[proxy.GateSupply])
	assert.Equal(t, telemetry.GateCounts{Pass: 2, Block: 2}, snap.Gates[proxy.GateCVE])
	assert.Equal(t, telemetry.GateCounts{Pass: 1, Block: 1}, snap.Gates[proxy.GateMalware])
}

func TestStoreCacheScanFailedBlockDoesNotCountPipelinePasses(t *testing.T) {
	s := telemetry.NewStore(4)
	s.Record(evt("r1", proxy.VerdictBlock, proxy.GateCache, "scan_failed"))

	snap := s.Snapshot()
	assert.Equal(t, telemetry.GateCounts{Pass: 0, Block: 1}, snap.Gates[proxy.GateCache])
	assert.Equal(t, telemetry.GateCounts{}, snap.Gates[proxy.GateSupply])
	assert.Equal(t, telemetry.GateCounts{}, snap.Gates[proxy.GateCVE])
}

func TestStoreQuarantine(t *testing.T) {
	now := time.Now()
	s := telemetry.NewStore(16)

	active := evt("r1", proxy.VerdictBlock, proxy.GateSupply, "package_younger_than_min_age")
	active.BlockUntil = now.Add(6 * time.Hour)
	s.Record(active)

	expired := evt("r2", proxy.VerdictBlock, proxy.GateSupply, "package_younger_than_min_age")
	expired.Package = "old-pkg"
	expired.BlockUntil = now.Add(-time.Hour)
	s.Record(expired)

	// Duplicate of the first package — newest wins, deduped by eco/pkg@ver.
	dup := active
	dup.RequestID = "r3"
	s.Record(dup)

	s.Record(evt("r4", proxy.VerdictPass, proxy.GateSupply, "ok"))

	q := s.Quarantine(now)
	require.Len(t, q, 1)
	assert.Equal(t, "r3", q[0].RequestID, "newest duplicate wins")
	assert.Equal(t, "requests", q[0].Package)

	// A newer expired record for the same package hides the older active one:
	// dedup happens before the expiry filter, newest record wins outright.
	gone := active
	gone.RequestID = "r5"
	gone.BlockUntil = now.Add(-time.Minute)
	s.Record(gone)
	assert.Empty(t, s.Quarantine(now))
}

func TestStoreConcurrent(t *testing.T) {
	s := telemetry.NewStore(64)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s.Record(evt(fmt.Sprintf("g%d-%d", g, i), proxy.VerdictPass, proxy.GateSupply, "ok"))
				s.Recent(10)
				s.Snapshot()
				s.Quarantine(time.Now())
			}
		}(g)
	}
	wg.Wait()
	assert.Equal(t, uint64(1600), s.Snapshot().Requests)
}
