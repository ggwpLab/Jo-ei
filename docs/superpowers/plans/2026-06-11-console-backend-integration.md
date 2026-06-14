# Console–Backend Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the embedded admin console (`web/console/`) to live proxy state: real request feed, KPIs, per-gate counters, quarantine, cache stats, registries, and a working runtime policy editor — replacing the client-side mock data.

**Architecture:** The handler emits one `proxy.Event` per intercepted request via an optional `Recorder` interface. A new `internal/telemetry` package stores the last 500 events in a ring buffer with aggregate counters and fans new events out to SSE subscribers. A new `internal/console` package serves a small JSON API over that state plus a `policy.Runtime` wrapper that holds the current `policy.Engine`/`supplychain.Filter` behind an `atomic.Pointer` so `PUT /api/policy` swaps both without restart. The SPA's `data.js` mock is replaced by `api.js` which fetches the REST endpoints and subscribes to `EventSource('/api/events')`.

**Tech Stack:** Go 1.25 stdlib only (no new deps; `net/http` 1.22+ method patterns are available), zerolog, testify; React 18 + Babel from CDN (unchanged this phase).

**Spec:** `docs/superpowers/specs/2026-06-11-console-backend-integration-design.md`

---

## File structure

| File | Responsibility |
|---|---|
| `internal/proxy/recorder.go` (new) | `Event` struct, verdict/gate constants, `Recorder` interface (declared in `proxy` like `ArtifactCache` to avoid import cycles) |
| `internal/proxy/handler.go` (modify) | optional `Recorder` in `HandlerConfig`; emit exactly one event per intercepted request outcome |
| `internal/proxy/recorder_test.go` (new) | handler emission tests with a fake recorder + fake scanners |
| `internal/telemetry/store.go` (new) | ring buffer (N=500), counters, quarantine derivation; `RWMutex`-guarded |
| `internal/telemetry/store_test.go` (new) | overflow/ordering, counters, quarantine, concurrency under `-race` |
| `internal/telemetry/broadcaster.go` (new) | SSE fan-out with non-blocking publish + `Hub` (the `proxy.Recorder` that feeds both) |
| `internal/telemetry/broadcaster_test.go` (new) | subscribe/cancel, slow-client drop, Hub |
| `internal/supplychain/filter.go` (modify) | add `(*Allowlist).Entries()` so the runtime can merge file entries |
| `internal/policy/runtime.go` (new) | `Runtime` atomic-swap wrapper, `RuntimeParams`, validation |
| `internal/policy/runtime_test.go` (new) | swap visibility, validation, file-allowlist merge, concurrency |
| `internal/console/server.go` (new) | HTTP API: overview, requests, events (SSE), quarantine, policy GET/PUT, registries |
| `internal/console/events.go` (new) | `proxy.Event` → wire JSON mapping (mirrors `data.js` field names) |
| `internal/console/server_test.go` (new) | httptest coverage of every endpoint |
| `cmd/jo-ei/main.go` (modify) | construct Store/Broadcaster/Hub/Runtime, mount `/api/` |
| `integration/console_test.go` (new) | end-to-end: requests → events → API; PUT policy changes live verdicts |
| `web/console/api.js` (new) | live API client populating `window.JOEI`; replaces `data.js` (deleted) |
| `web/console/*.jsx`, `index.html`, `screens.css` (modify) | drop mock-only widgets, live updates, working policy editor, connection banner |
| `README.md` (modify) | console API section + "no auth" known risk |

Conventions to hold across tasks: verdicts `PASS|CACHE|BLOCK|ERROR`; gates `cache|supply|cve|malware`; `blocked_by` vocabulary `supply_chain|cve|malware|denylist` (matches `GATE_LABEL` keys already in the SPA); ERROR events set `Gate` to the stage that failed (upstream metadata/download → `supply`, CVE scanner → `cve`, AV scanner → `malware`, cache store → `cache`).

---

### Task 1: `proxy.Event` + `Recorder` interface

**Files:**
- Create: `internal/proxy/recorder.go`

Pure type declarations — no behavior to test on its own; the contract is exercised by Tasks 2 and 6.

- [ ] **Step 1: Create `internal/proxy/recorder.go`**

```go
package proxy

import "time"

// Verdict values recorded for an intercepted request.
const (
	VerdictPass  = "PASS"
	VerdictCache = "CACHE"
	VerdictBlock = "BLOCK"
	VerdictError = "ERROR"
)

// Gate identifiers. For BLOCK events: the gate that blocked. For ERROR
// events: the stage that failed. For PASS events: the deepest gate the
// artifact cleared.
const (
	GateCache   = "cache"
	GateSupply  = "supply"
	GateCVE     = "cve"
	GateMalware = "malware"
)

// Event is one telemetry record per intercepted request outcome. Field
// semantics mirror the console's request objects (web/console).
type Event struct {
	RequestID  string
	Time       time.Time
	Ecosystem  string
	Package    string
	Version    string
	Verdict    string // PASS | CACHE | BLOCK | ERROR
	Gate       string // cache | supply | cve | malware
	LatencyMS  int64
	HTTPStatus int
	Reason     string
	BlockedBy  []string // "supply_chain" | "cve" | "malware" | "denylist"

	// CVE block details.
	CVEs []CVEFinding

	// Malware block details.
	MalwareEngine    string
	MalwareSignature string

	// Supply-chain details (also set on PASS when metadata was fetched).
	PublishedAt time.Time
	BlockUntil  time.Time // non-zero only for supply-chain blocks
}

// Recorder receives telemetry events. Implementations must be safe for
// concurrent use and must never block or fail the proxy data path: Record
// returns nothing. Defined here (like ArtifactCache) to avoid the import
// cycle proxy → telemetry → proxy; telemetry.Hub satisfies it structurally.
type Recorder interface {
	Record(Event)
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./...`
Expected: clean exit, no output.

- [ ] **Step 3: Commit**

```bash
git add internal/proxy/recorder.go
git commit -m "feat(proxy): add telemetry Event type and Recorder interface"
```

---

### Task 2: `telemetry.Store` — ring buffer + counters + quarantine

**Files:**
- Create: `internal/telemetry/store.go`
- Test: `internal/telemetry/store_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/telemetry/store_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/telemetry/ -v`
Expected: FAIL — package does not exist / undefined symbols.

- [ ] **Step 3: Implement `internal/telemetry/store.go`**

```go
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
```

- [ ] **Step 4: Run tests with the race detector**

Run: `go test ./internal/telemetry/ -race -v`
Expected: PASS (all 5 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/telemetry/store.go internal/telemetry/store_test.go
git commit -m "feat(telemetry): event ring buffer with counters and derived quarantine"
```

---

### Task 3: `telemetry.Broadcaster` + `Hub`

**Files:**
- Create: `internal/telemetry/broadcaster.go`
- Test: `internal/telemetry/broadcaster_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/telemetry/broadcaster_test.go`:

```go
package telemetry_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func TestBroadcasterDeliversToAllSubscribers(t *testing.T) {
	b := telemetry.NewBroadcaster()
	ch1, cancel1 := b.Subscribe()
	ch2, cancel2 := b.Subscribe()
	defer cancel1()
	defer cancel2()

	b.Publish(evt("r1", proxy.VerdictPass, proxy.GateSupply, "ok"))

	for _, ch := range []<-chan proxy.Event{ch1, ch2} {
		select {
		case got := <-ch:
			assert.Equal(t, "r1", got.RequestID)
		case <-time.After(time.Second):
			t.Fatal("subscriber did not receive event")
		}
	}
}

func TestBroadcasterCancelStopsDelivery(t *testing.T) {
	b := telemetry.NewBroadcaster()
	ch, cancel := b.Subscribe()
	cancel()
	cancel() // idempotent

	b.Publish(evt("r1", proxy.VerdictPass, proxy.GateSupply, "ok"))

	_, open := <-ch
	assert.False(t, open, "cancelled subscriber channel is closed")
}

func TestBroadcasterSlowSubscriberLosesEventsWithoutBlocking(t *testing.T) {
	b := telemetry.NewBroadcaster()
	ch, cancel := b.Subscribe()
	defer cancel()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ { // far beyond any buffer
			b.Publish(evt("r", proxy.VerdictPass, proxy.GateSupply, "ok"))
		}
		close(done)
	}()

	select {
	case <-done: // publisher never stalls on the full channel
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow subscriber")
	}
	assert.LessOrEqual(t, len(ch), 16, "slow subscriber only buffers up to its channel depth")
}

func TestHubRecordsAndPublishes(t *testing.T) {
	store := telemetry.NewStore(8)
	b := telemetry.NewBroadcaster()
	hub := &telemetry.Hub{Store: store, Broadcaster: b}
	ch, cancel := b.Subscribe()
	defer cancel()

	hub.Record(evt("r1", proxy.VerdictCache, proxy.GateCache, "cache_hit"))

	require.Len(t, store.Recent(0), 1)
	select {
	case got := <-ch:
		assert.Equal(t, "r1", got.RequestID)
	case <-time.After(time.Second):
		t.Fatal("hub did not publish")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/telemetry/ -run 'Broadcaster|Hub' -v`
Expected: FAIL — undefined: telemetry.NewBroadcaster, telemetry.Hub.

- [ ] **Step 3: Implement `internal/telemetry/broadcaster.go`**

```go
package telemetry

import (
	"sync"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// subscriberBuffer is the per-subscriber channel depth. A subscriber whose
// channel is full misses events rather than stalling the publisher.
const subscriberBuffer = 16

// Broadcaster fans out events to live subscribers (SSE handlers).
// Publish never blocks.
type Broadcaster struct {
	mu   sync.Mutex
	subs map[chan proxy.Event]struct{}
}

// NewBroadcaster creates an empty Broadcaster.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{subs: map[chan proxy.Event]struct{}{}}
}

// Subscribe registers a subscriber. The returned cancel func releases it and
// closes the channel; calling cancel more than once is safe.
func (b *Broadcaster) Subscribe() (<-chan proxy.Event, func()) {
	ch := make(chan proxy.Event, subscriberBuffer)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	cancel := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
	}
	return ch, cancel
}

// Publish delivers ev to every subscriber with buffer room; slow subscribers
// lose the event so the proxy data path never stalls.
func (b *Broadcaster) Publish(ev proxy.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Hub is the proxy.Recorder wired into handlers: it stores the event and
// fans it out to live subscribers.
type Hub struct {
	Store       *Store
	Broadcaster *Broadcaster
}

// Record implements proxy.Recorder.
func (h *Hub) Record(ev proxy.Event) {
	h.Store.Record(ev)
	h.Broadcaster.Publish(ev)
}
```

- [ ] **Step 4: Run the full telemetry suite with race detector**

Run: `go test ./internal/telemetry/ -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/telemetry/broadcaster.go internal/telemetry/broadcaster_test.go
git commit -m "feat(telemetry): SSE broadcaster with slow-client drop and Recorder hub"
```

---

### Task 4: `supplychain.Allowlist.Entries()`

**Files:**
- Modify: `internal/supplychain/filter.go` (add one method after `Contains`, ~line 43)
- Test: `internal/supplychain/filter_test.go` (append)

- [ ] **Step 1: Write the failing test** — append to `internal/supplychain/filter_test.go`:

```go
func TestAllowlistEntries(t *testing.T) {
	a := supplychain.NewAllowlist([]string{"pypi/requests", " npm/lodash@4.17.21 "})
	assert.Equal(t, []string{"npm/lodash@4.17.21", "pypi/requests"}, a.Entries())

	var nilList *supplychain.Allowlist
	assert.Nil(t, nilList.Entries())
}
```

(If the test file's package or imports differ, match them; it needs `supplychain` and `assert`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/supplychain/ -run TestAllowlistEntries -v`
Expected: FAIL — `a.Entries undefined`.

- [ ] **Step 3: Implement** — add to `internal/supplychain/filter.go` after `Contains` (add `"sort"` to imports):

```go
// Entries returns a sorted copy of the allowlist entries, for merging with
// runtime-added entries. Nil-safe.
func (a *Allowlist) Entries() []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.entries))
	for e := range a.entries {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/supplychain/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/supplychain/filter.go internal/supplychain/filter_test.go
git commit -m "feat(supplychain): expose allowlist entries for runtime policy merge"
```

---

### Task 5: `policy.Runtime` — atomic policy swap

**Files:**
- Create: `internal/policy/runtime.go`
- Test: `internal/policy/runtime_test.go`

The wrapper implements both `proxy.PolicyDecider` and `proxy.SCFilter`, so it slots into the existing `HandlerConfig.Filter`/`Policy` fields without handler changes. `policy` importing `supplychain` introduces no cycle (`supplychain` imports only `config` and `proxy`).

- [ ] **Step 1: Write the failing tests**

Create `internal/policy/runtime_test.go`:

```go
package policy_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

func newRuntime(t *testing.T, fileAllow []string) *policy.Runtime {
	t.Helper()
	return policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{Enabled: true, BlockOn: "CRITICAL"},
		config.PolicyProfile{CVEBlock: true},
		fileAllow,
	)
}

func freshMeta() *proxy.PackageMetadata {
	return &proxy.PackageMetadata{PublishedAt: time.Now().Add(-1 * time.Hour)}
}

// rtRef reuses the ref(eco, name, ver) helper already defined in
// engine_test.go (same package policy_test) — do not redeclare ref here.
func rtRef() *proxy.PackageRef {
	return ref("pypi", "requests", "2.31.0")
}

func highFinding() *proxy.ScanResult {
	return &proxy.ScanResult{Findings: []proxy.CVEFinding{{ID: "CVE-1", Severity: proxy.SeverityHigh}}}
}

func TestRuntimeBootFromConfig(t *testing.T) {
	r := newRuntime(t, nil)
	p := r.Current()
	assert.Equal(t, "enforce", p.Mode)
	assert.Equal(t, 24, p.MinAgeHours)
	assert.Equal(t, "CRITICAL", p.CVEBlockOn)
	assert.Empty(t, p.Allowlist)
	assert.Empty(t, p.Denylist)
}

func TestRuntimeApplySwapsCVEThreshold(t *testing.T) {
	r := newRuntime(t, nil)
	assert.True(t, r.Evaluate(rtRef(), highFinding()).Allowed, "HIGH below CRITICAL threshold")

	p := r.Current()
	p.CVEBlockOn = "HIGH"
	require.NoError(t, r.Apply(p))

	d := r.Evaluate(rtRef(), highFinding())
	assert.False(t, d.Allowed)
	assert.Equal(t, "cve_found", d.Reason)
}

func TestRuntimeApplySwapsSupplyChain(t *testing.T) {
	r := newRuntime(t, nil)
	res := r.Check(context.Background(), rtRef(), freshMeta())
	assert.False(t, res.Allowed, "1h-old package blocked by 24h min age")

	p := r.Current()
	p.MinAgeHours = 0
	require.NoError(t, r.Apply(p))
	assert.True(t, r.Check(context.Background(), rtRef(), freshMeta()).Allowed)

	p.MinAgeHours = 24
	p.Mode = "dry_run"
	require.NoError(t, r.Apply(p))
	res = r.Check(context.Background(), rtRef(), freshMeta())
	assert.True(t, res.Allowed)
	assert.Equal(t, "dry_run", res.Reason)
}

func TestRuntimeApplyDenylist(t *testing.T) {
	r := newRuntime(t, nil)
	p := r.Current()
	p.Denylist = []string{"pypi/requests"}
	require.NoError(t, r.Apply(p))

	d := r.Evaluate(rtRef(), &proxy.ScanResult{Clean: true})
	assert.False(t, d.Allowed)
	assert.Equal(t, "denylisted", d.Reason)
}

func TestRuntimeApplyValidation(t *testing.T) {
	r := newRuntime(t, nil)
	before := r.Current()

	cases := []struct {
		field string
		mut   func(*policy.RuntimeParams)
	}{
		{"mode", func(p *policy.RuntimeParams) { p.Mode = "yolo" }},
		{"min_age_hours", func(p *policy.RuntimeParams) { p.MinAgeHours = -1 }},
		{"cve_block_on", func(p *policy.RuntimeParams) { p.CVEBlockOn = "SEVERE" }},
		{"allowlist[0]", func(p *policy.RuntimeParams) { p.Allowlist = []string{"no-slash"} }},
		{"denylist[0]", func(p *policy.RuntimeParams) { p.Denylist = []string{"/noeco"} }},
	}
	for _, tc := range cases {
		p := r.Current()
		tc.mut(&p)
		err := r.Apply(p)
		var verr *policy.ValidationError
		require.ErrorAs(t, err, &verr, "field %s", tc.field)
		assert.Equal(t, tc.field, verr.Field)
		assert.Equal(t, before, r.Current(), "policy unchanged after invalid Apply")
	}
}

func TestRuntimeFileAllowlistAlwaysMerged(t *testing.T) {
	r := newRuntime(t, []string{"pypi/requests"})
	res := r.Check(context.Background(), rtRef(), freshMeta())
	assert.True(t, res.Allowed)
	assert.Equal(t, "allowlisted", res.Reason)

	// Runtime edit with an empty allowlist must not drop the file entries.
	p := r.Current()
	p.Allowlist = []string{}
	require.NoError(t, r.Apply(p))
	assert.Equal(t, "allowlisted", r.Check(context.Background(), rtRef(), freshMeta()).Reason)
}

func TestRuntimeConcurrentApplyAndEvaluate(t *testing.T) {
	r := newRuntime(t, nil)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			p := r.Current()
			p.MinAgeHours = i % 48
			_ = r.Apply(p)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			r.Evaluate(rtRef(), highFinding())
			r.Check(context.Background(), rtRef(), freshMeta())
		}
	}()
	wg.Wait()
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -run TestRuntime -v`
Expected: FAIL — undefined: policy.NewRuntime, policy.RuntimeParams, policy.ValidationError.

- [ ] **Step 3: Implement `internal/policy/runtime.go`**

```go
package policy

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

// RuntimeParams are the console-editable policy knobs (PUT /api/policy).
type RuntimeParams struct {
	Mode        string   `json:"mode"`          // supply-chain mode: enforce | dry_run | off
	MinAgeHours int      `json:"min_age_hours"` // supply-chain minimum age, ≥ 0
	CVEBlockOn  string   `json:"cve_block_on"`  // CRITICAL | HIGH | MEDIUM | LOW
	Allowlist   []string `json:"allowlist"`     // "eco/name[@version]"
	Denylist    []string `json:"denylist"`
}

// ValidationError names the parameter that failed validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type runtimeSnapshot struct {
	engine *Engine
	filter *supplychain.Filter
	params RuntimeParams
}

// Runtime holds the current policy Engine and supply-chain Filter behind an
// atomic pointer so the console can swap both without restart. It implements
// proxy.PolicyDecider and proxy.SCFilter. Edits are runtime-only: the YAML
// config wins again after a restart.
type Runtime struct {
	cur       atomic.Pointer[runtimeSnapshot]
	cveCfg    config.CVEConfig
	profile   config.PolicyProfile
	fileAllow []string // supply_chain.allowlist_path entries, immutable
}

// NewRuntime builds the boot snapshot from config. fileAllow entries are
// always honored by the supply-chain filter regardless of runtime edits.
func NewRuntime(sc config.SupplyChainConfig, cve config.CVEConfig, profile config.PolicyProfile, fileAllow []string) *Runtime {
	blockOn := cve.BlockOn
	if profile.CVEMinSeverity != "" {
		blockOn = profile.CVEMinSeverity
	}
	r := &Runtime{cveCfg: cve, profile: profile, fileAllow: fileAllow}
	r.install(RuntimeParams{
		Mode:        sc.Mode,
		MinAgeHours: sc.MinAgeHours,
		CVEBlockOn:  blockOn,
		Allowlist:   append([]string{}, profile.Allowlist...),
		Denylist:    append([]string{}, profile.Denylist...),
	})
	return r
}

// install builds a fresh Engine/Filter pair for p and swaps it in atomically;
// there is no partial application.
func (r *Runtime) install(p RuntimeParams) {
	merged := append(append([]string{}, r.fileAllow...), p.Allowlist...)
	filter := supplychain.NewFilter(
		config.SupplyChainConfig{Mode: p.Mode, MinAgeHours: p.MinAgeHours},
		supplychain.NewAllowlist(merged),
	)
	prof := r.profile
	prof.CVEMinSeverity = p.CVEBlockOn
	prof.Allowlist = p.Allowlist
	prof.Denylist = p.Denylist
	r.cur.Store(&runtimeSnapshot{
		engine: NewEngine(r.cveCfg, prof),
		filter: filter,
		params: p,
	})
}

var validModes = map[string]bool{"enforce": true, "dry_run": true, "off": true}
var validSeverities = map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}

// Apply validates p and atomically swaps the active policy. On error the
// current policy is unchanged.
func (r *Runtime) Apply(p RuntimeParams) error {
	if !validModes[p.Mode] {
		return &ValidationError{Field: "mode", Message: fmt.Sprintf("must be enforce, dry_run or off (got %q)", p.Mode)}
	}
	if p.MinAgeHours < 0 {
		return &ValidationError{Field: "min_age_hours", Message: "must be >= 0"}
	}
	if !validSeverities[p.CVEBlockOn] {
		return &ValidationError{Field: "cve_block_on", Message: fmt.Sprintf("must be CRITICAL, HIGH, MEDIUM or LOW (got %q)", p.CVEBlockOn)}
	}
	for i, e := range p.Allowlist {
		if msg := validateListEntry(e); msg != "" {
			return &ValidationError{Field: fmt.Sprintf("allowlist[%d]", i), Message: msg}
		}
	}
	for i, e := range p.Denylist {
		if msg := validateListEntry(e); msg != "" {
			return &ValidationError{Field: fmt.Sprintf("denylist[%d]", i), Message: msg}
		}
	}
	if p.Allowlist == nil {
		p.Allowlist = []string{}
	}
	if p.Denylist == nil {
		p.Denylist = []string{}
	}
	r.install(p)
	return nil
}

// validateListEntry checks the "ecosystem/name[@version]" shape; returns a
// message on failure, "" when valid.
func validateListEntry(e string) string {
	eco, rest, ok := strings.Cut(strings.TrimSpace(e), "/")
	if !ok || eco == "" || rest == "" {
		return fmt.Sprintf("entry %q must be ecosystem/name or ecosystem/name@version", e)
	}
	return ""
}

// Current returns a copy of the active params.
func (r *Runtime) Current() RuntimeParams {
	p := r.cur.Load().params
	p.Allowlist = append([]string{}, p.Allowlist...)
	p.Denylist = append([]string{}, p.Denylist...)
	return p
}

// Evaluate implements proxy.PolicyDecider against the current snapshot.
func (r *Runtime) Evaluate(ref *proxy.PackageRef, result *proxy.ScanResult) proxy.PolicyDecision {
	return r.cur.Load().engine.Evaluate(ref, result)
}

// Check implements proxy.SCFilter against the current snapshot.
func (r *Runtime) Check(ctx context.Context, ref *proxy.PackageRef, meta *proxy.PackageMetadata) proxy.FilterResult {
	return r.cur.Load().filter.Check(ctx, ref, meta)
}
```

- [ ] **Step 4: Run tests with race detector**

Run: `go test ./internal/policy/ -race -v`
Expected: PASS (new Runtime tests and the existing engine tests).

- [ ] **Step 5: Commit**

```bash
git add internal/policy/runtime.go internal/policy/runtime_test.go
git commit -m "feat(policy): runtime policy with atomic engine/filter swap and validation"
```

---

### Task 6: handler instrumentation — emit events

**Files:**
- Modify: `internal/proxy/handler.go` (`HandlerConfig` ~line 37, `ServeHTTP` lines 68–194)
- Test: `internal/proxy/recorder_test.go` (new)

- [ ] **Step 1: Write the failing tests**

Create `internal/proxy/recorder_test.go` (package `proxy_test`; reuses `makeUpstream`, `fakeCache`, `mockScanner` (CVE), and `mockAVScanner` already defined in `handler_test.go` — do not redeclare them):

```go
package proxy_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

type fakeRecorder struct {
	mu     sync.Mutex
	events []proxy.Event
}

func (f *fakeRecorder) Record(ev proxy.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

func (f *fakeRecorder) last(t *testing.T) proxy.Event {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.events, "expected at least one recorded event")
	return f.events[len(f.events)-1]
}

// recorderProxy builds a test proxy with a fakeRecorder attached. Extra
// scanners are optional.
func recorderProxy(t *testing.T, upstream *httptest.Server, mode string, cve proxy.CVEScanner, pol proxy.PolicyDecider, av proxy.AVScanner) (*httptest.Server, *fakeRecorder) {
	t.Helper()
	rec := &fakeRecorder{}
	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:     supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: mode}, nil),
		Cache:      newFakeCache(),
		Logger:     zerolog.Nop(),
		CVEScanner: cve,
		Policy:     pol,
		AVScanner:  av,
		Recorder:   rec,
	})
	return httptest.NewServer(handler), rec
}

func TestRecorder_PassEvent(t *testing.T) {
	upstream := makeUpstream(t, "requests", "2.31.0", 48)
	defer upstream.Close()
	srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	ev := rec.last(t)
	assert.Equal(t, proxy.VerdictPass, ev.Verdict)
	assert.Equal(t, proxy.GateSupply, ev.Gate, "no scanners configured → supply is the deepest gate")
	assert.Equal(t, "ok", ev.Reason)
	assert.Equal(t, "pypi", ev.Ecosystem)
	assert.Equal(t, "requests", ev.Package)
	assert.Equal(t, "2.31.0", ev.Version)
	assert.Equal(t, http.StatusOK, ev.HTTPStatus)
	assert.NotEmpty(t, ev.RequestID)
	assert.False(t, ev.PublishedAt.IsZero())
	assert.GreaterOrEqual(t, ev.LatencyMS, int64(0))
}

func TestRecorder_CacheHitEvent(t *testing.T) {
	upstream := makeUpstream(t, "requests", "2.31.0", 48)
	defer upstream.Close()
	srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, nil)
	defer srv.Close()

	url := srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl"
	for i := 0; i < 2; i++ {
		resp, err := http.Get(url)
		require.NoError(t, err)
		resp.Body.Close()
	}

	ev := rec.last(t)
	assert.Equal(t, proxy.VerdictCache, ev.Verdict)
	assert.Equal(t, proxy.GateCache, ev.Gate)
	assert.Equal(t, "cache_hit", ev.Reason)
}

func TestRecorder_SupplyBlockEvent(t *testing.T) {
	upstream := makeUpstream(t, "fresh-pkg", "1.0.0", 1) // 1h old < 24h min age
	defer upstream.Close()
	srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/f/fresh-pkg/fresh_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusLocked, resp.StatusCode)

	ev := rec.last(t)
	assert.Equal(t, proxy.VerdictBlock, ev.Verdict)
	assert.Equal(t, proxy.GateSupply, ev.Gate)
	assert.Equal(t, http.StatusLocked, ev.HTTPStatus)
	assert.Equal(t, []string{"supply_chain"}, ev.BlockedBy)
	assert.False(t, ev.PublishedAt.IsZero())
	assert.False(t, ev.BlockUntil.IsZero())
}

func TestRecorder_CVEBlockEvent(t *testing.T) {
	upstream := makeUpstream(t, "vuln-pkg", "1.0.0", 48)
	defer upstream.Close()
	scanner := &mockScanner{result: &proxy.ScanResult{
		Findings: []proxy.CVEFinding{{ID: "CVE-2024-0001", Severity: proxy.SeverityCritical, Summary: "bad"}},
	}}
	engine := policy.NewEngine(config.CVEConfig{BlockOn: "HIGH"}, config.PolicyProfile{CVEBlock: true})
	srv, rec := recorderProxy(t, upstream, "enforce", scanner, engine, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/v/vuln-pkg/vuln_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	ev := rec.last(t)
	assert.Equal(t, proxy.VerdictBlock, ev.Verdict)
	assert.Equal(t, proxy.GateCVE, ev.Gate)
	assert.Equal(t, "cve_found", ev.Reason)
	assert.Equal(t, []string{"cve"}, ev.BlockedBy)
	require.Len(t, ev.CVEs, 1)
	assert.Equal(t, "CVE-2024-0001", ev.CVEs[0].ID)
}

func TestRecorder_DenylistBlockEvent(t *testing.T) {
	upstream := makeUpstream(t, "evil-pkg", "1.0.0", 48)
	defer upstream.Close()
	scanner := &mockScanner{result: &proxy.ScanResult{Clean: true}}
	engine := policy.NewEngine(config.CVEConfig{BlockOn: "HIGH"},
		config.PolicyProfile{CVEBlock: true, Denylist: []string{"pypi/evil-pkg"}})
	srv, rec := recorderProxy(t, upstream, "enforce", scanner, engine, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/e/evil-pkg/evil_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	ev := rec.last(t)
	assert.Equal(t, "denylisted", ev.Reason)
	assert.Equal(t, []string{"denylist"}, ev.BlockedBy)
}

func TestRecorder_MalwareBlockEvent(t *testing.T) {
	upstream := makeUpstream(t, "trojan", "1.0.0", 48)
	defer upstream.Close()
	av := &mockAVScanner{result: &proxy.AVResult{Clean: false, Engine: "clamav", Signature: "Eicar-Test"}}
	srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, av)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/t/trojan/trojan-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	ev := rec.last(t)
	assert.Equal(t, proxy.VerdictBlock, ev.Verdict)
	assert.Equal(t, proxy.GateMalware, ev.Gate)
	assert.Equal(t, "malware_found", ev.Reason)
	assert.Equal(t, []string{"malware"}, ev.BlockedBy)
	assert.Equal(t, "clamav", ev.MalwareEngine)
	assert.Equal(t, "Eicar-Test", ev.MalwareSignature)
}

func TestRecorder_ErrorEvents(t *testing.T) {
	t.Run("metadata unavailable → supply", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer upstream.Close()
		srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, nil)
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/packages/py3/p/pkg/pkg-1.0.0-py3-none-any.whl")
		require.NoError(t, err)
		resp.Body.Close()

		ev := rec.last(t)
		assert.Equal(t, proxy.VerdictError, ev.Verdict)
		assert.Equal(t, proxy.GateSupply, ev.Gate)
		assert.Equal(t, "upstream_metadata_unavailable", ev.Reason)
	})

	t.Run("cve scanner error → cve", func(t *testing.T) {
		upstream := makeUpstream(t, "pkg", "1.0.0", 48)
		defer upstream.Close()
		scanner := &mockScanner{err: fmt.Errorf("osv.dev unavailable")}
		srv, rec := recorderProxy(t, upstream, "enforce", scanner, nil, nil)
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/packages/py3/p/pkg/pkg-1.0.0-py3-none-any.whl")
		require.NoError(t, err)
		resp.Body.Close()

		ev := rec.last(t)
		assert.Equal(t, proxy.VerdictError, ev.Verdict)
		assert.Equal(t, proxy.GateCVE, ev.Gate)
		assert.Equal(t, "cve_scan_error", ev.Reason)
	})

	t.Run("av scanner error → malware", func(t *testing.T) {
		upstream := makeUpstream(t, "pkg", "1.0.0", 48)
		defer upstream.Close()
		av := &mockAVScanner{err: fmt.Errorf("clamd unavailable")}
		srv, rec := recorderProxy(t, upstream, "enforce", nil, nil, av)
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/packages/py3/p/pkg/pkg-1.0.0-py3-none-any.whl")
		require.NoError(t, err)
		resp.Body.Close()

		ev := rec.last(t)
		assert.Equal(t, proxy.VerdictError, ev.Verdict)
		assert.Equal(t, proxy.GateMalware, ev.Gate)
		assert.Equal(t, "av_scan_error", ev.Reason)
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/ -run TestRecorder -v`
Expected: FAIL — `unknown field Recorder in struct literal of type proxy.HandlerConfig`.

- [ ] **Step 3: Add the `Recorder` field to `HandlerConfig`**

In `internal/proxy/handler.go`, extend the struct (line 37):

```go
// HandlerConfig groups dependencies for the ProxyHandler.
type HandlerConfig struct {
	Adapter    RegistryAdapter
	Filter     SCFilter
	Cache      ArtifactCache
	Logger     zerolog.Logger
	CVEScanner CVEScanner    // optional; nil disables CVE scanning
	Policy     PolicyDecider // optional; nil allows all when CVEScanner is set
	AVScanner  AVScanner     // optional; nil disables malware scanning
	Recorder   Recorder      // optional; nil disables telemetry
}
```

- [ ] **Step 4: Replace `ServeHTTP` with the instrumented version**

Replace the entire `ServeHTTP` method (lines 68–194) with:

```go
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()

	ref, isDownload := h.cfg.Adapter.NormalizeRequest(r)
	if !isDownload {
		// Metadata / simple API — proxy transparently, no interception
		h.proxyTransparent(w, r)
		return
	}

	// Telemetry: exactly one event per intercepted request at its outcome.
	// A nil Recorder makes record a no-op; telemetry can never fail a request.
	start := time.Now()
	record := func(verdict, gate, reason string, status int, mod func(*Event)) {
		if h.cfg.Recorder == nil {
			return
		}
		ev := Event{
			RequestID: requestID, Time: time.Now(),
			Ecosystem: ref.Ecosystem, Package: ref.Name, Version: ref.Version,
			Verdict: verdict, Gate: gate, Reason: reason,
			HTTPStatus: status, LatencyMS: time.Since(start).Milliseconds(),
		}
		if mod != nil {
			mod(&ev)
		}
		h.cfg.Recorder.Record(ev)
	}

	log := h.cfg.Logger.With().
		Str("request_id", requestID).
		Str("package", ref.Key()).
		Logger()

	// Check cache first
	if entry, found := h.cfg.Cache.Get(ref); found {
		if !entry.ScanClean {
			// Fail-closed: cached entry has failed scan result
			record(VerdictBlock, GateCache, "scan_failed", http.StatusForbidden, nil)
			h.writeError(w, requestID, ref, http.StatusForbidden, "scan_failed")
			return
		}
		log.Debug().Msg("cache hit")
		record(VerdictCache, GateCache, "cache_hit", http.StatusOK, nil)
		h.serveFromCache(w, entry)
		return
	}

	// Fetch upstream metadata for supply chain check
	ctx := r.Context()
	meta, err := h.cfg.Adapter.FetchMetadata(ctx, ref)
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch upstream metadata")
		record(VerdictError, GateSupply, "upstream_metadata_unavailable", http.StatusBadGateway, nil)
		h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_metadata_unavailable")
		return
	}

	// Supply chain filter
	scResult := h.cfg.Filter.Check(ctx, ref, meta)
	if !scResult.Allowed {
		log.Warn().
			Str("reason", scResult.Reason).
			Time("published_at", scResult.PublishedAt).
			Time("block_until", scResult.BlockUntil).
			Msg("supply chain filter blocked package")
		record(VerdictBlock, GateSupply, scResult.Reason, http.StatusLocked, func(ev *Event) {
			ev.BlockedBy = []string{"supply_chain"}
			ev.PublishedAt = scResult.PublishedAt
			ev.BlockUntil = scResult.BlockUntil
		})
		h.writeBlockedResponse(w, requestID, ref, scResult)
		return
	}
	if scResult.Reason == "dry_run" {
		log.Warn().
			Time("published_at", scResult.PublishedAt).
			Time("block_until", scResult.BlockUntil).
			Msg("dry_run: package would be blocked by supply chain filter")
	}

	// CVE scan — before downloading the artifact (fail-closed if scanner errors).
	if h.cfg.CVEScanner != nil {
		scanResult, err := h.cfg.CVEScanner.Scan(ctx, ref)
		if err != nil {
			log.Error().Err(err).Msg("CVE scan failed")
			record(VerdictError, GateCVE, "cve_scan_error", http.StatusServiceUnavailable, nil)
			h.writeError(w, requestID, ref, http.StatusServiceUnavailable, "cve_scan_error")
			return
		}
		if h.cfg.Policy != nil {
			decision := h.cfg.Policy.Evaluate(ref, scanResult)
			if !decision.Allowed {
				log.Warn().
					Str("reason", decision.Reason).
					Int("findings", len(decision.Findings)).
					Msg("CVE policy blocked package")
				blockedBy := "cve"
				if decision.Reason == "denylisted" {
					blockedBy = "denylist"
				}
				record(VerdictBlock, GateCVE, decision.Reason, http.StatusForbidden, func(ev *Event) {
					ev.BlockedBy = []string{blockedBy}
					ev.CVEs = decision.Findings
				})
				h.writeCVEBlockedResponse(w, requestID, ref, decision)
				return
			}
		}
	}

	// Download artifact, trying each configured upstream in order.
	upstreamURLs := h.cfg.Adapter.UpstreamURLs(r)
	if len(upstreamURLs) == 0 {
		log.Error().Msg("adapter returned no upstream URLs")
		record(VerdictError, GateSupply, "no_upstream_configured", http.StatusInternalServerError, nil)
		h.writeError(w, requestID, ref, http.StatusInternalServerError, "no_upstream_configured")
		return
	}
	tmpPath, allNotFound, err := h.downloadFromUpstreams(ctx, upstreamURLs)
	if err != nil {
		if allNotFound {
			log.Warn().Strs("upstream_urls", upstreamURLs).Msg("artifact not found on any upstream")
			record(VerdictError, GateSupply, "artifact_not_found", http.StatusNotFound, nil)
			h.writeError(w, requestID, ref, http.StatusNotFound, "artifact_not_found")
			return
		}
		log.Error().Err(err).Strs("upstream_urls", upstreamURLs).Msg("failed to download artifact")
		record(VerdictError, GateSupply, "upstream_unavailable", http.StatusBadGateway, nil)
		h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer os.Remove(tmpPath)

	// Antivirus scan — after download, before caching (fail-closed on error).
	if h.cfg.AVScanner != nil {
		avResult, err := h.cfg.AVScanner.Scan(ctx, tmpPath)
		if err != nil {
			log.Error().Err(err).Msg("AV scan failed")
			record(VerdictError, GateMalware, "av_scan_error", http.StatusServiceUnavailable, nil)
			h.writeError(w, requestID, ref, http.StatusServiceUnavailable, "av_scan_error")
			return
		}
		if !avResult.Clean {
			log.Warn().Str("engine", avResult.Engine).Str("signature", avResult.Signature).Msg("malware detected")
			record(VerdictBlock, GateMalware, "malware_found", http.StatusForbidden, func(ev *Event) {
				ev.BlockedBy = []string{"malware"}
				ev.MalwareEngine = avResult.Engine
				ev.MalwareSignature = avResult.Signature
			})
			h.writeMalwareBlockedResponse(w, requestID, ref, avResult.Engine, avResult.Signature)
			return
		}
	}

	// Cache the artifact (scan passed).
	if err := h.cfg.Cache.Put(ref, tmpPath, true, ""); err != nil {
		log.Error().Err(err).Msg("failed to cache artifact")
		// Fail-closed: don't serve if we cannot cache
		record(VerdictError, GateCache, "cache_error", http.StatusInternalServerError, nil)
		h.writeError(w, requestID, ref, http.StatusInternalServerError, "cache_error")
		return
	}

	log.Info().Str("sc_reason", scResult.Reason).Msg("serving artifact")
	entry, found := h.cfg.Cache.Get(ref)
	if !found {
		// Should not happen — we just Put it
		record(VerdictError, GateCache, "cache_error", http.StatusInternalServerError, nil)
		h.writeError(w, requestID, ref, http.StatusInternalServerError, "cache_error")
		return
	}
	// PASS gate = the deepest gate this artifact actually cleared.
	lastGate := GateSupply
	if h.cfg.CVEScanner != nil {
		lastGate = GateCVE
	}
	if h.cfg.AVScanner != nil {
		lastGate = GateMalware
	}
	record(VerdictPass, lastGate, scResult.Reason, http.StatusOK, func(ev *Event) {
		ev.PublishedAt = scResult.PublishedAt
	})
	h.serveFromCache(w, entry)
}
```

- [ ] **Step 5: Run the full proxy suite with race detector**

Run: `go test ./internal/proxy/... -race`
Expected: PASS — new recorder tests and all existing handler tests (nil-Recorder paths) green.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/handler.go internal/proxy/recorder_test.go
git commit -m "feat(proxy): emit one telemetry event per intercepted request outcome"
```

---

### Task 7: `internal/console` — HTTP API

**Files:**
- Create: `internal/console/server.go`
- Create: `internal/console/events.go`
- Test: `internal/console/server_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/console/server_test.go`:

```go
package console_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

type fakeStats struct{ stats cache.CacheStats }

func (f *fakeStats) Stats() (cache.CacheStats, error) { return f.stats, nil }

type fixture struct {
	store   *telemetry.Store
	hub     *telemetry.Hub
	runtime *policy.Runtime
	srv     *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store := telemetry.NewStore(16)
	bcast := telemetry.NewBroadcaster()
	runtime := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{Enabled: true, BlockOn: "HIGH"},
		config.PolicyProfile{CVEBlock: true},
		nil,
	)
	h := console.NewHandler(console.Config{
		Store:         store,
		Broadcaster:   bcast,
		Policy:        runtime,
		Cache:         &fakeStats{stats: cache.CacheStats{Entries: 42, SizeBytes: 1 << 30, HitRatio: 0.5, Evictions: 3}},
		CacheMaxBytes: 64 << 30,
		Registries: []console.RegistryInfo{
			{Ecosystem: "pypi", Enabled: true, Upstreams: []string{"https://pypi.org/simple"}},
		},
		Scanners: []console.ScannerInfo{{Name: "osv.dev", Detail: "https://api.osv.dev", Enabled: true}},
		Logger:   zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &fixture{store: store, hub: &telemetry.Hub{Store: store, Broadcaster: bcast}, runtime: runtime, srv: srv}
}

func getJSON(t *testing.T, url string, into any) int {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.NoError(t, json.NewDecoder(resp.Body).Decode(into))
	return resp.StatusCode
}

func blockEvent(id string, until time.Time) proxy.Event {
	return proxy.Event{
		RequestID: id, Time: time.Now(),
		Ecosystem: "npm", Package: "fresh", Version: "1.0.0",
		Verdict: proxy.VerdictBlock, Gate: proxy.GateSupply,
		Reason: "package_younger_than_min_age", HTTPStatus: 423,
		BlockedBy:   []string{"supply_chain"},
		PublishedAt: time.Now().Add(-time.Hour), BlockUntil: until,
	}
}

func TestOverview(t *testing.T) {
	f := newFixture(t)
	f.store.Record(proxy.Event{Verdict: proxy.VerdictCache, Gate: proxy.GateCache, Time: time.Now()})

	var body struct {
		StartedAt time.Time `json:"started_at"`
		KPIs      struct {
			RequestsTotal uint64  `json:"requests_total"`
			CacheHits     uint64  `json:"cache_hits"`
			HitRate       float64 `json:"hit_rate"`
		} `json:"kpis"`
		Gates map[string]telemetry.GateCounts `json:"gates"`
		Cache struct {
			Objects  int64 `json:"objects"`
			MaxBytes int64 `json:"max_bytes"`
		} `json:"cache"`
		Scanners []console.ScannerInfo `json:"scanners"`
	}
	code := getJSON(t, f.srv.URL+"/api/overview", &body)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, uint64(1), body.KPIs.RequestsTotal)
	assert.Equal(t, uint64(1), body.KPIs.CacheHits)
	assert.InDelta(t, 1.0, body.KPIs.HitRate, 0.001)
	assert.Equal(t, telemetry.GateCounts{Pass: 1}, body.Gates["cache"])
	assert.Equal(t, int64(42), body.Cache.Objects)
	assert.Equal(t, int64(64<<30), body.Cache.MaxBytes)
	require.Len(t, body.Scanners, 1)
	assert.False(t, body.StartedAt.IsZero())
}

func TestRequests(t *testing.T) {
	f := newFixture(t)
	for _, id := range []string{"r1", "r2", "r3"} {
		f.store.Record(proxy.Event{RequestID: id, Verdict: proxy.VerdictPass, Gate: proxy.GateSupply, Time: time.Now(), Ecosystem: "pypi", Package: "p", Version: "1"})
	}

	var body struct {
		Requests []struct {
			RequestID string `json:"request_id"`
			Eco       string `json:"eco"`
			Verdict   string `json:"verdict"`
		} `json:"requests"`
	}
	code := getJSON(t, f.srv.URL+"/api/requests?limit=2", &body)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, body.Requests, 2)
	assert.Equal(t, "r3", body.Requests[0].RequestID, "newest first")
	assert.Equal(t, "pypi", body.Requests[0].Eco)

	resp, err := http.Get(f.srv.URL + "/api/requests?limit=abc")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestQuarantine(t *testing.T) {
	f := newFixture(t)
	f.store.Record(blockEvent("r1", time.Now().Add(6*time.Hour)))
	f.store.Record(blockEvent("r2", time.Now().Add(-time.Hour))) // expired duplicate, newest — replaces r1 (same pkg) and is expired

	var body struct {
		Quarantine []struct {
			Eco        string    `json:"eco"`
			Pkg        string    `json:"pkg"`
			BlockUntil time.Time `json:"block_until"`
		} `json:"quarantine"`
	}
	code := getJSON(t, f.srv.URL+"/api/quarantine", &body)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, body.Quarantine, 0, "newest record for the package is expired")

	f.store.Record(blockEvent("r3", time.Now().Add(6*time.Hour)))
	getJSON(t, f.srv.URL+"/api/quarantine", &body)
	require.Len(t, body.Quarantine, 1)
	assert.Equal(t, "npm", body.Quarantine[0].Eco)
	assert.Equal(t, "fresh", body.Quarantine[0].Pkg)
}

func TestPolicyGetAndPut(t *testing.T) {
	f := newFixture(t)

	var pol struct {
		Mode        string   `json:"mode"`
		MinAgeHours int      `json:"min_age_hours"`
		CVEBlockOn  string   `json:"cve_block_on"`
		Allowlist   []string `json:"allowlist"`
		Persistence string   `json:"persistence"`
	}
	code := getJSON(t, f.srv.URL+"/api/policy", &pol)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "enforce", pol.Mode)
	assert.Equal(t, 24, pol.MinAgeHours)
	assert.Equal(t, "HIGH", pol.CVEBlockOn)
	assert.Equal(t, "runtime", pol.Persistence)

	put := func(body string) *http.Response {
		req, err := http.NewRequest(http.MethodPut, f.srv.URL+"/api/policy", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		return resp
	}

	resp := put(`{"mode":"dry_run","min_age_hours":48,"cve_block_on":"CRITICAL","allowlist":["pypi/requests"],"denylist":[]}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&pol))
	assert.Equal(t, "dry_run", pol.Mode)
	assert.Equal(t, 48, pol.MinAgeHours)
	assert.Equal(t, []string{"pypi/requests"}, pol.Allowlist)
	assert.Equal(t, "dry_run", f.runtime.Current().Mode, "runtime actually swapped")

	resp = put(`{"mode":"yolo","min_age_hours":1,"cve_block_on":"HIGH","allowlist":[],"denylist":[]}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errBody struct {
		Error string `json:"error"`
		Field string `json:"field"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "invalid_policy", errBody.Error)
	assert.Equal(t, "mode", errBody.Field)
	assert.Equal(t, "dry_run", f.runtime.Current().Mode, "policy unchanged after 400")
}

func TestRegistries(t *testing.T) {
	f := newFixture(t)
	var body struct {
		Registries []console.RegistryInfo `json:"registries"`
	}
	code := getJSON(t, f.srv.URL+"/api/registries", &body)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, body.Registries, 1)
	assert.Equal(t, "pypi", body.Registries[0].Ecosystem)
}

func TestEventsSSE(t *testing.T) {
	f := newFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.srv.URL+"/api/events", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	// Give the handler goroutine a moment to subscribe before publishing.
	time.Sleep(100 * time.Millisecond)
	f.hub.Record(proxy.Event{RequestID: "req_sse", Verdict: proxy.VerdictPass, Gate: proxy.GateMalware, Time: time.Now()})

	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(line, "data: "), "got %q", line)
	assert.Contains(t, line, `"request_id":"req_sse"`)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/console/ -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement `internal/console/events.go`**

```go
package console

import (
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// Wire shapes mirror the field names the SPA already renders (web/console),
// so the JSX screens change minimally.

type cveJSON struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity"`
	CVSS     float64 `json:"cvss"`
	Summary  string  `json:"summary"`
}

type malwareJSON struct {
	Engine    string `json:"engine"`
	Signature string `json:"signature"`
}

type supplyJSON struct {
	PublishedAt time.Time  `json:"published_at"`
	BlockUntil  *time.Time `json:"block_until,omitempty"`
}

type eventJSON struct {
	RequestID string       `json:"request_id"`
	TS        time.Time    `json:"ts"`
	Eco       string       `json:"eco"`
	Pkg       string       `json:"pkg"`
	Ver       string       `json:"ver"`
	Verdict   string       `json:"verdict"`
	Gate      string       `json:"gate"`
	Lat       int64        `json:"lat"`
	HTTP      int          `json:"http,omitempty"`
	Reason    string       `json:"reason,omitempty"`
	BlockedBy []string     `json:"blocked_by,omitempty"`
	CVEs      []cveJSON    `json:"cves,omitempty"`
	Malware   *malwareJSON `json:"malware,omitempty"`
	Supply    *supplyJSON  `json:"supply,omitempty"`
}

func toEventJSON(ev proxy.Event) eventJSON {
	out := eventJSON{
		RequestID: ev.RequestID, TS: ev.Time,
		Eco: ev.Ecosystem, Pkg: ev.Package, Ver: ev.Version,
		Verdict: ev.Verdict, Gate: ev.Gate, Lat: ev.LatencyMS,
		HTTP: ev.HTTPStatus, Reason: ev.Reason, BlockedBy: ev.BlockedBy,
	}
	for _, f := range ev.CVEs {
		out.CVEs = append(out.CVEs, cveJSON{ID: f.ID, Severity: f.Severity.String(), CVSS: f.Score, Summary: f.Summary})
	}
	if ev.MalwareEngine != "" || ev.MalwareSignature != "" {
		out.Malware = &malwareJSON{Engine: ev.MalwareEngine, Signature: ev.MalwareSignature}
	}
	if !ev.PublishedAt.IsZero() {
		sj := &supplyJSON{PublishedAt: ev.PublishedAt}
		if !ev.BlockUntil.IsZero() {
			bu := ev.BlockUntil
			sj.BlockUntil = &bu
		}
		out.Supply = sj
	}
	return out
}
```

- [ ] **Step 4: Implement `internal/console/server.go`**

```go
// Package console serves the admin console HTTP API over live proxy state:
// telemetry from internal/telemetry, the runtime policy, registry config and
// cache stats. No authentication this phase — documented as a known risk.
package console

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// CacheStatsProvider exposes cache statistics; cache.Cache satisfies it.
type CacheStatsProvider interface {
	Stats() (cache.CacheStats, error)
}

// RegistryInfo describes one configured registry for GET /api/registries.
type RegistryInfo struct {
	Ecosystem string   `json:"eco"`
	Enabled   bool     `json:"enabled"`
	Upstreams []string `json:"upstreams"`
}

// ScannerInfo describes one configured scan engine. Static configuration
// only — no live health probes this phase.
type ScannerInfo struct {
	Name    string `json:"name"`
	Detail  string `json:"detail"`
	Enabled bool   `json:"enabled"`
}

// Config wires the API to runtime state.
type Config struct {
	Store         *telemetry.Store
	Broadcaster   *telemetry.Broadcaster
	Policy        *policy.Runtime
	Cache         CacheStatsProvider // optional; nil reports zero stats
	CacheMaxBytes int64
	Registries    []RegistryInfo
	Scanners      []ScannerInfo
	Logger        zerolog.Logger
}

type server struct {
	cfg Config
}

// NewHandler returns the console API handler; mount it at "/api/".
func NewHandler(cfg Config) http.Handler {
	if cfg.Scanners == nil {
		cfg.Scanners = []ScannerInfo{}
	}
	if cfg.Registries == nil {
		cfg.Registries = []RegistryInfo{}
	}
	s := &server{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/overview", s.overview)
	mux.HandleFunc("GET /api/requests", s.requests)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/quarantine", s.quarantine)
	mux.HandleFunc("GET /api/policy", s.getPolicy)
	mux.HandleFunc("PUT /api/policy", s.putPolicy)
	mux.HandleFunc("GET /api/registries", s.registries)
	return mux
}

func (s *server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.cfg.Logger.Error().Err(err).Msg("console: writing JSON response")
	}
}

func (s *server) overview(w http.ResponseWriter, _ *http.Request) {
	snap := s.cfg.Store.Snapshot()

	var cs cache.CacheStats
	if s.cfg.Cache != nil {
		got, err := s.cfg.Cache.Stats()
		if err != nil {
			s.cfg.Logger.Error().Err(err).Msg("console: cache stats")
		} else {
			cs = got
		}
	}

	hitRate := 0.0
	if snap.Requests > 0 {
		hitRate = float64(snap.CacheHits) / float64(snap.Requests)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"started_at":     snap.StartedAt,
		"uptime_seconds": int64(time.Since(snap.StartedAt).Seconds()),
		"kpis": map[string]any{
			"requests_total":  snap.Requests,
			"cache_hits":      snap.CacheHits,
			"hit_rate":        hitRate,
			"blocked_total":   snap.Blocked,
			"errors":          snap.Errors,
			"supply_blocked":  snap.SupplyBlocked,
			"cve_blocked":     snap.CVEBlocked,
			"malware_blocked": snap.MalwareBlocked,
			"denylisted":      snap.Denylisted,
		},
		"gates": snap.Gates,
		"cache": map[string]any{
			"objects":    cs.Entries,
			"size_bytes": cs.SizeBytes,
			"max_bytes":  s.cfg.CacheMaxBytes,
			"hit_rate":   cs.HitRatio,
			"evictions":  cs.Evictions,
		},
		"scanners": s.cfg.Scanners,
	})
}

func (s *server) requests(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 {
			s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_limit"})
			return
		}
		limit = n
	}
	events := s.cfg.Store.Recent(limit)
	out := make([]eventJSON, 0, len(events))
	for _, ev := range events {
		out = append(out, toEventJSON(ev))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

func (s *server) quarantine(w http.ResponseWriter, _ *http.Request) {
	type qJSON struct {
		Eco         string    `json:"eco"`
		Pkg         string    `json:"pkg"`
		Ver         string    `json:"ver"`
		PublishedAt time.Time `json:"published_at"`
		BlockUntil  time.Time `json:"block_until"`
		RequestID   string    `json:"request_id"`
	}
	events := s.cfg.Store.Quarantine(time.Now())
	out := make([]qJSON, 0, len(events))
	for _, ev := range events {
		out = append(out, qJSON{
			Eco: ev.Ecosystem, Pkg: ev.Package, Ver: ev.Version,
			PublishedAt: ev.PublishedAt, BlockUntil: ev.BlockUntil, RequestID: ev.RequestID,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"quarantine": out})
}

// writePolicy renders the current runtime policy. "persistence":"runtime"
// tells the UI that edits reset to the YAML config on restart.
func (s *server) writePolicy(w http.ResponseWriter, status int) {
	p := s.cfg.Policy.Current()
	s.writeJSON(w, status, map[string]any{
		"mode":          p.Mode,
		"min_age_hours": p.MinAgeHours,
		"cve_block_on":  p.CVEBlockOn,
		"allowlist":     p.Allowlist,
		"denylist":      p.Denylist,
		"persistence":   "runtime",
	})
}

func (s *server) getPolicy(w http.ResponseWriter, _ *http.Request) {
	s.writePolicy(w, http.StatusOK)
}

func (s *server) putPolicy(w http.ResponseWriter, r *http.Request) {
	var p policy.RuntimeParams
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_policy", "field": "body", "message": err.Error(),
		})
		return
	}
	if err := s.cfg.Policy.Apply(p); err != nil {
		var verr *policy.ValidationError
		if errors.As(err, &verr) {
			s.writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "invalid_policy", "field": verr.Field, "message": verr.Message,
			})
			return
		}
		s.cfg.Logger.Error().Err(err).Msg("console: policy apply")
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "apply_failed"})
		return
	}
	s.cfg.Logger.Info().Interface("policy", s.cfg.Policy.Current()).Msg("runtime policy updated via console")
	s.writePolicy(w, http.StatusOK)
}

func (s *server) registries(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{"registries": s.cfg.Registries})
}

// events streams new telemetry over SSE. The browser EventSource reconnects
// automatically (including after the server's WriteTimeout closes the
// connection).
func (s *server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch, cancel := s.cfg.Broadcaster.Subscribe()
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fl.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			data, err := json.Marshal(toEventJSON(ev))
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return
			}
			fl.Flush()
		}
	}
}
```

- [ ] **Step 5: Run tests with race detector**

Run: `go test ./internal/console/ -race -v`
Expected: PASS (7 tests).

- [ ] **Step 6: Commit**

```bash
git add internal/console/
git commit -m "feat(console): HTTP API over telemetry store, runtime policy and registry config"
```

---

### Task 8: wire everything in `cmd/jo-ei/main.go`

**Files:**
- Modify: `cmd/jo-ei/main.go`

- [ ] **Step 1: Update imports** — add to the import block:

```go
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
```

- [ ] **Step 2: Add `recorder` to `sharedDeps` and `buildHandler`**

```go
// sharedDeps groups dependencies shared across every per-registry handler.
type sharedDeps struct {
	filter     proxy.SCFilter
	cache      proxy.ArtifactCache
	logger     zerolog.Logger
	cveScanner proxy.CVEScanner
	policy     proxy.PolicyDecider
	avScanner  proxy.AVScanner
	recorder   proxy.Recorder
}
```

In `buildHandler`, add to the `HandlerConfig` literal:

```go
		Recorder:   shared.recorder,
```

- [ ] **Step 3: Replace allowlist/filter/policy construction in `runProxy`**

Replace the block from `var allowlist *supplychain.Allowlist` through `shared := sharedDeps{...}` (currently lines 97–109) with:

```go
	var fileAllow []string
	if cfg.SupplyChain.AllowlistPath != "" {
		allowlist, err := supplychain.LoadAllowlist(cfg.SupplyChain.AllowlistPath)
		if err != nil {
			return err
		}
		fileAllow = allowlist.Entries()
	}

	// Runtime policy: engine + supply-chain filter behind an atomic swap so
	// the console can apply edits without restart (runtime-only; the YAML
	// config wins again after restart).
	policyRuntime := policy.NewRuntime(cfg.SupplyChain, cfg.CVE, profile, fileAllow)

	store := telemetry.NewStore(500)
	broadcaster := telemetry.NewBroadcaster()

	shared := sharedDeps{
		filter:   policyRuntime,
		cache:    &cacheAdapter{c: artifactCache},
		logger:   logger,
		recorder: &telemetry.Hub{Store: store, Broadcaster: broadcaster},
	}
```

In the CVE block (currently lines 112–125), replace `shared.policy = policy.NewEngine(cfg.CVE, profile)` with:

```go
		shared.policy = policyRuntime
```

- [ ] **Step 4: Mount the console API on the root mux**

After `root.Handle("/console/", web.ConsoleHandler())` add:

```go
	root.Handle("/api/", console.NewHandler(console.Config{
		Store:         store,
		Broadcaster:   broadcaster,
		Policy:        policyRuntime,
		Cache:         artifactCache,
		CacheMaxBytes: int64(cfg.Cache.Local.MaxSizeGB) << 30,
		Registries:    registryInfo(cfg),
		Scanners:      scannerInfo(cfg, profile),
		Logger:        logger,
	}))
```

- [ ] **Step 5: Add the info helpers** at the bottom of `main.go`:

```go
// registryInfo flattens the registry config for GET /api/registries.
func registryInfo(cfg *config.Config) []console.RegistryInfo {
	return []console.RegistryInfo{
		{Ecosystem: "pypi", Enabled: cfg.Registries.PyPI.Enabled, Upstreams: cfg.Registries.PyPI.Upstreams},
		{Ecosystem: "npm", Enabled: cfg.Registries.NPM.Enabled, Upstreams: cfg.Registries.NPM.Upstreams},
		{Ecosystem: "maven", Enabled: cfg.Registries.Maven.Enabled, Upstreams: cfg.Registries.Maven.Upstreams},
		{Ecosystem: "rubygems", Enabled: cfg.Registries.RubyGems.Enabled, Upstreams: cfg.Registries.RubyGems.Upstreams},
	}
}

// scannerInfo lists configured scan engines for the overview (static config,
// no live health probes this phase).
func scannerInfo(cfg *config.Config, profile config.PolicyProfile) []console.ScannerInfo {
	var out []console.ScannerInfo
	if cfg.CVE.Enabled {
		base := cfg.CVE.BaseURL
		if base == "" {
			base = "https://api.osv.dev"
		}
		out = append(out, console.ScannerInfo{Name: "osv.dev", Detail: base, Enabled: true})
	}
	for _, sc := range cfg.Malware.Scanners {
		out = append(out, console.ScannerInfo{Name: sc.Type, Detail: sc.Address, Enabled: profile.MalwareBlock})
	}
	return out
}
```

Also update the startup log line (the `Str("console", "/console/")` block) to include `Str("api", "/api/")`.

- [ ] **Step 6: Build and run all tests**

Run: `go build ./... ; go test ./... -count=1`
Expected: build clean, all packages PASS (including `cmd/jo-ei` tests).

- [ ] **Step 7: Commit**

```bash
git add cmd/jo-ei/main.go
git commit -m "feat(cmd): wire telemetry store, runtime policy and console API into the server"
```

---

### Task 9: integration test — full loop including policy swap

**Files:**
- Create: `integration/console_test.go`

- [ ] **Step 1: Write the test.** The file reuses `newTestRegistry` and `localCacheAdapter` from `integration/phase1_test.go` (same package). It must carry the same build tag.

```go
//go:build integration

package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// consoleStack mirrors the cmd/jo-ei wiring: handler + recorder hub +
// runtime policy + console API behind one mux.
func consoleStack(t *testing.T, upstream *httptest.Server) (*httptest.Server, *policy.Runtime) {
	t.Helper()

	dir := t.TempDir()
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:  dir,
		MaxSizeGB: 1,
		TTL:       24 * time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = localCache.Close() })

	runtime := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{},
		config.PolicyProfile{},
		nil,
	)
	store := telemetry.NewStore(100)
	bcast := telemetry.NewBroadcaster()
	hub := &telemetry.Hub{Store: store, Broadcaster: bcast}

	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:  adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:   runtime,
		Cache:    &localCacheAdapter{lc: localCache},
		Logger:   zerolog.Nop(),
		Recorder: hub,
	})

	mux := proxy.NewMux(map[string]*proxy.Handler{"pypi": handler}, zerolog.Nop())
	root := http.NewServeMux()
	root.Handle("/api/", console.NewHandler(console.Config{
		Store: store, Broadcaster: bcast, Policy: runtime, Logger: zerolog.Nop(),
	}))
	root.Handle("/", mux)

	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)
	return srv, runtime
}

func TestConsole_EndToEnd(t *testing.T) {
	// Upstream serving a 1h-old package (younger than the 24h min age).
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()

	srv, runtime := consoleStack(t, upstream)
	url := srv.URL + "/pypi/packages/py3/f/fresh-pkg/fresh_pkg-1.0.0-py3-none-any.whl"

	// 1. Fresh package is blocked at the supply gate (423).
	resp, err := http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusLocked, resp.StatusCode)

	// 2. The block shows up in the request feed…
	var feed struct {
		Requests []struct {
			Verdict string `json:"verdict"`
			Gate    string `json:"gate"`
			Pkg     string `json:"pkg"`
		} `json:"requests"`
	}
	getInto(t, srv.URL+"/api/requests", &feed)
	require.NotEmpty(t, feed.Requests)
	assert.Equal(t, "BLOCK", feed.Requests[0].Verdict)
	assert.Equal(t, "supply", feed.Requests[0].Gate)
	assert.Equal(t, "fresh-pkg", feed.Requests[0].Pkg)

	// 3. …and in quarantine.
	var quar struct {
		Quarantine []struct {
			Pkg string `json:"pkg"`
		} `json:"quarantine"`
	}
	getInto(t, srv.URL+"/api/quarantine", &quar)
	require.Len(t, quar.Quarantine, 1)
	assert.Equal(t, "fresh-pkg", quar.Quarantine[0].Pkg)

	// 4. PUT /api/policy lowers min_age to 0 — applies without restart.
	body := `{"mode":"enforce","min_age_hours":0,"cve_block_on":"HIGH","allowlist":[],"denylist":[]}`
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/policy", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	presp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	presp.Body.Close()
	require.Equal(t, http.StatusOK, presp.StatusCode)
	assert.Equal(t, 0, runtime.Current().MinAgeHours)

	// 5. The same package now passes under the new policy.
	resp, err = http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 6. Second fetch is a cache hit; overview KPIs reflect all four requests.
	resp, err = http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var overview struct {
		KPIs struct {
			RequestsTotal uint64 `json:"requests_total"`
			CacheHits     uint64 `json:"cache_hits"`
			BlockedTotal  uint64 `json:"blocked_total"`
		} `json:"kpis"`
	}
	getInto(t, srv.URL+"/api/overview", &overview)
	assert.Equal(t, uint64(4), overview.KPIs.RequestsTotal)
	assert.Equal(t, uint64(1), overview.KPIs.CacheHits)
	assert.Equal(t, uint64(1), overview.KPIs.BlockedTotal)

	// 7. The earlier quarantine entry is still derived from history (its
	// BlockUntil has not expired) — acceptable: quarantine reflects past
	// block events, and the entry ages out of the ring buffer over time.
}

func getInto(t *testing.T, url string, into any) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(into))
}
```

(If `cache.NewLocalCache` / `cache.LocalCacheConfig` field names differ from the snippet, copy the exact construction from `newTestProxy` in `integration/phase1_test.go:67-76` — that is the source of truth.)

- [ ] **Step 2: Run the test**

Run: `go test -tags integration ./integration/ -run TestConsole_EndToEnd -race -v`
Expected: PASS. If it fails, fix the stack-under-test wiring, not the assertions, unless an assertion contradicts the spec.

- [ ] **Step 3: Run everything**

Run: `go test ./... -race -count=1 ; go test -tags integration ./integration/ -race -count=1`
Expected: PASS across all packages.

- [ ] **Step 4: Commit**

```bash
git add integration/console_test.go
git commit -m "test(integration): console API end-to-end with live policy swap"
```

---

### Task 10: frontend — `api.js` replaces `data.js`

**Files:**
- Create: `web/console/api.js`
- Modify: `web/console/index.html` (line 24), `web/console/shared.jsx` (add hook)
- Delete: `web/console/data.js`

No SPA test harness exists and this phase does not introduce one — frontend steps are verified manually in Task 12.

- [ ] **Step 1: Create `web/console/api.js`**

```js
/* 浄衛 Jōei :: live API client — populates window.JOEI from the proxy API.
   Events: "joei:data" (full refresh), "joei:event" (one SSE event, detail = row),
   "joei:policy" (policy changed), "joei:connection" (JOEI.connected flipped). */
(function () {
  "use strict";

  const ECO = {
    pypi:     { id: "pypi",     label: "py",   name: "PyPI" },
    npm:      { id: "npm",      label: "npm",  name: "npm" },
    maven:    { id: "maven",    label: "mvn",  name: "Maven" },
    yarn:     { id: "yarn",     label: "yarn", name: "yarn" },
    rubygems: { id: "rubygems", label: "rb",   name: "RubyGems" },
  };

  const GATES = ["cache", "supply", "cve", "malware"];

  const GATE_META = {
    cache:   { label: "Cache",        sub: "LRU store",    kanji: null, role: "Served from store" },
    supply:  { label: "Supply Chain", sub: "min-age hold", kanji: "衛", role: "Maturity & lists" },
    cve:     { label: "CVE",          sub: "osv.dev",      kanji: "浄", role: "Vulnerability scan" },
    malware: { label: "Malware",      sub: "content scan", kanji: "浄", role: "Content scan" },
  };

  const emptyGateStats = () => {
    const g = {};
    GATES.forEach((k) => { g[k] = { ...GATE_META[k], pass: 0, block: 0 }; });
    return g;
  };

  const J = (window.JOEI = {
    ECO, GATES, CVES: {},
    requests: [],
    quarantine: [],
    policy: {
      mode: "off", min_age_hours: 0, cve_block_on: "CRITICAL",
      allowlist: [], denylist: [], persistence: "runtime",
      supply_chain: { min_age_hours: 0, mode: "off" },
    },
    registries: [],
    cache: { used_gb: 0, max_gb: 0, objects: "0", hit_rate: 0, evictions: 0 },
    kpis: {
      requests_total: 0, cache_hits: 0, hit_rate: 0, blocked_total: 0, errors: 0,
      supply_blocked: 0, cve_blocked: 0, malware_blocked: 0, denylisted: 0,
      quarantined: 0, started_at: null,
    },
    gateStats: emptyGateStats(),
    scanners: [],
    connected: false,
  });

  function fire(name, detail) {
    window.dispatchEvent(new CustomEvent(name, { detail }));
  }

  function setConnected(v) {
    if (J.connected !== v) { J.connected = v; fire("joei:connection"); }
  }

  async function getJSON(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(path + " -> HTTP " + res.status);
    return res.json();
  }

  /* Convert a wire event into the row shape the screens render. CVE details
     are registered into J.CVES so the drawer can look them up by id. */
  function reviveEvent(e) {
    const r = { ...e, ts: new Date(e.ts) };
    if (r.cves) {
      r.cves = r.cves.map((c) => {
        J.CVES[c.id] = { id: c.id, severity: c.severity, cvss: c.cvss || 0, summary: c.summary || "", source: "osv.dev" };
        return c.id;
      });
    }
    if (r.supply) {
      r.supply.published_at = new Date(r.supply.published_at);
      if (r.supply.block_until) r.supply.block_until = new Date(r.supply.block_until);
      r.supply.age_hours = Math.max(0, Math.round((Date.now() - r.supply.published_at.getTime()) / 3600000));
      r.supply.min_age_hours = J.policy.min_age_hours;
    }
    if (r.malware) r.malware.action = "REJECT";
    if (!r.blocked_by) r.blocked_by = [];
    return r;
  }

  function applyPolicy(p) {
    // supply_chain alias keeps older field paths in the screens working.
    J.policy = { ...p, supply_chain: { min_age_hours: p.min_age_hours, mode: p.mode } };
  }

  function applyOverview(o) {
    J.kpis = { ...o.kpis, quarantined: J.quarantine.length, started_at: new Date(o.started_at) };
    const gates = emptyGateStats();
    GATES.forEach((g) => {
      if (o.gates[g]) { gates[g].pass = o.gates[g].pass; gates[g].block = o.gates[g].block; }
    });
    J.gateStats = gates;
    const GB = 1024 ** 3;
    J.cache = {
      used_gb: +(o.cache.size_bytes / GB).toFixed(2),
      max_gb: Math.round(o.cache.max_bytes / GB),
      objects: Number(o.cache.objects).toLocaleString("en-US"),
      hit_rate: o.cache.hit_rate,
      evictions: o.cache.evictions,
    };
    J.scanners = o.scanners.map((s) => ({
      name: s.name, detail: s.detail, status: s.enabled ? "ok" : "off", latency: "",
    }));
  }

  async function load() {
    const [overview, requests, quarantine, pol, registries] = await Promise.all([
      getJSON("/api/overview"),
      getJSON("/api/requests?limit=120"),
      getJSON("/api/quarantine"),
      getJSON("/api/policy"),
      getJSON("/api/registries"),
    ]);
    applyPolicy(pol);
    J.quarantine = quarantine.quarantine.map((q) => ({
      ...q, published_at: new Date(q.published_at), block_until: new Date(q.block_until),
    }));
    applyOverview(overview);
    J.requests = requests.requests.map(reviveEvent);
    J.registries = registries.registries.map((r) => ({ eco: r.eco, enabled: r.enabled, upstreams: r.upstreams }));
    J.kpis.quarantined = J.quarantine.length;
    setConnected(true);
    fire("joei:data");
  }

  async function savePolicy(p) {
    const body = {
      mode: p.mode, min_age_hours: p.min_age_hours, cve_block_on: p.cve_block_on,
      allowlist: p.allowlist, denylist: p.denylist,
    };
    const res = await fetch("/api/policy", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      const err = new Error(data.message || "invalid policy");
      err.field = data.field;
      throw err;
    }
    applyPolicy(data);
    fire("joei:policy");
    return J.policy;
  }

  function connectEvents() {
    const es = new EventSource("/api/events");
    es.onmessage = (m) => {
      const r = reviveEvent(JSON.parse(m.data));
      J.requests = [r, ...J.requests].slice(0, 500);
      fire("joei:event", r);
    };
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false); // EventSource reconnects on its own
  }

  J.load = load;
  J.savePolicy = savePolicy;

  // Initial load; fire joei:data even on failure so the app shell can leave
  // the loader and show the connection banner.
  load().catch(() => { setConnected(false); fire("joei:data"); }).finally(connectEvents);
  // Counters and quarantine are not pushed over SSE — refresh periodically.
  setInterval(() => {
    if (!document.hidden) load().catch(() => setConnected(false));
  }, 15000);
})();
```

- [ ] **Step 2: Swap the script tag in `web/console/index.html`** (line 24):

```html
  <script src="api.js"></script>
```

(replacing `<script src="data.js"></script>`; the comment above it can become `<!-- api client + components (load order = dependency order) -->`)

- [ ] **Step 3: Add the refresh hook to `web/console/shared.jsx`** — after the formatter functions (after `fmtCountdown`, ~line 30):

```js
/* re-render when api.js refreshes window.JOEI */
function useJoeiData() {
  const [, setTick] = useState(0);
  useEffect(() => {
    const fn = () => setTick((t) => t + 1);
    window.addEventListener("joei:data", fn);
    window.addEventListener("joei:policy", fn);
    return () => {
      window.removeEventListener("joei:data", fn);
      window.removeEventListener("joei:policy", fn);
    };
  }, []);
}
```

and add `useJoeiData` to the `Object.assign(window, { ... })` export at the bottom of `shared.jsx`.

- [ ] **Step 4: Delete the mock** — `git rm web/console/data.js`

- [ ] **Step 5: Verify embed still builds**

Run: `go build ./... ; go test ./web/`
Expected: build clean; `web` package tests pass (if a web test references `data.js`, update it to `api.js`).

- [ ] **Step 6: Commit**

```bash
git add web/console/api.js web/console/index.html web/console/shared.jsx
git rm web/console/data.js
git commit -m "feat(web): replace mock data store with live API client"
```

---

### Task 11: frontend — app shell + policy editor

**Files:**
- Modify: `web/console/app.jsx`, `web/console/policy.jsx`, `web/console/screens.css`

- [ ] **Step 1: Rewrite `App` in `web/console/app.jsx`.** Replace the `App` function with:

```jsx
function App() {
  const [page, setPage] = useState("overview");
  const [treatment, setTreatment] = useState("procession");
  const [threat, setThreat] = useState(null);
  const [policy, setPolicyState] = useState(JOEI.policy);
  const [toasts, setToasts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(JOEI.connected);
  const tid = useRef(0);

  useEffect(() => {
    const onData = () => { setLoading(false); setPolicyState(JOEI.policy); };
    const onConn = () => setConnected(JOEI.connected);
    window.addEventListener("joei:data", onData);
    window.addEventListener("joei:policy", onData);
    window.addEventListener("joei:connection", onConn);
    return () => {
      window.removeEventListener("joei:data", onData);
      window.removeEventListener("joei:policy", onData);
      window.removeEventListener("joei:connection", onConn);
    };
  }, []);

  const notify = useCallback((t) => {
    const id = ++tid.current;
    setToasts((xs) => [...xs, { ...t, id }]);
    setTimeout(() => setToasts((xs) => xs.filter((x) => x.id !== id)), 4800);
  }, []);
  const dismiss = (id) => setToasts((xs) => xs.filter((x) => x.id !== id));

  const saveLists = (patch, toast) => {
    JOEI.savePolicy({ ...JOEI.policy, ...patch })
      .then(() => notify(toast))
      .catch((err) => notify({
        kind: "block", code: "400 Bad Request", title: "Policy update failed",
        msg: String(err.message || err),
      }));
  };

  const onAllowlist = (target) => {
    const t = typeof target === "string" ? target : `${target.eco}/${target.pkg}@${target.ver}`;
    if (JOEI.policy.allowlist.includes(t)) return;
    saveLists({ allowlist: [...JOEI.policy.allowlist, t] },
      { kind: "ok", code: "200 OK", title: "Added to allowlist", msg: <>Now trusted on all gates: <span className="t-pkg">{t}</span></> });
  };
  const onDenylist = (target) => {
    if (JOEI.policy.denylist.includes(target)) return;
    saveLists({ denylist: [...JOEI.policy.denylist, target] },
      { kind: "block", code: "403 Forbidden", title: "Added to denylist", msg: <>Will be blocked at the gate: <span className="t-pkg">{target}</span></> });
  };
  const openThreat = (r) => setThreat(r);

  const meta = PAGE_META[page];

  return (
    <div className="app">
      <PurifyLoader hide={!loading} />

      {/* ---------- sidebar (unchanged markup from the current file) ---------- */}
      <nav className="sidebar">
        {/* keep the existing sidebar JSX exactly as-is, except: remove the
            static `badge: "5"` from the quarantine NAV entry at the top of
            this file (leave `gold: true`), since the count is now live */}
      </nav>

      {/* ---------- main ---------- */}
      <div className="main">
        <header className="topbar">
          <h1><span className="crumb-kanji kanji">{meta.kanji}</span> {meta.title}</h1>
          <div className="topbar-spacer"></div>

          <span className="pill" title="Console edits apply immediately but reset to the YAML config on restart">
            <span className="muted" style={{ fontWeight: 500 }}>policy</span>&nbsp;runtime override
          </span>
          <span className={`pill ${policy.mode === "enforce" ? "enforce" : policy.mode === "dry_run" ? "dry" : "off"}`}>
            <span className="dot"></span>
            {policy.mode === "enforce" ? "Enforcing" : policy.mode === "dry_run" ? "Dry-run" : "Off"}
          </span>
        </header>

        {!connected && !loading && (
          <div className="conn-banner">⚠ No connection to the proxy — data may be stale; retrying…</div>
        )}

        <div className="content">
          {page === "overview" && <Overview treatment={treatment} setTreatment={setTreatment} openThreat={openThreat} />}
          {page === "feed" && <LiveFeed openThreat={openThreat} />}
          {page === "quarantine" && <Quarantine onAllowlist={onAllowlist} />}
          {page === "policy" && <Policy notify={notify} />}
          {page === "registries" && <Registries notify={notify} />}
        </div>
      </div>

      {threat && <ThreatDrawer r={threat} onClose={() => setThreat(null)} onAllowlist={onAllowlist} onDenylist={onDenylist} />}
      <ToastHost toasts={toasts} dismiss={dismiss} />
    </div>
  );
}
```

Concrete sidebar edit: in the `NAV` constant at the top of `app.jsx`, change the quarantine entry to `{ id: "quarantine", label: "Quarantine", icon: "quar", gold: true }` (drop `badge: "5"`). Keep the rest of the sidebar JSX untouched. Keep `ToastHost`, `PurifyLoader`, `PAGE_META`, and the `ReactDOM.createRoot(...)` line unchanged. The old 1.5s fake-loader `useEffect` and the local `setPolicy` mutations are removed.

- [ ] **Step 2: Add the banner style to `web/console/screens.css`** (append at the end):

```css
/* connection-lost banner (app shell) */
.conn-banner {
  margin: 12px 24px 0;
  padding: 10px 16px;
  border: 1px solid var(--vermilion);
  border-radius: 8px;
  background: rgba(200, 60, 40, 0.12);
  color: var(--vermilion-l);
  font-size: 13px;
}
```

- [ ] **Step 3: Rewrite `web/console/policy.jsx`.** Replace `buildYaml` and `Policy` (keep `ListEditor` and `YamlView` as they are):

```jsx
function buildYaml(p) {
  return [
    ["c", "# 浄衛 runtime policy — resets to config.yaml on restart"],
    ["k", "mode", "v", p.mode],
    ["k", "min_age_hours", "d", p.min_age_hours],
    ["k", "cve_block_on", "v", p.cve_block_on],
    ["c", ""],
    ["k", "allowlist:"],
    ...p.allowlist.map((x) => ["li", x]),
    ["c", ""],
    ["k", "denylist:"],
    ...p.denylist.map((x) => ["li", x]),
  ];
}
```

```jsx
function Policy({ notify }) {
  const [yaml, setYaml] = useState(false);
  const [draft, setDraft] = useState(() => ({ ...JOEI.policy }));
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [fieldError, setFieldError] = useState(null);

  // Pick up server-side changes unless the user has unsaved edits.
  useEffect(() => {
    const sync = () => { if (!dirty) setDraft({ ...JOEI.policy }); };
    window.addEventListener("joei:policy", sync);
    window.addEventListener("joei:data", sync);
    return () => {
      window.removeEventListener("joei:policy", sync);
      window.removeEventListener("joei:data", sync);
    };
  }, [dirty]);

  const p = draft;
  const update = (patch) => { setDraft({ ...p, ...patch }); setDirty(true); setFieldError(null); };

  const save = () => {
    setSaving(true);
    JOEI.savePolicy(p)
      .then(() => {
        setDirty(false);
        notify({ kind: "ok", code: "200 OK", title: "Policy applied",
          msg: <>Runtime policy updated — resets to the YAML config on restart.</> });
      })
      .catch((err) => {
        setFieldError(err.field || null);
        notify({ kind: "block", code: "400 Bad Request", title: "Policy rejected",
          msg: String(err.message || err) });
      })
      .finally(() => setSaving(false));
  };

  const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const MODES = [["enforce", "Enforce"], ["dry_run", "Dry-run"], ["off", "Off"]];

  return (
    <div className="content-inner">
      <div className="section-head">
        <span className="head-kanji kanji">法</span>
        <div>
          <div className="eyebrow">Runtime policy · applies immediately, resets on restart</div>
          <h2>Effective policy</h2>
        </div>
        <div className="spacer"></div>
        <div className="seg">
          <button className={!yaml ? "active" : ""} onClick={() => setYaml(false)}>Form</button>
          <button className={yaml ? "active" : ""} onClick={() => setYaml(true)}>View as YAML</button>
        </div>
        <button className={`btn ${dirty ? "primary" : ""}`} disabled={!dirty || saving}
          style={!dirty ? { opacity: .5 } : undefined} onClick={save}>
          {saving ? "Applying…" : dirty ? "Save & apply" : "Saved"}
        </button>
      </div>

      <p className="muted" style={{ maxWidth: 680, marginTop: -4, marginBottom: 18, fontSize: 13 }}>
        Changes are a <b style={{ color: "var(--gold-l)" }}>runtime override</b>: they apply to the gate
        immediately but are not written to <span className="mono">config.yaml</span> — a restart restores the file policy.
        {fieldError && <span style={{ color: "var(--vermilion-l)" }}> · rejected field: <span className="mono">{fieldError}</span></span>}
      </p>

      {yaml ? (
        <div className="card" style={{ padding: 22 }}><YamlView p={p} /></div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, alignItems: "start" }}>
          {/* supply-chain mode + CVE threshold */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label>衛 Supply-chain mode</label>
              <div className="hint">How the gate acts on an immature package.</div>
              <div className="seg-radio" style={{ marginTop: 8 }}>
                {MODES.map(([k, l]) => (
                  <button key={k} className={`${p.mode === k ? "active" : ""} ${k === "enforce" ? "enf" : ""}`}
                    onClick={() => update({ mode: k })}>{l}</button>
                ))}
              </div>
            </div>
            <div className="divider"></div>
            <div className="field">
              <label>CVE — block on severity ≥</label>
              <div className="hint">Returns <span className="mono">403 Forbidden</span> when any CVE meets or exceeds this level.</div>
              <div className="seg-radio" style={{ marginTop: 8 }}>
                {SEV.map((s) => (
                  <button key={s} className={`${p.cve_block_on === s ? "active" : ""} ${s === "CRITICAL" ? "crit" : ""}`}
                    onClick={() => update({ cve_block_on: s })}>{s}</button>
                ))}
              </div>
            </div>
          </div>

          {/* min age */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label>衛 Minimum age</label>
              <div className="hint">Hold new releases (<span className="mono">423 Locked</span>) until they reach this age.</div>
              <div className="row" style={{ gap: 14, marginTop: 10 }}>
                <input type="range" min="0" max="72" step="1" value={p.min_age_hours}
                  onChange={(e) => update({ min_age_hours: +e.target.value })} style={{ flex: 1, accentColor: "var(--gold)" }} />
                <span className="mono" style={{ fontSize: 18, color: "var(--gold-l)", minWidth: 64, textAlign: "right" }}>
                  {p.min_age_hours}h
                </span>
              </div>
            </div>
          </div>

          {/* allowlist */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label style={{ color: "var(--jade-l)" }}>Allowlist · always trust</label>
              <div className="hint">Format <span className="mono">ecosystem/name</span> or <span className="mono">ecosystem/name@version</span>. Bypasses all gates.</div>
            </div>
            <div style={{ marginTop: 12 }}>
              <ListEditor kind="allow" items={p.allowlist}
                onAdd={(v) => update({ allowlist: [...p.allowlist, v] })}
                onRemove={(v) => update({ allowlist: p.allowlist.filter((x) => x !== v) })} />
            </div>
          </div>

          {/* denylist */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label style={{ color: "var(--vermilion-l)" }}>Denylist · always block</label>
              <div className="hint">Returns <span className="mono">403 Forbidden</span> regardless of scan results.</div>
            </div>
            <div style={{ marginTop: 12 }}>
              <ListEditor kind="deny" items={p.denylist}
                onAdd={(v) => update({ denylist: [...p.denylist, v] })}
                onRemove={(v) => update({ denylist: p.denylist.filter((x) => x !== v) })} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
```

(The profile selector and the duplicate "global enforcement mode" / "supply-chain mode" pair from the mock are gone: the backend has exactly one supply-chain mode.)

- [ ] **Step 4: Commit**

```bash
git add web/console/app.jsx web/console/policy.jsx web/console/screens.css
git commit -m "feat(web): live app shell with connection banner and working runtime policy editor"
```

---

### Task 12: frontend — remaining screens + manual verification

**Files:**
- Modify: `web/console/feed.jsx`, `web/console/overview.jsx`, `web/console/quarantine.jsx`, `web/console/registries.jsx`, `web/console/hero.jsx`, `web/console/drawer.jsx`

- [ ] **Step 1: `feed.jsx` — real SSE stream.** In `LiveFeed`, delete the `seqRef` line and replace the `useEffect` (the `STREAM_POOL` interval, lines 40–52) with:

```jsx
  useEffect(() => {
    const onEvent = (e) => {
      if (paused) return;
      setNewId(e.detail.request_id);
      setRows((rs) => [e.detail, ...rs].slice(0, 120));
    };
    const onData = () => { if (!paused) setRows(JOEI.requests.slice(0, 120)); };
    window.addEventListener("joei:event", onEvent);
    window.addEventListener("joei:data", onData);
    return () => {
      window.removeEventListener("joei:event", onEvent);
      window.removeEventListener("joei:data", onData);
    };
  }, [paused]);
```

Also update the empty state copy (line 100) to reflect reality when there is no traffic at all:

```jsx
            <div className="e-sub">{q || filter !== "all"
              ? <>Nothing in the stream matches “{q || filter}”. Clear the filter to see all traffic.</>
              : <>No requests have passed through the gate yet. Point a package manager at the proxy and traffic will appear here live.</>}</div>
```

- [ ] **Step 2: `overview.jsx` — honest KPIs.** Replace the `Overview` function body's data sources and the KPI/breakdown blocks:

At the top of `Overview` add live refresh:

```jsx
function Overview({ treatment, setTreatment, openThreat }) {
  useJoeiData();
  const [, setTick] = useState(0);
  useEffect(() => {
    const fn = () => setTick((t) => t + 1);
    window.addEventListener("joei:event", fn);
    return () => window.removeEventListener("joei:event", fn);
  }, []);

  const k = JOEI.kpis;
  const recent = JOEI.requests.slice(0, 6);
  const uptime = k.started_at ? fmtAgo(k.started_at).replace(" ago", "") : "—";
```

Replace the section-head eyebrow `Today · {date}` with `Since start · uptime {uptime}`.

Replace the four `KpiCard`s (sparklines and fake deltas were mock-only — removed per spec):

```jsx
      <div className="kpi-grid">
        <KpiCard label="Requests · since start" value={fmtCompact(k.requests_total)}
          delta={<><b>{fmtNum(k.requests_total)}</b> total · {fmtNum(k.errors)} errors</>} watermark="求" />
        <KpiCard label="Served from cache" value={(k.hit_rate * 100).toFixed(1) + "%"} accent="jade"
          delta={<><b>{fmtCompact(k.cache_hits)}</b> hits since start</>} watermark="蔵" />
        <KpiCard label="Blocked · since start" value={fmtNum(k.blocked_total)} accent="verm"
          delta={<>423 Locked + 403 Forbidden</>} watermark="封" />
        <KpiCard label="In quarantine" value={fmtNum(k.quarantined)} accent="gold"
          delta={<>held until min-age maturity</>} watermark="守" />
      </div>
```

Replace the breakdown card values:

```jsx
      <div className="card breakdown" style={{ marginTop: 14 }}>
        <div className="bd">
          <span className="v" style={{ color: "var(--gold-l)" }}>{fmtNum(k.supply_blocked)}</span>
          <span className="l">衛 Supply-chain · 423</span>
        </div>
        <div className="bd">
          <span className="v" style={{ color: "var(--vermilion-l)" }}>{fmtNum(k.cve_blocked)}</span>
          <span className="l">浄 CVE blocked · 403</span>
        </div>
        <div className="bd">
          <span className="v" style={{ color: "var(--vermilion-l)" }}>{fmtNum(k.malware_blocked)}</span>
          <span className="l">浄 Malware blocked · 403</span>
        </div>
        <div className="bd">
          <span className="v" style={{ color: "var(--washi-soft)" }}>{fmtNum(k.denylisted)}</span>
          <span className="l">Denylisted · 403</span>
        </div>
      </div>
```

The "Recent activity" block stays as-is (it reads the now-live `recent`).

- [ ] **Step 3: `quarantine.jsx` — live data + real maturity window.**

In `Quarantine`, replace the local-state init and add sync:

```jsx
function Quarantine({ onAllowlist }) {
  useJoeiData();
  const [items, setItems] = useState(() => JOEI.quarantine.slice());
  useEffect(() => {
    const fn = () => setItems(JOEI.quarantine.slice());
    window.addEventListener("joei:data", fn);
    return () => window.removeEventListener("joei:data", fn);
  }, []);
```

In the intro paragraph, change `JOEI.policy.supply_chain.min_age_hours` to `JOEI.policy.min_age_hours`.

In `QuarantineCard`, replace the hardcoded 24h window (line 11) and label:

```jsx
  const total = Math.max(1, q.block_until.getTime() - q.published_at.getTime());
```

and `<span className="muted" ...>maturing to 24h</span>` → `maturing to {JOEI.policy.min_age_hours}h`.

- [ ] **Step 4: `registries.jsx` — read-only live data.** Replace the `Registries` and `RegistryCard` data plumbing:

```jsx
function RegistryCard({ reg }) {
  const e = JOEI.ECO[reg.eco] || { name: reg.eco };
  return (
    <div className="card reg-card">
      <div className="reg-head">
        <Eco id={JOEI.ECO[reg.eco] ? reg.eco : "pypi"} size={30} />
        <div className="col">
          <span className="reg-name">{e.name}</span>
          <span className="reg-vol">{reg.enabled ? `${reg.upstreams.length} upstream${reg.upstreams.length === 1 ? "" : "s"}` : "disabled"}</span>
        </div>
        <div className="right row" style={{ gap: 10 }}>
          <span className="muted" style={{ fontSize: 12 }}>{reg.enabled ? "enabled" : "off"}</span>
          <button className={`toggle ${reg.enabled ? "on" : ""}`} disabled
            title="Configured in config.yaml — console management arrives in a later phase" aria-label="toggle"></button>
        </div>
      </div>
      <div className="upstream">
        {reg.upstreams.map((u, i) => (
          <div className="upstream-item" key={u} style={{ opacity: reg.enabled ? 1 : 0.45 }}>
            <span className="ord">{i + 1}</span>
            <span>{u}</span>
            <span className="pri">{i === 0 ? "primary" : "fallback"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Registries() {
  useJoeiData();
  const regs = JOEI.registries;
  const c = JOEI.cache;
  const usedPct = c.max_gb > 0 ? Math.min(100, (c.used_gb / c.max_gb) * 100) : 0;

  return (
    <div className="content-inner">
      <div className="section-head">
        <span className="head-kanji kanji">蔵</span>
        <div>
          <div className="eyebrow">Upstreams &amp; storage</div>
          <h2>Registries &amp; cache</h2>
        </div>
      </div>

      {/* cache panel */}
      <div className="card" style={{ padding: 22, marginBottom: 22 }}>
        <div className="row" style={{ alignItems: "flex-end", marginBottom: 16 }}>
          <div>
            <div className="eyebrow" style={{ fontSize: 11, letterSpacing: ".18em", color: "var(--washi-mut)" }}>LOCAL CACHE</div>
            <div className="row" style={{ alignItems: "baseline", gap: 8, marginTop: 4 }}>
              <span className="mono" style={{ fontSize: 28, fontWeight: 600, color: "var(--jade-l)" }}>{c.used_gb}</span>
              <span className="muted mono">/ {c.max_gb} GB used</span>
            </div>
          </div>
        </div>
        <div className="cache-meter">
          <i className="used" style={{ width: usedPct + "%" }}></i>
        </div>
        <div className="row" style={{ marginTop: 12, gap: 28, fontSize: 12.5 }}>
          <span className="muted">Objects <b className="mono" style={{ color: "var(--washi)" }}>{c.objects}</b></span>
          <span className="muted">Hit rate · since start <b className="mono" style={{ color: "var(--jade-l)" }}>{(c.hit_rate * 100).toFixed(1)}%</b></span>
          <span className="muted">LRU evictions · since start <b className="mono" style={{ color: "var(--gold-l)" }}>{fmtNum(c.evictions)}</b></span>
        </div>
      </div>

      <div className="section-head" style={{ marginBottom: 14 }}>
        <h2 style={{ fontSize: 16 }}>Per-ecosystem upstreams</h2>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        {regs.length === 0
          ? <div className="card"><div className="empty"><span className="e-kanji">無</span><div className="e-title">No registries</div></div></div>
          : regs.map((r) => <RegistryCard key={r.eco} reg={r} />)}
      </div>
    </div>
  );
}
```

(The mock 24h sparkline, fake request volumes, eviction-headroom hatch and the fake enable/disable toggle behavior are removed — registry management is a later phase.)

- [ ] **Step 5: `hero.jsx` — live gate stats, honest scanner strip.**

In `GateHero`, add `useJoeiData();` as the first line of the function body (so `stats = JOEI.gateStats` re-reads on refresh).

In `ScannerStrip`, the mock latency badge goes away and "fail-closed" no longer pretends to probe health. Replace the function with:

```jsx
function ScannerStrip() {
  useJoeiData();
  return (
    <div className="scanner-strip">
      <span className="fc-label">
        <span style={{ color: "var(--jade-l)" }}>● </span>
        Fail-closed
      </span>
      <span className="muted" style={{ fontSize: 12 }}>
        Scanner errors hold requests rather than serving unscanned artifacts.
      </span>
      <div className="right row" style={{ gap: 20 }}>
        {JOEI.scanners.length === 0
          ? <span className="muted" style={{ fontSize: 12 }}>no scanners configured</span>
          : JOEI.scanners.map((s) => (
              <span className={`health ${s.status}`} key={s.name + s.detail} title={s.detail}>
                <i className="hdot"></i>{s.name}
              </span>
            ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 6: `drawer.jsx` — guard CVE lookups.** In `ThreatDrawer`'s CVE list (line 99), replace:

```jsx
                {r.cves.map((id) => {
                  const c = JOEI.CVES[id];
```

with:

```jsx
                {r.cves.map((id) => {
                  const c = JOEI.CVES[id] || { id, severity: "UNKNOWN", cvss: 0, summary: "" };
```

and change `CVSS {c.cvss.toFixed(1)}` to `CVSS {(c.cvss || 0).toFixed(1)}`.

- [ ] **Step 7: Manual verification** (no SPA test harness; this is the verification step for Tasks 10–12).

Build and start a local proxy with the console:

```bash
go build -o bin/jo-ei ./cmd/jo-ei && ./bin/jo-ei --config config.yaml
```

(Use the repo's existing dev `config.yaml` / docker-compose setup; pypi enabled is enough.) Then verify in a browser at `http://localhost:<listen-port>/console/`:

1. Console loads past the torii loader; with no traffic, Overview shows zeros and Live Feed shows the honest empty state (no fake stream).
2. `pip download requests --index-url http://localhost:<port>/pypi/simple/ ...` (or `curl http://localhost:<port>/pypi/packages/...`) — the request appears in the Live Feed within a second (SSE), KPIs update within 15 s.
3. Policy screen: set min age to 48h, Save & apply → toast "Policy applied"; `curl -s localhost:<port>/api/policy` shows `"min_age_hours":48`; downloading a recently published package returns 423 and the package appears in Quarantine.
4. Enter an invalid allowlist entry (`no-slash`), Save → red toast naming `allowlist[0]`, policy unchanged.
5. Stop the proxy with the browser open → red "No connection" banner appears; restart → banner clears (EventSource reconnects), feed resumes, history is empty (honest restart).
6. Registries screen shows the configured upstreams read-only; cache panel shows real object count/size.

- [ ] **Step 8: Commit**

```bash
git add web/console/
git commit -m "feat(web): live feed, overview, quarantine, registries and hero from real proxy state"
```

---

### Task 13: README + final verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document the console API.** In the README's admin-console section (or add one near the configuration docs), add:

```markdown
### Admin console & API

The embedded console at `/console/` shows live proxy state and lets you edit
the effective policy at runtime. It is backed by a JSON API under `/api/`:

| Endpoint | Method | Description |
|---|---|---|
| `/api/overview` | GET | KPIs, per-gate counters, cache stats, configured scanners (since process start) |
| `/api/requests?limit=N` | GET | recent request events, newest first (in-memory ring, last 500) |
| `/api/events` | GET | Server-Sent Events stream of new request events |
| `/api/quarantine` | GET | active supply-chain holds (derived from recent block events) |
| `/api/policy` | GET / PUT | effective policy; PUT validates and applies atomically |
| `/api/registries` | GET | configured registries and upstreams |

Policy edits made through the console are **runtime-only**: they apply
immediately without restart, but the YAML config wins again after a restart.
Event history and counters are in-memory and reset on restart.

> ⚠️ **Known risk — no authentication.** The console and the `/api/`
> endpoints (including `PUT /api/policy`) are open to anyone who can reach
> the proxy port. Run Jōei on a trusted network or behind an authenticating
> reverse proxy. Console/API authentication is planned for a later phase.
```

- [ ] **Step 2: Full verification**

Run: `go build ./... ; go vet ./... ; go test ./... -race -count=1`
Expected: all clean / PASS. Fix anything that fails before claiming completion.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document console API, runtime-only policy and no-auth risk"
```

---

## Out of scope (per spec — do not implement)

- Registry enable/disable and cache invalidation from the console
- Console/API authentication
- Persistent event history and calendar-day metrics
- Vendoring React/Babel (CDN stays)
- Live scanner health probes
