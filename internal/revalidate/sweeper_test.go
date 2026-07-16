package revalidate

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
)

type fakeStore struct {
	mu          sync.Mutex
	due         []cache.RevalEntry
	lastBefore  int64
	lastLimit   int
	validated   []gate.PackageRef
	invalidated []gate.PackageRef
}

func (f *fakeStore) DueForRevalidation(before int64, limit int) ([]cache.RevalEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastBefore, f.lastLimit = before, limit
	out := f.due
	f.due = nil // consumed
	return out, nil
}
func (f *fakeStore) MarkValidated(ref *gate.PackageRef, _ int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validated = append(f.validated, *ref)
	return nil
}
func (f *fakeStore) Invalidate(ref *gate.PackageRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidated = append(f.invalidated, *ref)
	return nil
}

type stubRevalidator struct {
	outcome Outcome
	reason  *EvictReason
}

func (s stubRevalidator) Revalidate(context.Context, cache.RevalEntry) (Outcome, *EvictReason) {
	return s.outcome, s.reason
}

type recspy struct{ events []gate.Event }

func (r *recspy) Record(e gate.Event) { r.events = append(r.events, e) }

func pkgEntry(name string) cache.RevalEntry {
	return cache.RevalEntry{Ref: gate.PackageRef{Ecosystem: "pypi", Name: name, Version: "1.0"}}
}

func TestSweeper_KeepBumpsValidated(t *testing.T) {
	store := &fakeStore{due: []cache.RevalEntry{pkgEntry("a")}}
	s := NewSweeper(store, map[string]Revalidator{"pypi": stubRevalidator{outcome: Keep}}, &recspy{}, Config{BatchSize: 10}, zerolog.Nop())
	s.sweepOnce(context.Background())
	assert.Equal(t, []gate.PackageRef{{Ecosystem: "pypi", Name: "a", Version: "1.0"}}, store.validated)
	assert.Empty(t, store.invalidated)
}

func TestSweeper_EvictInvalidatesAndRecords(t *testing.T) {
	store := &fakeStore{due: []cache.RevalEntry{pkgEntry("bad")}}
	rec := &recspy{}
	reason := &EvictReason{Gate: gate.GateMalware, Reason: "malware_found", BlockedBy: "malware", Engine: "clamav", Signature: "EICAR"}
	s := NewSweeper(store, map[string]Revalidator{"pypi": stubRevalidator{outcome: Evict, reason: reason}}, rec, Config{BatchSize: 10}, zerolog.Nop())
	s.sweepOnce(context.Background())

	require.Len(t, store.invalidated, 1)
	assert.Equal(t, "bad", store.invalidated[0].Name)
	assert.Empty(t, store.validated)
	require.Len(t, rec.events, 1)
	ev := rec.events[0]
	assert.Equal(t, gate.VerdictBlock, ev.Verdict)
	assert.Equal(t, gate.GateMalware, ev.Gate)
	assert.Equal(t, "revalidation", ev.RequestID)
	assert.Equal(t, "EICAR", ev.MalwareSignature)
	assert.Equal(t, []string{"malware"}, ev.BlockedBy)
}

func TestSweeper_RetryLeavesEntry(t *testing.T) {
	store := &fakeStore{due: []cache.RevalEntry{pkgEntry("x")}}
	s := NewSweeper(store, map[string]Revalidator{"pypi": stubRevalidator{outcome: Retry}}, &recspy{}, Config{BatchSize: 10}, zerolog.Nop())
	s.sweepOnce(context.Background())
	assert.Empty(t, store.validated)
	assert.Empty(t, store.invalidated)
}

func TestSweeper_UnknownEcosystemSkipped(t *testing.T) {
	store := &fakeStore{due: []cache.RevalEntry{{Ref: gate.PackageRef{Ecosystem: "go", Name: "m", Version: "1"}}}}
	s := NewSweeper(store, map[string]Revalidator{"pypi": stubRevalidator{outcome: Keep}}, &recspy{}, Config{BatchSize: 10}, zerolog.Nop())
	s.sweepOnce(context.Background())
	assert.Empty(t, store.validated)
	assert.Empty(t, store.invalidated)
}

func TestSweeper_LogsSweepSummary(t *testing.T) {
	store := &fakeStore{due: []cache.RevalEntry{
		pkgEntry("a"), // pypi → Keep
		{Ref: gate.PackageRef{Ecosystem: "npm", Name: "bad", Version: "1"}}, // Evict
		{Ref: gate.PackageRef{Ecosystem: "maven", Name: "x", Version: "1"}}, // Retry
		{Ref: gate.PackageRef{Ecosystem: "go", Name: "m", Version: "1"}},    // no revalidator → skipped
	}}
	var buf bytes.Buffer
	s := NewSweeper(store, map[string]Revalidator{
		"pypi":  stubRevalidator{outcome: Keep},
		"npm":   stubRevalidator{outcome: Evict, reason: &EvictReason{Gate: gate.GateCVE, Reason: "cve_found", BlockedBy: "cve"}},
		"maven": stubRevalidator{outcome: Retry},
	}, &recspy{}, Config{BatchSize: 10}, zerolog.New(&buf))
	s.sweepOnce(context.Background())

	out := buf.String()
	require.Contains(t, out, "revalidation sweep complete")
	assert.Contains(t, out, `"due":4`)
	assert.Contains(t, out, `"kept":1`)
	assert.Contains(t, out, `"evicted":1`)
	assert.Contains(t, out, `"retried":1`)
	assert.Contains(t, out, `"skipped":1`)
	assert.Contains(t, out, `"level":"info"`)
}

func TestSweeper_NothingDueLogsDebugOnly(t *testing.T) {
	var buf bytes.Buffer
	s := NewSweeper(&fakeStore{}, map[string]Revalidator{}, &recspy{}, Config{BatchSize: 10}, zerolog.New(&buf))
	s.sweepOnce(context.Background())

	out := buf.String()
	assert.NotContains(t, out, "revalidation sweep complete", "no info summary when nothing was due")
	assert.Contains(t, out, `"level":"debug"`)
	assert.Contains(t, out, "nothing due")
}

func TestSweeper_PassesBatchSizeAndCutoff(t *testing.T) {
	store := &fakeStore{}
	s := NewSweeper(store, map[string]Revalidator{}, &recspy{}, Config{BatchSize: 7, RevalidateAfter: 0}, zerolog.Nop())
	s.sweepOnce(context.Background())
	assert.Equal(t, 7, store.lastLimit)
}

func TestSweeper_StartCloseDoesNotHang(t *testing.T) {
	store := &fakeStore{}
	// Interval 0 must not panic — Start normalises it to the default.
	s := NewSweeper(store, map[string]Revalidator{}, &recspy{}, Config{Interval: 0, BatchSize: 1}, zerolog.Nop())
	s.Start()
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return — goroutine leak or deadlock")
	}
}

func TestSweeper_DoubleStartIsSafe(t *testing.T) {
	store := &fakeStore{}
	s := NewSweeper(store, map[string]Revalidator{}, &recspy{}, Config{Interval: time.Hour, BatchSize: 1}, zerolog.Nop())
	s.Start()
	s.Start() // second call must be a no-op (sync.Once), not leak a goroutine
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after double Start")
	}
}
