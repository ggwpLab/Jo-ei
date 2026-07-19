package dockerproxy

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
)

// countingScanner wraps stubScanner and counts ScanImage calls so tests can
// tell a fresh evaluation from a cached-verdict short-circuit.
type countingScanner struct {
	stubScanner
	calls *int
}

func (s countingScanner) ScanImage(ctx context.Context, ref string) (*ImageScanResult, error) {
	*s.calls++
	return s.stubScanner.ScanImage(ctx, ref)
}

// errScanner simulates a scanner infrastructure outage (e.g. Trivy down).
type errScanner struct{}

func (errScanner) ScanImage(context.Context, string) (*ImageScanResult, error) {
	return nil, context.DeadlineExceeded
}

func (errScanner) Health() health.Sample { return health.Sample{} }

// newRecheckGate builds a manifest gate over the shared fake registry with the
// given TTL and scanner, returning the gate, its store, and the repo name.
func newRecheckGate(t *testing.T, sc ImageScanner, ttl time.Duration, c *fakeCache) (*manifestGate, *verdictStore, string) {
	t.Helper()
	srvURL, repo, _ := newGateTestServer(t)
	adapter := NewAdapter([]string{srvURL}, nil)
	store := newVerdictStore(c)
	g := newManifestGate(gateDeps{
		adapter: adapter, scanner: sc, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{},
		store: store, tags: newTagIndex(0), recheckTTL: ttl, logger: zerolog.Nop(),
	})
	return g, store, repo
}

// rewindVerdict pushes the image verdict's check timestamps into the past.
func rewindVerdict(c *fakeCache, repo, digest string, d time.Duration) {
	e := c.entries[imageRefKey(repo, digest).Key()]
	e.LastCVECheck = e.LastCVECheck.Add(-d)
	e.LastMalwareCheck = e.LastMalwareCheck.Add(-d)
}

func TestGateRecheck_FreshVerdictShortCircuits(t *testing.T) {
	c := newFakeCache()
	calls := 0
	g, _, repo := newRecheckGate(t, countingScanner{calls: &calls}, time.Hour, c)

	// First evaluation stores the verdict…
	digest, v, err := g.Evaluate(context.Background(), repo, "latest")
	if err != nil || !v.Allowed {
		t.Fatalf("seed evaluate: v=%+v err=%v", v, err)
	}
	// …the repeat pull inside the TTL must not re-scan.
	before := calls
	_, v2, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil || !v2.FromCache {
		t.Fatalf("repeat evaluate: v=%+v err=%v, want FromCache", v2, err)
	}
	if calls != before {
		t.Fatalf("fresh cached verdict must not re-scan (calls %d→%d)", before, calls)
	}
}

func TestGateRecheck_ExpiredVerdictReScans(t *testing.T) {
	c := newFakeCache()
	calls := 0
	g, _, repo := newRecheckGate(t, countingScanner{calls: &calls}, time.Hour, c)

	digest, _, err := g.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	rewindVerdict(c, repo, digest, 2*time.Hour)
	before := calls
	_, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil || !v.Allowed {
		t.Fatalf("re-eval: v=%+v err=%v", v, err)
	}
	if calls == before {
		t.Fatal("expired verdict must force a fresh scan")
	}
	if v.FromCache {
		t.Fatal("a fresh re-evaluation must not be marked FromCache")
	}
}

func TestGateRecheck_ExpiredBlockCascadesBlobs(t *testing.T) {
	c := newFakeCache()
	calls := 0
	sc := countingScanner{calls: &calls}
	g, store, repo := newRecheckGate(t, sc, time.Hour, c)

	digest, _, err := g.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	// The seed evaluation cached the config/layer blobs (fake registry serves
	// sha256:cfg + sha256:layer1 — see newGateTestServer).
	rewindVerdict(c, repo, digest, 2*time.Hour)

	// Now the scanner finds a blocking CVE.
	g.scanner = countingScanner{
		stubScanner: stubScanner{findings: []gate.CVEFinding{{ID: "CVE-1", Severity: gate.SeverityHigh}}},
		calls:       &calls,
	}
	_, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil || v.Allowed {
		t.Fatalf("re-eval: v=%+v err=%v, want block", v, err)
	}
	if _, _, found := store.GetBlob("sha256:cfg"); found {
		t.Error("config blob must be cascade-evicted on re-check block")
	}
	if _, _, found := store.GetBlob("sha256:layer1"); found {
		t.Error("layer blob must be cascade-evicted on re-check block")
	}
}

func TestGateRecheck_ScanErrorServesStaleVerdict(t *testing.T) {
	c := newFakeCache()
	calls := 0
	g, _, repo := newRecheckGate(t, countingScanner{calls: &calls}, time.Hour, c)

	digest, _, err := g.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	rewindVerdict(c, repo, digest, 2*time.Hour)
	g.scanner = errScanner{}
	_, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil {
		t.Fatalf("scanner outage on re-check must serve the stale verdict, got err %v", err)
	}
	if !v.Allowed || !v.FromCache {
		t.Fatalf("v=%+v, want stale allowed FromCache verdict", v)
	}
}

func TestGateRecheck_ZeroTTLNeverExpires(t *testing.T) {
	c := newFakeCache()
	calls := 0
	g, _, repo := newRecheckGate(t, countingScanner{calls: &calls}, 0, c)

	digest, _, err := g.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	rewindVerdict(c, repo, digest, 1000*time.Hour)
	before := calls
	_, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil || !v.FromCache || calls != before {
		t.Fatalf("TTL 0: verdict must never expire (v=%+v err=%v calls %d→%d)", v, err, before, calls)
	}
}

// gatedImageScanner blocks ScanImage until release is closed. Counts calls.
type gatedImageScanner struct {
	stubScanner
	release chan struct{}
	calls   atomic.Int32
}

func (s *gatedImageScanner) ScanImage(ctx context.Context, ref string) (*ImageScanResult, error) {
	s.calls.Add(1)
	<-s.release
	return s.stubScanner.ScanImage(ctx, ref)
}

func TestGateCoalesce_ParallelEvaluateSingleScan(t *testing.T) {
	c := newFakeCache()
	sc := &gatedImageScanner{release: make(chan struct{})}
	g, _, repo := newRecheckGate(t, sc, time.Hour, c)

	const n = 6
	type result struct {
		v   GateVerdict
		err error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, v, err := g.Evaluate(context.Background(), repo, "latest")
			results[i] = result{v, err}
		}(i)
	}
	// Wait for the leader to reach the scanner, settle so followers join the
	// flight, then release.
	require.Eventually(t, func() bool { return sc.calls.Load() >= 1 },
		5*time.Second, 5*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	close(sc.release)
	wg.Wait()

	if got := sc.calls.Load(); got != 1 {
		t.Fatalf("ScanImage called %d times, want 1 (parallel evaluations must coalesce)", got)
	}
	for i, r := range results {
		if r.err != nil || !r.v.Allowed {
			t.Fatalf("result %d: v=%+v err=%v, want shared allowed verdict", i, r.v, r.err)
		}
	}
}

// writeManifestFile writes a minimal schema2 manifest (with mediaType) to a
// temp file and returns its path.
func writeManifestFile(t *testing.T) string {
	t.Helper()
	body := `{"schemaVersion":2,"mediaType":"` + mediaTypeSchema2Manifest + `",` +
		`"config":{"digest":"sha256:cfg"},"layers":[{"digest":"sha256:layer1"}]}`
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// deadGate builds a manifest gate over the given store whose upstream is
// unreachable, for offline-serving tests.
func deadGate(ttl time.Duration, c *fakeCache) (*manifestGate, *verdictStore) {
	adapter := NewAdapter([]string{"http://127.0.0.1:1"}, nil)
	store := newVerdictStore(c)
	g := newManifestGate(gateDeps{
		adapter: adapter, scanner: stubScanner{}, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{},
		store: store, tags: newTagIndex(0), recheckTTL: ttl, logger: zerolog.Nop(),
	})
	return g, store
}

func TestFastPath_FreshVerdictServedWithoutUpstream(t *testing.T) {
	c := newFakeCache()
	// Seed through a live registry, then re-point at a dead upstream.
	liveG, _, repo := newRecheckGate(t, stubScanner{}, time.Hour, c)
	digest, seeded, err := liveG.Evaluate(context.Background(), repo, "latest")
	if err != nil || !seeded.Allowed {
		t.Fatalf("seed: v=%+v err=%v", seeded, err)
	}

	g, _ := deadGate(time.Hour, c)
	gotDigest, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil {
		t.Fatalf("fresh by-digest pull must not touch the upstream: %v", err)
	}
	if gotDigest != digest || !v.Allowed || !v.FromCache {
		t.Fatalf("digest=%s v=%+v, want cached allowed verdict for %s", gotDigest, v, digest)
	}
	if v.ManifestPath == "" || v.ContentType == "" {
		t.Fatalf("fast path must carry manifest path and sniffed content type, got %+v", v)
	}
}

func TestFastPath_FreshBlockedVerdictServes403WithoutUpstream(t *testing.T) {
	c := newFakeCache()
	g, store := deadGate(time.Hour, c)
	if err := store.PutImageVerdict("library/app", "sha256:bad", writeManifestFile(t), false, "cve_found"); err != nil {
		t.Fatal(err)
	}
	_, v, err := g.Evaluate(context.Background(), "library/app", "sha256:bad")
	if err != nil {
		t.Fatalf("blocked fast path must not touch the upstream: %v", err)
	}
	if v.Allowed || v.BlockedBy != "cve" || !v.FromCache {
		t.Fatalf("v=%+v, want cached cve block", v)
	}
}

func TestFastPath_ExpiredVerdictDeadUpstreamServesStale(t *testing.T) {
	c := newFakeCache()
	liveG, _, repo := newRecheckGate(t, stubScanner{}, time.Hour, c)
	digest, _, err := liveG.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	rewindVerdict(c, repo, digest, 2*time.Hour)

	g, _ := deadGate(time.Hour, c)
	_, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil {
		t.Fatalf("expired by-digest + dead upstream must serve stale, got err %v", err)
	}
	if !v.Allowed || !v.FromCache {
		t.Fatalf("v=%+v, want stale allowed verdict", v)
	}
}

func TestFastPath_NoVerdictDeadUpstreamFailsClosed(t *testing.T) {
	c := newFakeCache()
	g, _ := deadGate(time.Hour, c)
	_, _, err := g.Evaluate(context.Background(), "library/app", "sha256:unknown")
	if err == nil {
		t.Fatal("no cached verdict + dead upstream must fail closed")
	}
}

func TestFastPath_MissingMediaTypeFallsThroughToFetch(t *testing.T) {
	c := newFakeCache()
	liveG, store, repo := newRecheckGate(t, stubScanner{}, time.Hour, c)
	digest, _, err := liveG.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	// Overwrite the stored body with one lacking a top-level mediaType.
	p := filepath.Join(t.TempDir(), "untyped.json")
	if err := os.WriteFile(p, []byte(`{"schemaVersion":2,"config":{"digest":"sha256:cfg"},"layers":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.PutImageVerdict(repo, digest, p, true, "ok"); err != nil {
		t.Fatal(err)
	}
	// Live upstream: the fall-through fetch succeeds and still serves.
	_, v, err := liveG.Evaluate(context.Background(), repo, digest)
	if err != nil || !v.Allowed {
		t.Fatalf("v=%+v err=%v, want allowed via fetch fall-through", v, err)
	}
}
