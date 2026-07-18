package dockerproxy

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"

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
