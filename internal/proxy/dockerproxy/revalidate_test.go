package dockerproxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/revalidate"
)

// writeManifest writes a schema2 image manifest (config + 1 layer) to a temp
// file and returns its path; mirrors newGateTestServer's image.
func writeManifest(t *testing.T) string {
	t.Helper()
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     mediaTypeSchema2Manifest,
		"config":        map[string]string{"digest": "sha256:cfg"},
		"layers": []map[string]interface{}{
			{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": "sha256:layer1"},
		},
	}
	b, _ := json.Marshal(manifest)
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestRevalidator(t *testing.T, sc ImageScanner, av gate.AVScanner, pol gate.PolicyDecider, c cache.Cache) (*Revalidator, string) {
	srvURL, repo, _ := newGateTestServer(t)
	adapter := NewAdapter([]string{srvURL}, nil)
	store := newVerdictStore(c)
	mgate := newManifestGate(gateDeps{
		adapter: adapter, scanner: sc, av: av,
		filter: allowFilter{}, policy: pol,
		store: store, tags: newTagIndex(0), logger: zerolog.Nop(),
	})
	return &Revalidator{gate: mgate, cache: c}, repo
}

func TestDockerRevalidator_CleanKeeps(t *testing.T) {
	c := newFakeCache()
	r, repo := newTestRevalidator(t, stubScanner{}, stubAV{}, findingPolicy{}, c)
	e := cache.RevalEntry{Ref: gate.PackageRef{Ecosystem: "docker", Name: repo, Version: "sha256:img"}, FilePath: writeManifest(t)}
	out, reason := r.Revalidate(context.Background(), e)
	if out != revalidate.Keep || reason != nil {
		t.Fatalf("out=%v reason=%v, want Keep/nil", out, reason)
	}
}

func TestDockerRevalidator_CVEBlockEvictsAndCascades(t *testing.T) {
	c := newFakeCache()
	// Pre-cache the two blobs so we can assert they are invalidated on eviction.
	tmp := filepath.Join(t.TempDir(), "b")
	_ = os.WriteFile(tmp, []byte("x"), 0o600)
	store := newVerdictStore(c)
	_ = store.PutBlob("sha256:cfg", tmp, true)
	_ = store.PutBlob("sha256:layer1", tmp, true)

	r, repo := newTestRevalidator(t,
		stubScanner{findings: []gate.CVEFinding{{ID: "CVE-1", Severity: gate.SeverityHigh}}},
		stubAV{}, findingPolicy{}, c)
	e := cache.RevalEntry{Ref: gate.PackageRef{Ecosystem: "docker", Name: repo, Version: "sha256:img"}, FilePath: writeManifest(t)}

	out, reason := r.Revalidate(context.Background(), e)
	if out != revalidate.Evict {
		t.Fatalf("out=%v, want Evict", out)
	}
	if reason == nil || reason.BlockedBy != "cve" {
		t.Fatalf("reason=%+v, want blocked_by cve", reason)
	}
	if _, _, found := store.GetBlob("sha256:cfg"); found {
		t.Error("config blob should have been cascade-invalidated")
	}
	if _, _, found := store.GetBlob("sha256:layer1"); found {
		t.Error("layer blob should have been cascade-invalidated")
	}
}

// countingScanner wraps stubScanner and counts ScanImage calls, so tests can
// assert the revalidation path actually re-scanned rather than trusting a
// cached verdict.
type countingScanner struct {
	stubScanner
	calls *int
}

func (s countingScanner) ScanImage(ctx context.Context, ref string) (*ImageScanResult, error) {
	*s.calls++
	return s.stubScanner.ScanImage(ctx, ref)
}

// TestDockerRevalidator_IgnoresOwnCachedVerdict is the CRITICAL regression
// test: the image-verdict entry under revalidation is, by definition, already
// in the cache as clean. Revalidate must NOT let manifestGate.Evaluate
// short-circuit on that cached verdict — it must re-run Trivy/ClamAV so a
// newly-blocking CVE is caught. Before the fix, Evaluate's cached-verdict
// check returns the stale clean verdict without ever calling the scanner, so
// this asserts Evict where the unfixed code returns Keep.
func TestDockerRevalidator_IgnoresOwnCachedVerdict(t *testing.T) {
	c := newFakeCache()
	calls := 0
	scanner := countingScanner{
		stubScanner: stubScanner{findings: []gate.CVEFinding{{ID: "CVE-9999", Severity: gate.SeverityHigh}}},
		calls:       &calls,
	}
	r, repo := newTestRevalidator(t, scanner, stubAV{}, findingPolicy{}, c)

	// Seed the cache with the clean verdict that a prior pull would have
	// stored for this exact repo+digest — the state Revalidate always starts
	// from, since it is only ever invoked on entries already in the cache.
	store := newVerdictStore(c)
	if err := store.PutImageVerdict(repo, "sha256:img", writeManifest(t), true, "ok"); err != nil {
		t.Fatalf("seeding cached verdict: %v", err)
	}

	e := cache.RevalEntry{Ref: gate.PackageRef{Ecosystem: "docker", Name: repo, Version: "sha256:img"}, FilePath: writeManifest(t)}
	out, reason := r.Revalidate(context.Background(), e)
	if out != revalidate.Evict {
		t.Fatalf("out=%v, want Evict (a fresh scan must find the new CVE despite the stale cached clean verdict)", out)
	}
	if reason == nil || reason.BlockedBy != "cve" {
		t.Fatalf("reason=%+v, want blocked_by cve", reason)
	}
	if calls == 0 {
		t.Error("scanner was never called — Revalidate short-circuited on the cached verdict instead of re-evaluating")
	}
}

// TestDockerRevalidator_CachedCleanStillReScans is the inverse of the above:
// even when the fresh scan agrees the image is still clean, Revalidate must
// have actually run the scanner rather than trusting the cache — this proves
// the fresh-evaluation path isn't simply evicting everything unconditionally.
func TestDockerRevalidator_CachedCleanStillReScans(t *testing.T) {
	c := newFakeCache()
	calls := 0
	scanner := countingScanner{stubScanner: stubScanner{}, calls: &calls}
	r, repo := newTestRevalidator(t, scanner, stubAV{}, findingPolicy{}, c)

	store := newVerdictStore(c)
	if err := store.PutImageVerdict(repo, "sha256:img", writeManifest(t), true, "ok"); err != nil {
		t.Fatalf("seeding cached verdict: %v", err)
	}

	e := cache.RevalEntry{Ref: gate.PackageRef{Ecosystem: "docker", Name: repo, Version: "sha256:img"}, FilePath: writeManifest(t)}
	out, reason := r.Revalidate(context.Background(), e)
	if out != revalidate.Keep || reason != nil {
		t.Fatalf("out=%v reason=%v, want Keep/nil", out, reason)
	}
	if calls == 0 {
		t.Error("scanner was never called — Revalidate must re-scan even a cached-clean entry, not trust the cache")
	}
}

func TestDockerRevalidator_BlobEntryIsNoOp(t *testing.T) {
	c := newFakeCache()
	r, _ := newTestRevalidator(t, stubScanner{}, stubAV{}, findingPolicy{}, c)
	e := cache.RevalEntry{Ref: gate.PackageRef{Ecosystem: "docker", Name: "blobs", Version: "sha256:layer1"}}
	out, reason := r.Revalidate(context.Background(), e)
	if out != revalidate.Keep || reason != nil {
		t.Fatalf("out=%v reason=%v, want Keep/nil for blob entry", out, reason)
	}
}

func TestDockerRevalidator_GateErrorRetries(t *testing.T) {
	c := newFakeCache()
	// Adapter pointed at a dead upstream → FetchManifest fails → Retry.
	adapter := NewAdapter([]string{"http://127.0.0.1:1"}, nil)
	store := newVerdictStore(c)
	mgate := newManifestGate(gateDeps{
		adapter: adapter, scanner: stubScanner{}, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{}, store: store,
		tags: newTagIndex(0), logger: zerolog.Nop(),
	})
	r := &Revalidator{gate: mgate, cache: c}
	e := cache.RevalEntry{Ref: gate.PackageRef{Ecosystem: "docker", Name: "library/test", Version: "sha256:img"}, FilePath: writeManifest(t)}
	out, _ := r.Revalidate(context.Background(), e)
	if out != revalidate.Retry {
		t.Fatalf("out=%v, want Retry", out)
	}
}
