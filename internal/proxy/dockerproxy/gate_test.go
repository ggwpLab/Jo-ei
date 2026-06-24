package dockerproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// --- stubs ---

type stubScanner struct {
	findings []proxy.CVEFinding
	err      error
}

func (s stubScanner) ScanImage(_ context.Context, _ string) (*ImageScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &ImageScanResult{Findings: s.findings}, nil
}
func (s stubScanner) Health() health.Sample { return health.Sample{} }

type stubAV struct{ infected bool }

func (s stubAV) Scan(_ context.Context, _ string) (*proxy.AVResult, error) {
	if s.infected {
		return &proxy.AVResult{Clean: false, Signature: "EICAR", Engine: "clamav"}, nil
	}
	return &proxy.AVResult{Clean: true}, nil
}

// allowFilter and policy that allow everything / block on findings.
type allowFilter struct{}

func (allowFilter) Check(_ context.Context, _ *proxy.PackageRef, _ *proxy.PackageMetadata) proxy.FilterResult {
	return proxy.FilterResult{Allowed: true, Reason: "ok"}
}

type findingPolicy struct{}

func (findingPolicy) Evaluate(_ *proxy.PackageRef, r *proxy.ScanResult) proxy.PolicyDecision {
	if r != nil && len(r.Findings) > 0 {
		return proxy.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: r.Findings}
	}
	return proxy.PolicyDecision{Allowed: true, Reason: "ok"}
}

// newGateTestServer starts an httptest server that serves a minimal schema2
// manifest (1 config + 1 layer) for repo "library/test" at tag "latest".
// Returns the server URL, the repo name, and the tag.
func newGateTestServer(t *testing.T) (string, string, string) {
	t.Helper()
	const (
		repo      = "library/test"
		tag       = "latest"
		cfgDigest = "sha256:cfg"
		layDigest = "sha256:layer1"
		imgDigest = "sha256:img"
	)
	cfgBody := `{"created":"2020-01-01T00:00:00Z"}`
	layBody := "layerdata" // 9 bytes

	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     mediaTypeSchema2Manifest,
		"config": map[string]string{
			"mediaType": "application/vnd.docker.container.image.v1+json",
			"digest":    cfgDigest,
		},
		"layers": []map[string]interface{}{
			{
				"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
				"digest":    layDigest,
				"size":      len(layBody),
			},
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/v2/%s/manifests/%s", repo, tag), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", mediaTypeSchema2Manifest)
		w.Header().Set("Docker-Content-Digest", imgDigest)
		_, _ = w.Write(manifestBytes)
	})
	mux.HandleFunc(fmt.Sprintf("/v2/%s/blobs/%s", repo, cfgDigest), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(cfgBody))
	})
	mux.HandleFunc(fmt.Sprintf("/v2/%s/blobs/%s", repo, layDigest), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(layBody))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, repo, tag
}

func TestGateBlocksOnCVE(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t) // serves index-free manifest + config + 1 layer
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}),
		scanner: stubScanner{findings: []proxy.CVEFinding{{ID: "CVE-1", Severity: proxy.SeverityHigh}}},
		av:      stubAV{},
		filter:  allowFilter{},
		policy:  findingPolicy{},
		store:   newVerdictStore(newFakeCache()),
		logger:  zerolog.Nop(),
	}
	g := newManifestGate(d)
	_, v, err := g.Evaluate(context.Background(), repo, ref)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.Reason != "cve_found" || v.BlockedBy != "cve" {
		t.Errorf("verdict = %+v, want blocked cve_found", v)
	}
}

func TestGateBlocksOnMalware(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t)
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}),
		scanner: stubScanner{}, av: stubAV{infected: true},
		filter: allowFilter{}, policy: findingPolicy{},
		store: newVerdictStore(newFakeCache()), logger: zerolog.Nop(),
	}
	_, v, err := newManifestGate(d).Evaluate(context.Background(), repo, ref)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.BlockedBy != "malware" {
		t.Errorf("verdict = %+v, want blocked malware", v)
	}
}

func TestGateAllowsCleanImageAndCachesVerdict(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t)
	store := newVerdictStore(newFakeCache())
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}),
		scanner: stubScanner{}, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{},
		store: store, logger: zerolog.Nop(),
	}
	g := newManifestGate(d)
	digest, v, err := g.Evaluate(context.Background(), repo, ref)
	if err != nil || !v.Allowed {
		t.Fatalf("Evaluate clean: v=%+v err=%v", v, err)
	}
	if _, _, found := store.GetImageVerdict(repo, digest); !found {
		t.Error("clean verdict should be cached by digest")
	}
}

func TestGateFailClosedOnOversizedLayer(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t) // layer body is 9 bytes
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}),
		scanner: stubScanner{}, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{},
		store: newVerdictStore(newFakeCache()), logger: zerolog.Nop(),
		maxLayerBytes: 1, // smaller than the layer → block
	}
	_, v, err := newManifestGate(d).Evaluate(context.Background(), repo, ref)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.BlockedBy != "malware" {
		t.Errorf("oversized layer should fail-closed as malware block, got %+v", v)
	}
}

// newIndexGateServer serves a multi-arch OCI index at "library/test:latest".
func newIndexGateServer(t *testing.T) (string, string, string) {
	t.Helper()
	const (
		repo      = "library/test"
		tag       = "latest"
		idxDigest = "sha256:index"
	)
	index := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     mediaTypeOCIIndex,
		"manifests": []map[string]interface{}{
			{"digest": "sha256:arm", "mediaType": mediaTypeOCIManifest,
				"platform": map[string]string{"os": "linux", "architecture": "arm64"}},
			{"digest": "sha256:amd", "mediaType": mediaTypeOCIManifest,
				"platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/v2/%s/manifests/%s", repo, tag), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mediaTypeOCIIndex)
		w.Header().Set("Docker-Content-Digest", idxDigest)
		_, _ = w.Write(indexBytes)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, repo, tag
}

// TestGatePassesThroughIndex verifies a multi-arch index is served un-gated:
// the scanner and AV (here both set to block) must NOT be consulted, since the
// index has no image content — the concrete child manifest is gated later when
// the client requests it by digest.
func TestGatePassesThroughIndex(t *testing.T) {
	srvURL, repo, ref := newIndexGateServer(t)
	store := newVerdictStore(newFakeCache())
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}),
		// Both would block if consulted; passthrough must skip them.
		scanner: stubScanner{findings: []proxy.CVEFinding{{ID: "CVE-1", Severity: proxy.SeverityHigh}}},
		av:      stubAV{infected: true},
		filter:  allowFilter{},
		policy:  findingPolicy{},
		store:   store,
		logger:  zerolog.Nop(),
	}
	digest, v, err := newManifestGate(d).Evaluate(context.Background(), repo, ref)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !v.Allowed || !v.IsIndex || v.Reason != reasonIndexPassthrough {
		t.Errorf("index should pass through allowed, got %+v", v)
	}
	if digest != "sha256:index" {
		t.Errorf("digest = %q, want sha256:index", digest)
	}
	if clean, reason, found := store.GetImageVerdict(repo, digest); !found || !clean || reason != reasonIndexPassthrough {
		t.Errorf("index verdict should be cached clean: found=%v clean=%v reason=%q", found, clean, reason)
	}
}
