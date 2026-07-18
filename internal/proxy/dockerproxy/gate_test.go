package dockerproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
)

// --- stubs ---

type stubScanner struct {
	findings []gate.CVEFinding
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

func (s stubAV) Scan(_ context.Context, _ string) (*gate.AVResult, error) {
	if s.infected {
		return &gate.AVResult{Clean: false, Signature: "EICAR", Engine: "clamav"}, nil
	}
	return &gate.AVResult{Clean: true}, nil
}

// allowFilter and policy that allow everything / block on findings.
type allowFilter struct{}

func (allowFilter) Check(_ context.Context, _ *gate.PackageRef, _ *gate.PackageMetadata) gate.FilterResult {
	return gate.FilterResult{Allowed: true, Reason: "ok"}
}

type findingPolicy struct{}

func (findingPolicy) Evaluate(_ *gate.PackageRef, r *gate.ScanResult) gate.PolicyDecision {
	if r != nil && len(r.Findings) > 0 {
		return gate.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: r.Findings}
	}
	return gate.PolicyDecision{Allowed: true, Reason: "ok"}
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
	serveManifest := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", mediaTypeSchema2Manifest)
		w.Header().Set("Docker-Content-Digest", imgDigest)
		_, _ = w.Write(manifestBytes)
	}
	mux.HandleFunc(fmt.Sprintf("/v2/%s/manifests/%s", repo, tag), serveManifest)
	// Also serve by digest so re-validation (which calls Evaluate with a digest
	// ref rather than a tag) can fetch the manifest without a 404.
	mux.HandleFunc(fmt.Sprintf("/v2/%s/manifests/%s", repo, imgDigest), serveManifest)
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
		adapter: NewAdapter([]string{srvURL}, nil),
		scanner: stubScanner{findings: []gate.CVEFinding{{ID: "CVE-1", Severity: gate.SeverityHigh}}},
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
		adapter: NewAdapter([]string{srvURL}, nil),
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
		adapter: NewAdapter([]string{srvURL}, nil),
		scanner: stubScanner{}, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{},
		store: store, logger: zerolog.Nop(),
	}
	g := newManifestGate(d)
	digest, v, err := g.Evaluate(context.Background(), repo, ref)
	if err != nil || !v.Allowed {
		t.Fatalf("Evaluate clean: v=%+v err=%v", v, err)
	}
	if _, _, _, found := store.GetImageVerdict(repo, digest); !found {
		t.Error("clean verdict should be cached by digest")
	}
}

func TestGateFailClosedOnOversizedLayer(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t) // layer body is 9 bytes
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}, nil),
		scanner: stubScanner{}, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{},
		store: newVerdictStore(newFakeCache()), logger: zerolog.Nop(),
		maxLayerBytes: 1, // smaller than the layer в†’ block
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
// index has no image content вЂ” the concrete child manifest is gated later when
// the client requests it by digest.
func TestGatePassesThroughIndex(t *testing.T) {
	srvURL, repo, ref := newIndexGateServer(t)
	store := newVerdictStore(newFakeCache())
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}, nil),
		// Both would block if consulted; passthrough must skip them.
		scanner: stubScanner{findings: []gate.CVEFinding{{ID: "CVE-1", Severity: gate.SeverityHigh}}},
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
	if !v.Allowed || !v.Passthrough || v.Reason != reasonIndexPassthrough {
		t.Errorf("index should pass through allowed, got %+v", v)
	}
	if digest != "sha256:index" {
		t.Errorf("digest = %q, want sha256:index", digest)
	}
	if clean, reason, _, found := store.GetImageVerdict(repo, digest); !found || !clean || reason != reasonIndexPassthrough {
		t.Errorf("index verdict should be cached clean: found=%v clean=%v reason=%q", found, clean, reason)
	}
}

// newAttestationGateServer serves a buildx attestation manifest (layers are
// in-toto JSON, not a filesystem) at "library/test:att".
func newAttestationGateServer(t *testing.T) (string, string, string) {
	t.Helper()
	const (
		repo      = "library/test"
		ref       = "att"
		attDigest = "sha256:att"
	)
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     mediaTypeOCIManifest,
		"config": map[string]string{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    "sha256:attcfg",
		},
		"layers": []map[string]interface{}{
			{"mediaType": "application/vnd.in-toto+json", "digest": "sha256:sbom"},
			{"mediaType": "application/vnd.in-toto+json", "digest": "sha256:provenance"},
		},
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal attestation manifest: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/v2/%s/manifests/%s", repo, ref), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mediaTypeOCIManifest)
		w.Header().Set("Docker-Content-Digest", attDigest)
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, repo, ref
}

// TestGatePassesThroughAttestation verifies an attestation manifest (in-toto
// layers) is served un-gated: Trivy/ClamAV (both set to block) must NOT be
// consulted, since it carries no scannable filesystem content. Without this the
// gate would hand it to Trivy and fail every pull with "invalid tar header".
func TestGatePassesThroughAttestation(t *testing.T) {
	srvURL, repo, ref := newAttestationGateServer(t)
	store := newVerdictStore(newFakeCache())
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}, nil),
		scanner: stubScanner{findings: []gate.CVEFinding{{ID: "CVE-1", Severity: gate.SeverityHigh}}},
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
	if !v.Allowed || !v.Passthrough || v.Reason != reasonAttestationPassthrough {
		t.Errorf("attestation should pass through allowed, got %+v", v)
	}
	if digest != "sha256:att" {
		t.Errorf("digest = %q, want sha256:att", digest)
	}
}

// blockFilter denies every package as "younger than min age", echoing the
// published/block-until timestamps the real supply-chain filter would return.
type blockFilter struct {
	published  time.Time
	blockUntil time.Time
}

func (f blockFilter) Check(_ context.Context, _ *gate.PackageRef, _ *gate.PackageMetadata) gate.FilterResult {
	return gate.FilterResult{
		Allowed:     false,
		Reason:      "package_younger_than_min_age",
		PublishedAt: f.published,
		BlockUntil:  f.blockUntil,
	}
}

func TestGateSupplyChainBlockCarriesTimesAndIsNotCached(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t)
	published := time.Now().Add(-1 * time.Hour)
	until := time.Now().Add(23 * time.Hour)
	store := newVerdictStore(newFakeCache())
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}, nil),
		scanner: stubScanner{}, av: stubAV{},
		filter: blockFilter{published: published, blockUntil: until},
		policy: findingPolicy{},
		store:  store, logger: zerolog.Nop(),
	}
	digest, v, err := newManifestGate(d).Evaluate(context.Background(), repo, ref)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.BlockedBy != "supply_chain" {
		t.Fatalf("verdict = %+v, want supply_chain block", v)
	}
	if v.BlockUntil.IsZero() || v.PublishedAt.IsZero() {
		t.Errorf("supply block must carry BlockUntil/PublishedAt, got %+v", v)
	}
	if _, _, _, found := store.GetImageVerdict(repo, digest); found {
		t.Error("time-based supply-chain block must NOT be cached")
	}
}
