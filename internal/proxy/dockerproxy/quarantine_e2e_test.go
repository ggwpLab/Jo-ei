package dockerproxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// youngRegistry serves a single-arch schema2 image whose config.created is `age`
// in the past, so the real supply-chain filter (min_age 24h) blocks it.
func youngRegistry(t *testing.T, age time.Duration) (url, repo, tag string) {
	t.Helper()
	repo, tag = "library/test", "latest"
	const (
		cfgDigest = "sha256:cfg"
		layDigest = "sha256:layer1"
		imgDigest = "sha256:img"
	)
	created := time.Now().Add(-age).UTC().Format(time.RFC3339)
	cfgBody := fmt.Sprintf(`{"created":%q}`, created)
	layBody := "layerdata"
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     mediaTypeSchema2Manifest,
		"config":        map[string]string{"mediaType": "application/vnd.docker.container.image.v1+json", "digest": cfgDigest},
		"layers": []map[string]interface{}{
			{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": layDigest, "size": len(layBody)},
		},
	}
	manifestBytes, _ := json.Marshal(manifest)
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/v2/%s/manifests/%s", repo, tag), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mediaTypeSchema2Manifest)
		w.Header().Set("Docker-Content-Digest", imgDigest)
		_, _ = w.Write(manifestBytes)
	})
	mux.HandleFunc(fmt.Sprintf("/v2/%s/blobs/%s", repo, cfgDigest), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(cfgBody))
	})
	mux.HandleFunc(fmt.Sprintf("/v2/%s/blobs/%s", repo, layDigest), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(layBody))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, repo, tag
}

// TestDockerSupplyBlockReachesQuarantine drives the FULL pipeline: a young image
// pulled through the Docker handler with the REAL supply-chain filter and the
// REAL SQLite telemetry store, then asserts it appears in Store.Quarantine().
func TestDockerSupplyBlockReachesQuarantine(t *testing.T) {
	srvURL, repo, tag := youngRegistry(t, 1*time.Hour) // 1h old < 24h min-age → blocked

	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := telemetry.Open(db, 30, 365, zerolog.Nop())
	if err != nil {
		t.Fatalf("open telemetry: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	filter := supplychain.NewFilter(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		supplychain.NewAllowlist(nil),
	)
	adapter := NewAdapter([]string{srvURL}, nil)
	vstore := newVerdictStore(newFakeCache())
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: stubScanner{}, av: stubAV{},
		filter: filter, policy: findingPolicy{},
		store: vstore, logger: zerolog.Nop(),
	})
	h := NewHandler(Config{Adapter: adapter, Gate: gate, Store: vstore, Recorder: store, Logger: zerolog.Nop()})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+tag, nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("pull status = %d, body=%s (expected 403 supply block)", w.Code, w.Body.String())
	}

	q := store.Quarantine(time.Now())
	if len(q) != 1 {
		t.Fatalf("Quarantine returned %d entries, want 1: %+v", len(q), q)
	}
	if q[0].Ecosystem != "docker" {
		t.Errorf("quarantine entry eco = %q, want docker", q[0].Ecosystem)
	}
}

// seedStaleSupplyBlock caches a supply-chain block the way the PRE-FIX build did
// (verdict store persists only clean+reason, never the block_until timestamp).
func seedStaleSupplyBlock(t *testing.T, adapter *Adapter, vstore *verdictStore, repo, ref string) {
	t.Helper()
	body, _, digest, err := adapter.FetchManifest(t.Context(), repo, ref)
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	tmp := filepath.Join(t.TempDir(), "manifest")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := vstore.PutImageVerdict(repo, digest, tmp, false, "package_younger_than_min_age"); err != nil {
		t.Fatalf("seed verdict: %v", err)
	}
}

// TestStaleCachedSupplyBlockIsReEvaluated guards the user-reported regression: a
// supply-chain block cached by a PRE-FIX build is restored from cache with
// BlockUntil zero (the store does not persist timestamps), so the image is
// blocked but never enters Quarantine. The gate must ignore such a stale entry
// and re-evaluate, producing a fresh block that carries block_until.
func TestStaleCachedSupplyBlockIsReEvaluated(t *testing.T) {
	srvURL, repo, tag := youngRegistry(t, 1*time.Hour) // still young → re-eval re-blocks
	adapter := NewAdapter([]string{srvURL}, nil)
	vstore := newVerdictStore(newFakeCache())
	seedStaleSupplyBlock(t, adapter, vstore, repo, tag)

	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: stubScanner{}, av: stubAV{},
		filter: supplychain.NewFilter(config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24}, supplychain.NewAllowlist(nil)),
		policy: findingPolicy{}, store: vstore, logger: zerolog.Nop(),
	})
	_, v, err := gate.Evaluate(t.Context(), repo, tag)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.BlockedBy != "supply_chain" {
		t.Fatalf("young image should still be supply-blocked after re-eval, got %+v", v)
	}
	if v.BlockUntil.IsZero() {
		t.Fatal("stale cached supply block was trusted (BlockUntil=0) → image blocked but never quarantined")
	}
}

// TestStaleCachedSupplyBlockClearsAfterMaturity is the other half: an image that
// has since matured past min-age must be ALLOWED on re-pull, not held forever by
// a stale cached block (the latent staleness bug the no-cache decision fixes).
func TestStaleCachedSupplyBlockClearsAfterMaturity(t *testing.T) {
	srvURL, repo, tag := youngRegistry(t, 48*time.Hour) // matured: 48h > 24h min-age
	adapter := NewAdapter([]string{srvURL}, nil)
	vstore := newVerdictStore(newFakeCache())
	seedStaleSupplyBlock(t, adapter, vstore, repo, tag)

	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: stubScanner{}, av: stubAV{},
		filter: supplychain.NewFilter(config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24}, supplychain.NewAllowlist(nil)),
		policy: findingPolicy{}, store: vstore, logger: zerolog.Nop(),
	})
	_, v, err := gate.Evaluate(t.Context(), repo, tag)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !v.Allowed {
		t.Fatalf("matured image must be allowed after re-eval, got %+v", v)
	}
}

// youngMultiArchRegistry serves a multi-arch OCI index whose amd64 child is a
// young schema2 image (config.created `age` in the past).
func youngMultiArchRegistry(t *testing.T, age time.Duration) (url, repo, tag, childDigest string) {
	t.Helper()
	repo, tag, childDigest = "library/test", "latest", "sha256:amd"
	const (
		cfgDigest = "sha256:cfg"
		layDigest = "sha256:layer1"
	)
	created := time.Now().Add(-age).UTC().Format(time.RFC3339)
	cfgBody := fmt.Sprintf(`{"created":%q}`, created)
	layBody := "layerdata"
	index := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     mediaTypeOCIIndex,
		"manifests": []map[string]interface{}{
			{"digest": "sha256:arm", "mediaType": mediaTypeOCIManifest, "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
			{"digest": childDigest, "mediaType": mediaTypeOCIManifest, "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		},
	}
	child := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     mediaTypeSchema2Manifest,
		"config":        map[string]string{"digest": cfgDigest},
		"layers": []map[string]interface{}{
			{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": layDigest, "size": len(layBody)},
		},
	}
	indexBytes, _ := json.Marshal(index)
	childBytes, _ := json.Marshal(child)
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/v2/%s/manifests/%s", repo, tag), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mediaTypeOCIIndex)
		w.Header().Set("Docker-Content-Digest", "sha256:index")
		_, _ = w.Write(indexBytes)
	})
	mux.HandleFunc(fmt.Sprintf("/v2/%s/manifests/%s", repo, childDigest), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mediaTypeSchema2Manifest)
		w.Header().Set("Docker-Content-Digest", childDigest)
		_, _ = w.Write(childBytes)
	})
	mux.HandleFunc(fmt.Sprintf("/v2/%s/blobs/%s", repo, cfgDigest), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(cfgBody))
	})
	mux.HandleFunc(fmt.Sprintf("/v2/%s/blobs/%s", repo, layDigest), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(layBody))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, repo, tag, childDigest
}

// TestDockerMultiArchSupplyBlockReachesQuarantine reproduces the production flow:
// pull a young multi-arch image by tag (index passthrough), then the platform
// child by digest (supply block), and assert the image lands in Quarantine().
func TestDockerMultiArchSupplyBlockReachesQuarantine(t *testing.T) {
	srvURL, repo, tag, childDigest := youngMultiArchRegistry(t, 1*time.Hour)

	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := telemetry.Open(db, 30, 365, zerolog.Nop())
	if err != nil {
		t.Fatalf("open telemetry: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	filter := supplychain.NewFilter(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		supplychain.NewAllowlist(nil),
	)
	adapter := NewAdapter([]string{srvURL}, nil)
	vstore := newVerdictStore(newFakeCache())
	tags := newTagIndex(0)
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: stubScanner{}, av: stubAV{},
		filter: filter, policy: findingPolicy{}, tags: tags,
		store: vstore, logger: zerolog.Nop(),
	})
	h := NewHandler(Config{Adapter: adapter, Gate: gate, Store: vstore, Tags: tags, Recorder: store, Logger: zerolog.Nop()})

	// 1. Pull index by tag → passthrough (not recorded), populates digest→tag.
	wIdx := httptest.NewRecorder()
	h.ServeHTTP(wIdx, httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+tag, nil))
	if wIdx.Code != http.StatusOK {
		t.Fatalf("index pull status = %d, body=%s", wIdx.Code, wIdx.Body.String())
	}
	// 2. Pull platform child by digest → supply block.
	wChild := httptest.NewRecorder()
	h.ServeHTTP(wChild, httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+childDigest, nil))
	if wChild.Code != http.StatusForbidden {
		t.Fatalf("child pull status = %d, body=%s (expected 403 supply block)", wChild.Code, wChild.Body.String())
	}

	q := store.Quarantine(time.Now())
	if len(q) != 1 {
		t.Fatalf("Quarantine returned %d entries, want 1: %+v", len(q), q)
	}
	if q[0].Ecosystem != "docker" || q[0].Version != tag {
		t.Errorf("quarantine entry = eco %q ver %q, want docker/%s", q[0].Ecosystem, q[0].Version, tag)
	}
}
