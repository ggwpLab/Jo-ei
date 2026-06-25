package dockerproxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

func TestNewAssemblesHandler(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t)
	h := New(HandlerDeps{
		Upstreams:     []string{srvURL},
		Scanner:       stubScanner{},
		AV:            stubAV{},
		Filter:        allowFilter{},
		Policy:        findingPolicy{},
		Cache:         newFakeCache(),
		MaxLayerBytes: 0,
		Recorder:      &recspy{},
		Logger:        zerolog.Nop(),
	})
	req := httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("assembled handler status = %d", w.Code)
	}
}

type recspy struct{ events []proxy.Event }

func (r *recspy) Record(e proxy.Event) { r.events = append(r.events, e) }

func newTestHandler(t *testing.T, sc ImageScanner, av proxy.AVScanner, rec proxy.Recorder) (*Handler, string, string) {
	srvURL, repo, ref := newGateTestServer(t)
	adapter := NewAdapter([]string{srvURL}, nil)
	store := newVerdictStore(newFakeCache())
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: sc, av: av,
		filter: allowFilter{}, policy: findingPolicy{},
		store: store, logger: zerolog.Nop(),
	})
	h := NewHandler(Config{Adapter: adapter, Gate: gate, Store: store, Recorder: rec, Logger: zerolog.Nop()})
	return h, repo, ref
}

func TestHandlerPing(t *testing.T) {
	h, _, _ := newTestHandler(t, stubScanner{}, stubAV{}, &recspy{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ping status = %d", w.Code)
	}
	if w.Header().Get("Docker-Distribution-API-Version") != "registry/2.0" {
		t.Error("missing API version header")
	}
}

func TestHandlerManifestCleanServes(t *testing.T) {
	rec := &recspy{}
	h, repo, ref := newTestHandler(t, stubScanner{}, stubAV{}, rec)
	req := httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("manifest status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(rec.events) != 1 || rec.events[0].Verdict != proxy.VerdictPass {
		t.Errorf("events = %+v", rec.events)
	}
}

func TestHandlerManifestCVEBlocked403(t *testing.T) {
	rec := &recspy{}
	h, repo, ref := newTestHandler(t,
		stubScanner{findings: []proxy.CVEFinding{{ID: "CVE-1", Severity: proxy.SeverityHigh}}},
		stubAV{}, rec)
	req := httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "DENIED") {
		t.Errorf("body = %s", w.Body.String())
	}
	if len(rec.events) != 1 || rec.events[0].Verdict != proxy.VerdictBlock {
		t.Errorf("events = %+v", rec.events)
	}
}

// newMultiArchServer serves a multi-arch index at repo:tag whose amd64 child is
// a concrete schema2 image (config + 1 layer). Returns url, repo, tag, and the
// amd64 child digest the client fetches after platform selection.
func newMultiArchServer(t *testing.T) (url, repo, tag, childDigest string) {
	t.Helper()
	repo, tag, childDigest = "library/test", "3.21", "sha256:amd"
	const (
		cfgDigest = "sha256:cfg"
		layDigest = "sha256:layer1"
	)
	layBody := "layerdata"
	index := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     mediaTypeOCIIndex,
		"manifests": []map[string]interface{}{
			{"digest": "sha256:arm", "mediaType": mediaTypeOCIManifest,
				"platform": map[string]string{"os": "linux", "architecture": "arm64"}},
			{"digest": childDigest, "mediaType": mediaTypeOCIManifest,
				"platform": map[string]string{"os": "linux", "architecture": "amd64"}},
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
		_, _ = w.Write([]byte(`{"created":"2020-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc(fmt.Sprintf("/v2/%s/blobs/%s", repo, layDigest), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(layBody))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, repo, tag, childDigest
}

// A multi-arch pull asks for repo:tag (an index, served un-gated and not
// recorded) and then fetches the platform child manifest by digest (gated and
// recorded). The recorded feed entry must show the human tag, not the opaque
// child digest.
func TestHandlerMultiArchRecordsTagNotDigest(t *testing.T) {
	srvURL, repo, tag, childDigest := newMultiArchServer(t)
	rec := &recspy{}
	h := New(HandlerDeps{
		Upstreams: []string{srvURL},
		Scanner:   stubScanner{},
		AV:        stubAV{},
		Filter:    allowFilter{},
		Policy:    findingPolicy{},
		Cache:     newFakeCache(),
		Recorder:  rec,
		Logger:    zerolog.Nop(),
	})

	// 1. Pull the index by tag: passthrough, not recorded, learns digestв†’tag.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+tag, nil))
	// 2. Pull the platform child by digest: gated and recorded.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+childDigest, nil))

	if w.Code != http.StatusOK {
		t.Fatalf("child manifest status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(rec.events) != 1 {
		t.Fatalf("want exactly 1 event (index passthrough not recorded), got %+v", rec.events)
	}
	if rec.events[0].Version != tag {
		t.Errorf("feed Version = %q, want the tag %q (not the platform digest %q)",
			rec.events[0].Version, tag, childDigest)
	}
}

func TestHandlerIndexPassthroughNoTelemetry(t *testing.T) {
	srvURL, repo, ref := newIndexGateServer(t)
	rec := &recspy{}
	h := New(HandlerDeps{
		Upstreams: []string{srvURL},
		// Both would block a concrete manifest; the index must not be gated.
		Scanner:  stubScanner{findings: []proxy.CVEFinding{{ID: "CVE-1", Severity: proxy.SeverityHigh}}},
		AV:       stubAV{infected: true},
		Filter:   allowFilter{},
		Policy:   findingPolicy{},
		Cache:    newFakeCache(),
		Recorder: rec,
		Logger:   zerolog.Nop(),
	})
	req := httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("index status = %d, want 200", w.Code)
	}
	if len(rec.events) != 0 {
		t.Errorf("index passthrough must not record a feed event, got %+v", rec.events)
	}
}

func TestHandlerSupplyChainBlockRecordsBlockUntil(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t)
	adapter := NewAdapter([]string{srvURL}, nil)
	store := newVerdictStore(newFakeCache())
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: stubScanner{}, av: stubAV{},
		filter: blockFilter{published: time.Now().Add(-time.Hour), blockUntil: time.Now().Add(23 * time.Hour)},
		policy: findingPolicy{},
		store:  store, logger: zerolog.Nop(),
	})
	rec := &recspy{}
	h := NewHandler(Config{Adapter: adapter, Gate: gate, Store: store, Recorder: rec, Logger: zerolog.Nop()})

	pull := func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil))
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
	}
	// Two pulls: the second must not be shadowed by a cached zero-block verdict.
	pull()
	pull()

	if len(rec.events) != 2 {
		t.Fatalf("want 2 block events, got %d: %+v", len(rec.events), rec.events)
	}
	for i, ev := range rec.events {
		if ev.Verdict != proxy.VerdictBlock || ev.Gate != proxy.GateSupply {
			t.Errorf("event %d: verdict=%q gate=%q, want block/supply", i, ev.Verdict, ev.Gate)
		}
		if ev.BlockUntil.IsZero() {
			t.Errorf("event %d: BlockUntil is zero — image will not appear in quarantine", i)
		}
	}
}
