package dockerproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
)

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// attestationUpstream serves repo:att — an attestation manifest whose config
// and layers are blobs — plus each blob's body. extra layers may be added.
type attestationUpstream struct {
	repo   string
	config []byte
	layers []attLayer
	bodies map[string][]byte // digest → body served (may differ from content, for mismatch tests)
}

type attLayer struct {
	mediaType string
	body      []byte
}

func (u *attestationUpstream) start(t *testing.T) string {
	t.Helper()
	if u.bodies == nil {
		u.bodies = map[string][]byte{}
	}
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaTypeOCIManifest,
		"config":        map[string]string{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": sha(u.config)},
	}
	if _, ok := u.bodies[sha(u.config)]; !ok {
		u.bodies[sha(u.config)] = u.config
	}
	var layers []map[string]any
	for _, l := range u.layers {
		layers = append(layers, map[string]any{"mediaType": l.mediaType, "digest": sha(l.body), "size": len(l.body)})
		if _, ok := u.bodies[sha(l.body)]; !ok {
			u.bodies[sha(l.body)] = l.body
		}
	}
	manifest["layers"] = layers
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/v2/%s/manifests/att", u.repo), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mediaTypeOCIManifest)
		w.Header().Set("Docker-Content-Digest", sha(body))
		_, _ = w.Write(body)
	})
	mux.HandleFunc(fmt.Sprintf("/v2/%s/blobs/", u.repo), func(w http.ResponseWriter, r *http.Request) {
		d := r.URL.Path[len(fmt.Sprintf("/v2/%s/blobs/", u.repo)):]
		b, ok := u.bodies[d]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		_, _ = w.Write(b)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func attHandler(upstreamURL string, c cache.Cache) http.Handler {
	return New(HandlerDeps{
		Upstreams: []string{upstreamURL},
		Scanner:   stubScanner{},
		AV:        stubAV{infected: true}, // must never be consulted for attestation content
		Filter:    allowFilter{},
		Policy:    findingPolicy{},
		Cache:     c,
		Recorder:  &recspy{},
		Logger:    zerolog.Nop(),
	})
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

var (
	sbom       = []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document"}`)
	attConfig  = []byte(`{"architecture":"unknown","os":"unknown"}`)
	inTotoType = "application/vnd.in-toto+json"
)

func TestHandlerServesAttestationBlobs(t *testing.T) {
	up := &attestationUpstream{repo: "library/test", config: attConfig, layers: []attLayer{{inTotoType, sbom}}}
	h := attHandler(up.start(t), newFakeCache())

	if w := get(h, "/library/test/manifests/att"); w.Code != http.StatusOK {
		t.Fatalf("manifest status = %d", w.Code)
	}
	for _, body := range [][]byte{attConfig, sbom} {
		w := get(h, "/library/test/blobs/"+sha(body))
		if w.Code != http.StatusOK {
			t.Fatalf("blob %s status = %d", sha(body), w.Code)
		}
		if !bytes.Equal(w.Body.Bytes(), body) {
			t.Errorf("blob body = %q", w.Body.String())
		}
		if w.Header().Get("Docker-Content-Digest") != sha(body) {
			t.Errorf("Docker-Content-Digest = %q", w.Header().Get("Docker-Content-Digest"))
		}
		if w.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
			t.Errorf("Content-Length = %q", w.Header().Get("Content-Length"))
		}
	}
}

// A passthrough manifest that also lists a filesystem layer must not open an
// unscanned route to that layer: tar layers are only ever served from the
// gated cache.
func TestHandlerAttestationNeverServesFilesystemLayer(t *testing.T) {
	tarLayer := []byte("pretend-this-is-a-tar.gz")
	up := &attestationUpstream{repo: "library/test", config: attConfig, layers: []attLayer{
		{"application/vnd.oci.image.layer.v1.tar+gzip", tarLayer},
		{inTotoType, sbom},
	}}
	h := attHandler(up.start(t), newFakeCache())
	get(h, "/library/test/manifests/att")

	if w := get(h, "/library/test/blobs/"+sha(tarLayer)); w.Code != http.StatusNotFound {
		t.Errorf("filesystem layer status = %d, want 404", w.Code)
	}
	if w := get(h, "/library/test/blobs/"+sha(sbom)); w.Code != http.StatusOK {
		t.Errorf("in-toto layer status = %d, want 200", w.Code)
	}
}

// After a restart the manifest is served from the cached verdict without the
// gate re-reading it; its blobs must still be served.
func TestHandlerAttestationBlobsAfterCachedManifest(t *testing.T) {
	up := &attestationUpstream{repo: "library/test", config: attConfig, layers: []attLayer{{inTotoType, sbom}}}
	url := up.start(t)
	shared := newFakeCache()
	get(attHandler(url, shared), "/library/test/manifests/att")

	restarted := attHandler(url, shared)
	if w := get(restarted, "/library/test/manifests/att"); w.Code != http.StatusOK {
		t.Fatalf("cached manifest status = %d", w.Code)
	}
	if w := get(restarted, "/library/test/blobs/"+sha(sbom)); w.Code != http.StatusOK {
		t.Errorf("blob after cached manifest status = %d, want 200", w.Code)
	}
}

func TestHandlerAttestationBlobDigestMismatch(t *testing.T) {
	up := &attestationUpstream{repo: "library/test", config: attConfig, layers: []attLayer{{inTotoType, sbom}},
		bodies: map[string][]byte{sha(sbom): []byte("tampered")}}
	h := attHandler(up.start(t), newFakeCache())
	get(h, "/library/test/manifests/att")

	w := get(h, "/library/test/blobs/"+sha(sbom))
	if w.Code == http.StatusOK {
		t.Fatal("served a blob whose bytes do not match its digest")
	}
	if bytes.Contains(w.Body.Bytes(), []byte("tampered")) {
		t.Error("mismatching bytes leaked to the client")
	}
}

func TestHandlerAttestationBlobOversized(t *testing.T) {
	big := bytes.Repeat([]byte("x"), maxAttestationBlobBytes+1)
	up := &attestationUpstream{repo: "library/test", config: attConfig, layers: []attLayer{{inTotoType, big}}}
	h := attHandler(up.start(t), newFakeCache())
	get(h, "/library/test/manifests/att")

	if w := get(h, "/library/test/blobs/"+sha(big)); w.Code == http.StatusOK {
		t.Error("served an attestation blob over the size cap")
	}
}

func TestHandlerAttestationBlobRepoScoped(t *testing.T) {
	up := &attestationUpstream{repo: "library/test", config: attConfig, layers: []attLayer{{inTotoType, sbom}}}
	h := attHandler(up.start(t), newFakeCache())
	get(h, "/library/test/manifests/att")

	if w := get(h, "/library/other/blobs/"+sha(sbom)); w.Code != http.StatusNotFound {
		t.Errorf("status under another repo = %d, want 404", w.Code)
	}
}

func TestAttestationBlobs_Bounded(t *testing.T) {
	a := newAttestationBlobs(2)
	for _, d := range []string{"sha256:a", "sha256:b", "sha256:c"} {
		a.add("r", d)
	}
	if a.has("r", "sha256:a") {
		t.Error("oldest entry should have been evicted")
	}
	if !a.has("r", "sha256:b") || !a.has("r", "sha256:c") {
		t.Error("newest entries should remain")
	}
}
