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

// Only a manifest whose every layer is in-toto is an attestation. Anything
// else — a canonical tar layer, or a layer type the gate's list does not know
// (which containerd may still unpack) — is gated like an image, and none of its
// blobs is ever relayed unscanned.
func TestHandlerNonAttestationLayersNeverRelayed(t *testing.T) {
	for _, mt := range []string{
		"application/vnd.oci.image.layer.v1.tar+gzip",
		"application/vnd.docker.image.rootfs.diff.tar",
		"application/vnd.oci.image.layer.v1.tar+gzip; foo=bar",
		"application/vnd.oci.image.layer.v1.TAR+gzip",
		"application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
		"application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
		"",
		"application/octet-stream",
		"application/vnd.cncf.helm.chart.content.v1.tar+gzip",
	} {
		layer := []byte("layer-bytes-for " + mt)
		for _, layers := range [][]attLayer{{{mt, layer}}, {{mt, layer}, {inTotoType, sbom}}} {
			up := &attestationUpstream{repo: "evil/img", config: attConfig, layers: layers}
			h := attHandler(up.start(t), newFakeCache())

			get(h, "/evil/img/manifests/att")
			if w := get(h, "/evil/img/blobs/"+sha(layer)); w.Code == http.StatusOK {
				t.Errorf("type %q (%d layers): layer relayed unscanned", mt, len(layers))
			}
			if w := get(h, "/evil/img/blobs/"+sha(attConfig)); w.Code == http.StatusOK {
				t.Errorf("type %q (%d layers): config relayed for a non-attestation manifest", mt, len(layers))
			}
		}
	}
}

func TestIsAttestationManifest(t *testing.T) {
	mk := func(types ...string) []byte {
		var ls []map[string]string
		for i, mt := range types {
			ls = append(ls, map[string]string{"mediaType": mt, "digest": fmt.Sprintf("sha256:%d", i)})
		}
		b, _ := json.Marshal(map[string]any{"layers": ls})
		return b
	}
	for _, tc := range []struct {
		body []byte
		want bool
	}{
		{mk(inTotoType), true},
		{mk(inTotoType, "application/vnd.in-toto+json"), true},
		{mk(" Application/VND.IN-TOTO+JSON ; charset=utf-8"), true},
		{mk(inTotoType, "application/vnd.oci.image.layer.v1.tar+gzip"), false},
		{mk("application/vnd.docker.image.rootfs.diff.tar"), false},
		{mk(), false},
		{mk(make([]string, maxAttestationLayers+1)...), false},
	} {
		if got := isAttestationManifest(tc.body); got != tc.want {
			t.Errorf("isAttestationManifest(%s) = %v, want %v", tc.body, got, tc.want)
		}
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
