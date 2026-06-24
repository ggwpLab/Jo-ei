package dockerproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestResolveDigest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/v2/library/nginx/manifests/latest" {
			w.Header().Set("Docker-Content-Digest", "sha256:deadbeef")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	a := NewAdapter([]string{srv.URL})
	dg, err := a.ResolveDigest(context.Background(), "library/nginx", "latest")
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if dg != "sha256:deadbeef" {
		t.Errorf("digest = %q", dg)
	}
}

func TestFetchManifestReturnsIndexRaw(t *testing.T) {
	// A multi-arch index must be returned as-is (NOT resolved to a platform):
	// the Docker client selects a platform itself and requests the concrete
	// child manifest by digest, which the gate then scans.
	index := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaTypeOCIIndex,
		"manifests": []map[string]any{
			{"digest": "sha256:arm", "mediaType": mediaTypeOCIManifest,
				"platform": map[string]string{"os": "linux", "architecture": "arm64"}},
			{"digest": "sha256:amd", "mediaType": mediaTypeOCIManifest,
				"platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		},
	}
	indexBody, _ := json.Marshal(index)

	var childRequested bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/library/nginx/manifests/latest":
			w.Header().Set("Content-Type", mediaTypeOCIIndex)
			w.Header().Set("Docker-Content-Digest", "sha256:index")
			_, _ = w.Write(indexBody)
		case "/v2/library/nginx/manifests/sha256:amd":
			childRequested = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	a := NewAdapter([]string{srv.URL})
	body, ct, dg, err := a.FetchManifest(context.Background(), "library/nginx", "latest")
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if dg != "sha256:index" {
		t.Errorf("digest = %q, want sha256:index (the index itself, not a child)", dg)
	}
	if ct != mediaTypeOCIIndex {
		t.Errorf("content-type = %q, want the index media type", ct)
	}
	if string(body) != string(indexBody) {
		t.Errorf("body = %q, want the raw index", body)
	}
	if childRequested {
		t.Error("FetchManifest must not resolve/fetch a child manifest; the client does that")
	}
	if !isIndexMediaType(ct) {
		t.Errorf("isIndexMediaType(%q) = false, want true", ct)
	}
}

func TestImageConfigCreatedAndLayers(t *testing.T) {
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	configBlob, _ := json.Marshal(map[string]any{"created": created.Format(time.RFC3339)})
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaTypeOCIManifest,
		"config":        map[string]any{"digest": "sha256:cfg"},
		"layers": []map[string]any{
			{"digest": "sha256:l1"}, {"digest": "sha256:l2"},
		},
	}
	manifestBody, _ := json.Marshal(manifest)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/library/nginx/blobs/sha256:cfg" {
			_, _ = w.Write(configBlob)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	a := NewAdapter([]string{srv.URL})
	gotCreated, configDigest, layers, err := a.ImageConfig(context.Background(), "library/nginx", manifestBody)
	if err != nil {
		t.Fatalf("ImageConfig: %v", err)
	}
	if !gotCreated.Equal(created) {
		t.Errorf("created = %v, want %v", gotCreated, created)
	}
	if configDigest != "sha256:cfg" {
		t.Errorf("configDigest = %q, want sha256:cfg", configDigest)
	}
	if len(layers) != 2 || layers[0] != "sha256:l1" || layers[1] != "sha256:l2" {
		t.Errorf("layers = %v", layers)
	}
}

func TestHostFromUpstreamNormalizesDockerHub(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{[]string{"https://registry-1.docker.io"}, "docker.io"},
		{[]string{"https://index.docker.io/"}, "docker.io"},
		{[]string{"https://docker.io"}, "docker.io"},
		{[]string{"https://ghcr.io"}, "ghcr.io"},
		{[]string{"https://quay.io/"}, "quay.io"},
		{[]string{"http://localhost:5000"}, "localhost:5000"},
		{nil, ""},
	}
	for _, tt := range tests {
		if got := hostFromUpstream(tt.in); got != tt.want {
			t.Errorf("hostFromUpstream(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
