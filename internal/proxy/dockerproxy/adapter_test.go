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

func TestFetchManifestSelectsPlatformFromIndex(t *testing.T) {
	amd64Manifest := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`
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

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/library/nginx/manifests/latest":
			w.Header().Set("Content-Type", mediaTypeOCIIndex)
			w.Header().Set("Docker-Content-Digest", "sha256:index")
			_, _ = w.Write(indexBody)
		case "/v2/library/nginx/manifests/sha256:amd":
			w.Header().Set("Content-Type", mediaTypeOCIManifest)
			w.Header().Set("Docker-Content-Digest", "sha256:amd")
			_, _ = w.Write([]byte(amd64Manifest))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	a := NewAdapter([]string{srv.URL})
	body, ct, dg, err := a.FetchManifest(context.Background(), "library/nginx", "latest", "linux/amd64")
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if dg != "sha256:amd" {
		t.Errorf("selected digest = %q, want sha256:amd", dg)
	}
	if ct != mediaTypeOCIManifest {
		t.Errorf("content-type = %q", ct)
	}
	if string(body) != amd64Manifest {
		t.Errorf("body = %q", body)
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
