//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/proxy/dockerproxy"
)

// dockerFakeUpstream serves a minimal Docker Registry V2 for one image.
func dockerFakeUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	configBlob, _ := json.Marshal(map[string]any{"created": "2020-01-01T00:00:00Z"})
	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"digest": "sha256:cfg"},
		"layers": []map[string]any{
			{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:layer1"},
			{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:layer2"},
		},
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/manifests/latest"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", "sha256:img")
			_, _ = w.Write(manifest)
		case strings.HasSuffix(r.URL.Path, "/blobs/sha256:cfg"):
			_, _ = w.Write(configBlob)
		case strings.HasSuffix(r.URL.Path, "/blobs/sha256:layer1"):
			_, _ = w.Write([]byte("layer-one"))
		case strings.HasSuffix(r.URL.Path, "/blobs/sha256:layer2"):
			_, _ = w.Write([]byte("layer-two"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// stubs local to the Docker integration test.

type dockerOKScanner struct{}

func (dockerOKScanner) ScanImage(context.Context, string) (*dockerproxy.ImageScanResult, error) {
	return &dockerproxy.ImageScanResult{}, nil
}

func (dockerOKScanner) Health() health.Sample { return health.Sample{} }

type dockerCleanAV struct{}

func (dockerCleanAV) Scan(context.Context, string) (*gate.AVResult, error) {
	return &gate.AVResult{Clean: true}, nil
}

type dockerAllowAll struct{}

func (dockerAllowAll) Check(context.Context, *gate.PackageRef, *gate.PackageMetadata) gate.FilterResult {
	return gate.FilterResult{Allowed: true, Reason: "ok"}
}

func (dockerAllowAll) Evaluate(*gate.PackageRef, *gate.ScanResult) gate.PolicyDecision {
	return gate.PolicyDecision{Allowed: true, Reason: "ok"}
}

func TestDockerPullFlow(t *testing.T) {
	up := dockerFakeUpstream(t)
	defer up.Close()

	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:   t.TempDir(),
		MaxSizeGB:  1,
		StaleAfter: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	dh := dockerproxy.New(dockerproxy.HandlerDeps{
		Upstreams: []string{up.URL},
		Scanner:   dockerOKScanner{},
		AV:        dockerCleanAV{},
		Filter:    dockerAllowAll{},
		Policy:    dockerAllowAll{},
		Cache:     lc,
		Logger:    zerolog.Nop(),
	})

	// Mimic the mux stripping the /v2 prefix.
	front := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/v2")
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		dh.ServeHTTP(w, r)
	})
	ts := httptest.NewServer(front)
	defer ts.Close()

	// 1. Manifest pull: gate runs, image approved, manifest served.
	resp, err := http.Get(ts.URL + "/v2/library/nginx/manifests/latest")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify manifest body is valid JSON with the expected schema version.
	var m map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&m))
	assert.Equal(t, float64(2), m["schemaVersion"])

	// 2. Layer blob now served from cache (populated during the gate).
	resp2, err := http.Get(ts.URL + "/v2/library/nginx/blobs/sha256:layer1")
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	body, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	assert.Equal(t, "layer-one", string(body))

	// 3. Second layer also cached.
	resp3, err := http.Get(ts.URL + "/v2/library/nginx/blobs/sha256:layer2")
	require.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusOK, resp3.StatusCode)

	body2, err := io.ReadAll(resp3.Body)
	require.NoError(t, err)
	assert.Equal(t, "layer-two", string(body2))

	// 4. Config blob is cached during the gate and served from cache too — a
	// real docker pull fetches it, so a 404 here would break the pull.
	resp4, err := http.Get(ts.URL + "/v2/library/nginx/blobs/sha256:cfg")
	require.NoError(t, err)
	defer resp4.Body.Close()
	assert.Equal(t, http.StatusOK, resp4.StatusCode)

	body3, err := io.ReadAll(resp4.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"created":"2020-01-01T00:00:00Z"}`, string(body3))
}
