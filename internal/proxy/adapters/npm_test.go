package adapters_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNPMAdapter_NormalizeRequest_Tarball(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	r := httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-4.17.21.tgz", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "npm", ref.Ecosystem)
	assert.Equal(t, "lodash", ref.Name)
	assert.Equal(t, "4.17.21", ref.Version)
}

func TestNPMAdapter_NormalizeRequest_ScopedTarball(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	r := httptest.NewRequest(http.MethodGet, "/@babel/core/-/core-7.24.0.tgz", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "@babel/core", ref.Name)
	assert.Equal(t, "7.24.0", ref.Version)
}

func TestNPMAdapter_NormalizeRequest_MetadataNotIntercepted(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	r := httptest.NewRequest(http.MethodGet, "/lodash", nil)
	_, ok := a.NormalizeRequest(r)
	assert.False(t, ok)
}

func TestNPMAdapter_FetchMetadata(t *testing.T) {
	publishedAt := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/lodash", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"time": map[string]any{
				"4.17.21": publishedAt.Format(time.RFC3339),
			},
			"versions": map[string]any{
				"4.17.21": map[string]any{
					"license": "MIT",
					"dist":    map[string]any{"shasum": "abc123sha1"},
				},
			},
		})
	}))
	defer srv.Close()

	a := adapters.NewNPMAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)

	assert.WithinDuration(t, publishedAt, meta.PublishedAt, time.Second)
	assert.Equal(t, "MIT", meta.License)
	assert.Equal(t, "abc123sha1", meta.Checksum)
}

func TestNPMAdapter_FetchMetadata_VersionMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"time": map[string]any{}, "versions": map[string]any{}})
	}))
	defer srv.Close()

	a := adapters.NewNPMAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "9.9.9"}
	_, err := a.FetchMetadata(context.Background(), ref)
	assert.Error(t, err)
}

func TestNPMAdapter_NormalizeRequest_EmptyVersionRejected(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})
	r := httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-.tgz", nil)
	_, ok := a.NormalizeRequest(r)
	assert.False(t, ok)
}

func TestNPMAdapter_FetchMetadata_VersionInTimeButNotVersions(t *testing.T) {
	publishedAt := time.Now().UTC().Add(-48 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"time":     map[string]any{"1.0.0": publishedAt.Format(time.RFC3339)},
			"versions": map[string]any{}, // version absent from versions map
		})
	}))
	defer srv.Close()

	a := adapters.NewNPMAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"}
	_, err := a.FetchMetadata(context.Background(), ref)
	assert.Error(t, err)
}

func TestNPMAdapter_FetchMetadata_FallsBackToSecondUpstream(t *testing.T) {
	published := time.Now().UTC().Add(-72 * time.Hour)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"time": map[string]string{"1.0.0": published.Format(time.RFC3339)},
			"versions": map[string]any{
				"1.0.0": map[string]any{"license": "MIT", "dist": map[string]any{"shasum": "abc"}},
			},
		})
	}))
	defer up.Close()

	a := adapters.NewNPMAdapter([]string{down.URL, up.URL})
	ref := &proxy.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, published, meta.PublishedAt, time.Second)
}

func TestNPMAdapter_UpstreamURLs_OnePerUpstream(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org/", "https://mirror.example.org"})
	r := httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-1.0.0.tgz", nil)
	urls := a.UpstreamURLs(r)
	assert.Equal(t, []string{
		"https://registry.npmjs.org/lodash/-/lodash-1.0.0.tgz",
		"https://mirror.example.org/lodash/-/lodash-1.0.0.tgz",
	}, urls)
}
