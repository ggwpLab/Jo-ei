package adapters_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNPMAdapter_NormalizeRequest_Tarball(t *testing.T) {
	a := adapters.NewNPMAdapter("https://registry.npmjs.org")

	r := httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-4.17.21.tgz", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "npm", ref.Ecosystem)
	assert.Equal(t, "lodash", ref.Name)
	assert.Equal(t, "4.17.21", ref.Version)
}

func TestNPMAdapter_NormalizeRequest_ScopedTarball(t *testing.T) {
	a := adapters.NewNPMAdapter("https://registry.npmjs.org")

	r := httptest.NewRequest(http.MethodGet, "/@babel/core/-/core-7.24.0.tgz", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "@babel/core", ref.Name)
	assert.Equal(t, "7.24.0", ref.Version)
}

func TestNPMAdapter_NormalizeRequest_MetadataNotIntercepted(t *testing.T) {
	a := adapters.NewNPMAdapter("https://registry.npmjs.org")

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

	a := adapters.NewNPMAdapter(srv.URL)
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

	a := adapters.NewNPMAdapter(srv.URL)
	ref := &proxy.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "9.9.9"}
	_, err := a.FetchMetadata(context.Background(), ref)
	assert.Error(t, err)
}
