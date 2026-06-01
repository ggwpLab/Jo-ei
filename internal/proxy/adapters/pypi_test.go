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

func TestPyPIAdapter_NormalizeRequest_WheelDownload(t *testing.T) {
	a := adapters.NewPyPIAdapter([]string{"https://pypi.org"})

	r := httptest.NewRequest(http.MethodGet,
		"/packages/cp312/r/requests/requests-2.32.0-py3-none-any.whl", nil)

	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "pypi", ref.Ecosystem)
	assert.Equal(t, "requests", ref.Name)
	assert.Equal(t, "2.32.0", ref.Version)
}

func TestPyPIAdapter_NormalizeRequest_TarGzDownload(t *testing.T) {
	a := adapters.NewPyPIAdapter([]string{"https://pypi.org"})

	r := httptest.NewRequest(http.MethodGet,
		"/packages/source/r/requests/requests-2.32.0.tar.gz", nil)

	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "requests", ref.Name)
	assert.Equal(t, "2.32.0", ref.Version)
}

func TestPyPIAdapter_NormalizeRequest_SimpleAPINotIntercepted(t *testing.T) {
	a := adapters.NewPyPIAdapter([]string{"https://pypi.org"})

	r := httptest.NewRequest(http.MethodGet, "/simple/requests/", nil)
	_, ok := a.NormalizeRequest(r)
	assert.False(t, ok)
}

func TestPyPIAdapter_NormalizeRequest_UnderscoreNormalization(t *testing.T) {
	a := adapters.NewPyPIAdapter([]string{"https://pypi.org"})

	r := httptest.NewRequest(http.MethodGet,
		"/packages/source/m/my_package/my_package-1.0.0.tar.gz", nil)

	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	// PyPI normalizes underscores to dashes
	assert.Equal(t, "my-package", ref.Name)
}

func TestPyPIAdapter_FetchMetadata(t *testing.T) {
	uploadTime := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/pypi/requests/2.31.0/json", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]any{
				"name":    "requests",
				"version": "2.31.0",
				"license": "Apache-2.0",
				"author":  "Kenneth Reitz",
			},
			"urls": []map[string]any{
				{
					"upload_time_iso_8601": uploadTime.Format(time.RFC3339),
					"url":                 "https://files.pythonhosted.org/packages/requests-2.31.0.whl",
					"digests":             map[string]any{"sha256": "abc123"},
				},
			},
		})
	}))
	defer srv.Close()

	a := adapters.NewPyPIAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)

	assert.WithinDuration(t, uploadTime, meta.PublishedAt, time.Second)
	assert.Equal(t, "Kenneth Reitz", meta.Maintainer)
	assert.Equal(t, "Apache-2.0", meta.License)
	assert.Equal(t, "abc123", meta.Checksum)
}

func TestPyPIAdapter_FetchMetadata_FallsBackToSecondUpstream(t *testing.T) {
	published := time.Now().UTC().Add(-72 * time.Hour)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]any{"name": "requests", "version": "2.31.0", "license": "MIT", "author": "x"},
			"urls": []map[string]any{{
				"upload_time_iso_8601": published.Format(time.RFC3339),
				"url":                  "https://example.com/requests.whl",
				"digests":              map[string]any{"sha256": "abc"},
			}},
		})
	}))
	defer up.Close()

	a := adapters.NewPyPIAdapter([]string{down.URL, up.URL})
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, published, meta.PublishedAt, time.Second)
}

func TestPyPIAdapter_UpstreamURLs_OnePerUpstream(t *testing.T) {
	a := adapters.NewPyPIAdapter([]string{"https://pypi.org/", "https://mirror.example.org"})
	r := httptest.NewRequest(http.MethodGet, "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl", nil)
	urls := a.UpstreamURLs(r)
	assert.Equal(t, []string{
		"https://pypi.org/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl",
		"https://mirror.example.org/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl",
	}, urls)
}
