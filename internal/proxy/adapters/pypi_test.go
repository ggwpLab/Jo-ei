package adapters_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
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
					"url":                  "https://files.pythonhosted.org/packages/requests-2.31.0.whl",
					"digests":              map[string]any{"sha256": "abc123"},
				},
			},
		})
	}))
	defer srv.Close()

	a := adapters.NewPyPIAdapter([]string{srv.URL})
	ref := &gate.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)

	assert.WithinDuration(t, uploadTime, meta.PublishedAt, time.Second)
	assert.Equal(t, "Kenneth Reitz", meta.Maintainer)
	assert.Equal(t, "Apache-2.0", meta.License)
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
	ref := &gate.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}
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

func TestPyPIAdapter_NormalizeRequest_FilesOfOneVersionGetDistinctCacheKeys(t *testing.T) {
	a := adapters.NewPyPIAdapter([]string{"https://pypi.org"})
	paths := []string{
		"/packages/cp311/n/numpy/numpy-1.26.4-cp311-cp311-manylinux_2_17_x86_64.whl",
		"/packages/cp312/n/numpy/numpy-1.26.4-cp312-cp312-win_amd64.whl",
		"/packages/source/n/numpy/numpy-1.26.4.tar.gz",
	}
	keys := map[string]bool{}
	for _, p := range paths {
		ref, ok := a.NormalizeRequest(httptest.NewRequest(http.MethodGet, p, nil))
		require.True(t, ok, p)
		assert.Equal(t, "numpy", ref.Name)
		assert.Equal(t, "1.26.4", ref.Version)
		keys[ref.Key()] = true
	}
	assert.Len(t, keys, len(paths), "each distribution file needs its own cache slot")
}

func TestPyPIAdapter_NormalizeRequest_NameNormalizedPerPEP503(t *testing.T) {
	a := adapters.NewPyPIAdapter([]string{"https://pypi.org"})
	cases := map[string]string{
		"/packages/source/z/zope.interface/zope.interface-5.4.0.tar.gz": "zope-interface",
		"/packages/source/b/backports/Backports.Zoneinfo-0.2.1.tar.gz":  "backports-zoneinfo",
		"/packages/py3/f/foo/Foo__Bar-1.0-py3-none-any.whl":             "foo-bar",
		"/packages/py3/f/foo/foo_._bar-1.0-py3-none-any.whl":            "foo-bar",
	}
	for p, want := range cases {
		ref, ok := a.NormalizeRequest(httptest.NewRequest(http.MethodGet, p, nil))
		require.True(t, ok, p)
		assert.Equal(t, want, ref.Name, p)
	}
}

// pypiRelease serves a /pypi/<name>/<version>/json document listing files.
func pypiRelease(t *testing.T, files map[string]time.Time) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urls := []map[string]any{}
		for name, at := range files {
			urls = append(urls, map[string]any{
				"filename":             name,
				"upload_time_iso_8601": at.Format(time.RFC3339),
				"url":                  "https://files.pythonhosted.org/packages/xx/" + name,
				"digests":              map[string]any{"sha256": "00"},
			})
		}
		json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]any{"name": "evil", "version": "1.0"},
			"urls": urls,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPyPIAdapter_FetchMetadata_UsesTheRequestedFilesUploadTime(t *testing.T) {
	old := time.Now().UTC().Add(-2 * 365 * 24 * time.Hour).Truncate(time.Second)
	fresh := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	srv := pypiRelease(t, map[string]time.Time{
		"evil-1.0.tar.gz": old,
		"evil-1.0-cp312-cp312-manylinux_x86_64.whl": fresh, // added to the old release later
	})

	a := adapters.NewPyPIAdapter([]string{srv.URL})
	ref := &gate.PackageRef{Ecosystem: "pypi", Name: "evil", Version: "1.0",
		Classifier: "evil-1.0-cp312-cp312-manylinux_x86_64.whl"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, fresh, meta.PublishedAt, time.Second)
}

func TestPyPIAdapter_FetchMetadata_FileMissingFromReleaseIsAnError(t *testing.T) {
	srv := pypiRelease(t, map[string]time.Time{"evil-1.0.tar.gz": time.Now().Add(-48 * time.Hour)})

	a := adapters.NewPyPIAdapter([]string{srv.URL})
	ref := &gate.PackageRef{Ecosystem: "pypi", Name: "evil", Version: "1.0", Classifier: "evil-1.0-py3-none-any.whl"}
	_, err := a.FetchMetadata(context.Background(), ref)
	assert.Error(t, err)
}

func TestPyPIAdapter_FetchMetadata_WithoutFileUsesNewestUpload(t *testing.T) {
	old := time.Now().UTC().Add(-700 * 24 * time.Hour).Truncate(time.Second)
	fresh := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	srv := pypiRelease(t, map[string]time.Time{"evil-1.0.tar.gz": old, "evil-1.0-py3-none-any.whl": fresh})

	a := adapters.NewPyPIAdapter([]string{srv.URL})
	meta, err := a.FetchMetadata(context.Background(), &gate.PackageRef{Ecosystem: "pypi", Name: "evil", Version: "1.0"})
	require.NoError(t, err)
	assert.WithinDuration(t, fresh, meta.PublishedAt, time.Second)
}
