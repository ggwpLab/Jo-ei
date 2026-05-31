package adapters_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMavenAdapter_NormalizeRequest_Jar(t *testing.T) {
	a := adapters.NewMavenAdapter("https://repo1.maven.org/maven2")

	r := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "maven", ref.Ecosystem)
	assert.Equal(t, "com.google.guava:guava", ref.Name)
	assert.Equal(t, "31.0.1-jre", ref.Version)
}

func TestMavenAdapter_NormalizeRequest_PomNotIntercepted(t *testing.T) {
	a := adapters.NewMavenAdapter("https://repo1.maven.org/maven2")

	r := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.pom", nil)
	_, ok := a.NormalizeRequest(r)
	assert.False(t, ok)
}

func TestMavenAdapter_FetchMetadata_UsesLastModified(t *testing.T) {
	lastModified := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		assert.Equal(t, "/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar", r.URL.Path)
		w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := adapters.NewMavenAdapter(srv.URL)
	ref := &proxy.PackageRef{Ecosystem: "maven", Name: "com.google.guava:guava", Version: "31.0.1-jre"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, lastModified, meta.PublishedAt, time.Second)
}

func TestMavenAdapter_FetchMetadata_NoLastModifiedYieldsZeroTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // no Last-Modified header
	}))
	defer srv.Close()

	a := adapters.NewMavenAdapter(srv.URL)
	ref := &proxy.PackageRef{Ecosystem: "maven", Name: "com.google.guava:guava", Version: "31.0.1-jre"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.True(t, meta.PublishedAt.IsZero())
}
