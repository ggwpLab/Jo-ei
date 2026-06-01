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
	a := adapters.NewMavenAdapter([]string{"https://repo1.maven.org/maven2"})

	r := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "maven", ref.Ecosystem)
	assert.Equal(t, "com.google.guava:guava", ref.Name)
	assert.Equal(t, "31.0.1-jre", ref.Version)
}

func TestMavenAdapter_NormalizeRequest_PomNotIntercepted(t *testing.T) {
	a := adapters.NewMavenAdapter([]string{"https://repo1.maven.org/maven2"})

	r := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.pom", nil)
	_, ok := a.NormalizeRequest(r)
	assert.False(t, ok)
}

func TestMavenAdapter_FetchMetadata_UsesLastModified(t *testing.T) {
	lastModified := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		assert.Equal(t, "/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.pom", r.URL.Path)
		w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := adapters.NewMavenAdapter([]string{srv.URL})
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

	a := adapters.NewMavenAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "maven", Name: "com.google.guava:guava", Version: "31.0.1-jre"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.True(t, meta.PublishedAt.IsZero())
}

func TestMavenAdapter_NormalizeRequest_WarAndAar(t *testing.T) {
	a := adapters.NewMavenAdapter([]string{"https://repo1.maven.org/maven2"})
	cases := []struct {
		path        string
		wantName    string
		wantVersion string
	}{
		{"/com/example/myapp/1.0/myapp-1.0.war", "com.example:myapp", "1.0"},
		{"/com/example/mylib/2.3.4/mylib-2.3.4.aar", "com.example:mylib", "2.3.4"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, c.path, nil)
		ref, ok := a.NormalizeRequest(r)
		require.True(t, ok, "path %q", c.path)
		assert.Equal(t, c.wantName, ref.Name, "path %q", c.path)
		assert.Equal(t, c.wantVersion, ref.Version, "path %q", c.path)
	}
}

func TestMavenAdapter_FetchMetadata_WarUsesPomHead(t *testing.T) {
	lastModified := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		// Even though the intercepted artifact was a .war, metadata HEADs the .pom.
		assert.Equal(t, "/com/example/myapp/1.0/myapp-1.0.pom", r.URL.Path)
		w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := adapters.NewMavenAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "maven", Name: "com.example:myapp", Version: "1.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, lastModified, meta.PublishedAt, time.Second)
}

func TestMavenAdapter_FetchMetadata_NonOKReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	a := adapters.NewMavenAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "maven", Name: "com.example:gone", Version: "9.9.9"}
	_, err := a.FetchMetadata(context.Background(), ref)
	assert.Error(t, err)
}

func TestMavenAdapter_FetchMetadata_FallsBackToSecondUpstream(t *testing.T) {
	lastModified := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	a := adapters.NewMavenAdapter([]string{down.URL, up.URL})
	ref := &proxy.PackageRef{Ecosystem: "maven", Name: "com.google.guava:guava", Version: "31.0.1-jre"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, lastModified, meta.PublishedAt, time.Second)
}

func TestMavenAdapter_FetchMetadata_AllUpstreamsFail(t *testing.T) {
	down1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down1.Close()
	down2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down2.Close()

	a := adapters.NewMavenAdapter([]string{down1.URL, down2.URL})
	ref := &proxy.PackageRef{Ecosystem: "maven", Name: "com.google.guava:guava", Version: "31.0.1-jre"}
	_, err := a.FetchMetadata(context.Background(), ref)
	require.Error(t, err)
}

func TestMavenAdapter_UpstreamURLs_OnePerUpstream(t *testing.T) {
	a := adapters.NewMavenAdapter([]string{
		"https://repo1.maven.org/maven2/",
		"https://repo.spring.io/release",
	})
	r := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar", nil)
	urls := a.UpstreamURLs(r)
	assert.Equal(t, []string{
		"https://repo1.maven.org/maven2/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar",
		"https://repo.spring.io/release/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar",
	}, urls)
}
