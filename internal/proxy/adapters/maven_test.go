package adapters_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
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

func TestMavenAdapter_NormalizeRequest_Classifier(t *testing.T) {
	a := adapters.NewMavenAdapter([]string{"https://repo1.maven.org/maven2"})

	cases := []struct {
		path           string
		wantName       string
		wantVersion    string
		wantClassifier string
	}{
		{
			"/com/fasterxml/jackson/core/jackson-annotations/2.18.5/jackson-annotations-2.18.5-sources.jar",
			"com.fasterxml.jackson.core:jackson-annotations", "2.18.5", "sources",
		},
		{
			"/com/fasterxml/jackson/core/jackson-annotations/2.18.5/jackson-annotations-2.18.5-javadoc.jar",
			"com.fasterxml.jackson.core:jackson-annotations", "2.18.5", "javadoc",
		},
		{
			// No classifier — the main artifact.
			"/com/fasterxml/jackson/core/jackson-annotations/2.18.5/jackson-annotations-2.18.5.jar",
			"com.fasterxml.jackson.core:jackson-annotations", "2.18.5", "",
		},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, c.path, nil)
		ref, ok := a.NormalizeRequest(r)
		require.True(t, ok, "path %q", c.path)
		assert.Equal(t, c.wantName, ref.Name, "path %q", c.path)
		assert.Equal(t, c.wantVersion, ref.Version, "path %q", c.path)
		assert.Equal(t, c.wantClassifier, ref.Classifier, "path %q", c.path)
	}
}

func TestMavenAdapter_NormalizeRequest_ClassifierYieldsDistinctCacheKeys(t *testing.T) {
	a := adapters.NewMavenAdapter([]string{"https://repo1.maven.org/maven2"})
	base := "/com/example/foo/1.0/foo-1.0"

	mainReq := httptest.NewRequest(http.MethodGet, base+".jar", nil)
	srcReq := httptest.NewRequest(http.MethodGet, base+"-sources.jar", nil)

	mainRef, ok := a.NormalizeRequest(mainReq)
	require.True(t, ok)
	srcRef, ok := a.NormalizeRequest(srcReq)
	require.True(t, ok)

	// The whole point: the sources jar must not collide with the main jar in
	// the artifact cache, which is keyed on PackageRef.Key().
	assert.NotEqual(t, mainRef.Key(), srcRef.Key())
}

func TestMavenAdapter_NormalizeRequest_PomNotIntercepted(t *testing.T) {
	a := adapters.NewMavenAdapter([]string{"https://repo1.maven.org/maven2"})

	r := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.pom", nil)
	_, ok := a.NormalizeRequest(r)
	assert.False(t, ok)
}

func TestMavenAdapter_MetadataFromHeader_UsesLastModified(t *testing.T) {
	lastModified := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)
	a := adapters.NewMavenAdapter([]string{"https://repo1.maven.org/maven2"})

	h := http.Header{}
	h.Set("Last-Modified", lastModified.Format(http.TimeFormat))
	meta := a.MetadataFromHeader(h)
	assert.WithinDuration(t, lastModified, meta.PublishedAt, time.Second)
}

func TestMavenAdapter_MetadataFromHeader_NoLastModifiedYieldsZeroTime(t *testing.T) {
	a := adapters.NewMavenAdapter([]string{"https://repo1.maven.org/maven2"})
	meta := a.MetadataFromHeader(http.Header{})
	assert.True(t, meta.PublishedAt.IsZero())
}

// FetchMetadata is a no-op for Maven (the date comes from the download); it must
// never make a network call.
func TestMavenAdapter_FetchMetadata_IsNoOp(t *testing.T) {
	a := adapters.NewMavenAdapter([]string{"http://127.0.0.1:0"}) // unreachable: proves no call
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
