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

func TestRubyGemsAdapter_NormalizeRequest_PlainGem(t *testing.T) {
	a := adapters.NewRubyGemsAdapter([]string{"https://rubygems.org"})
	r := httptest.NewRequest(http.MethodGet, "/gems/rails-7.0.4.gem", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "rubygems", ref.Ecosystem)
	assert.Equal(t, "rails", ref.Name)
	assert.Equal(t, "7.0.4", ref.Version)
}

func TestRubyGemsAdapter_NormalizeRequest_HyphenatedName(t *testing.T) {
	a := adapters.NewRubyGemsAdapter([]string{"https://rubygems.org"})
	r := httptest.NewRequest(http.MethodGet, "/gems/aws-sdk-s3-1.0.0.gem", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "aws-sdk-s3", ref.Name)
	assert.Equal(t, "1.0.0", ref.Version)
}

func TestRubyGemsAdapter_NormalizeRequest_PlatformGem(t *testing.T) {
	a := adapters.NewRubyGemsAdapter([]string{"https://rubygems.org"})
	r := httptest.NewRequest(http.MethodGet, "/gems/nokogiri-1.15.0-x86_64-linux.gem", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "nokogiri", ref.Name)
	assert.Equal(t, "1.15.0-x86_64-linux", ref.Version)
}

func TestRubyGemsAdapter_NormalizeRequest_NonGemNotIntercepted(t *testing.T) {
	a := adapters.NewRubyGemsAdapter([]string{"https://rubygems.org"})
	for _, p := range []string{"/api/v1/versions/rails.json", "/info/rails", "/versions", "/specs.4.8.gz"} {
		r := httptest.NewRequest(http.MethodGet, p, nil)
		_, ok := a.NormalizeRequest(r)
		assert.False(t, ok, "path %q must not be intercepted", p)
	}
}

func TestRubyGemsAdapter_UpstreamURLs_OnePerUpstream(t *testing.T) {
	a := adapters.NewRubyGemsAdapter([]string{"https://rubygems.org/", "https://mirror.example.org"})
	r := httptest.NewRequest(http.MethodGet, "/gems/rails-7.0.4.gem", nil)
	urls := a.UpstreamURLs(r)
	assert.Equal(t, []string{
		"https://rubygems.org/gems/rails-7.0.4.gem",
		"https://mirror.example.org/gems/rails-7.0.4.gem",
	}, urls)
}

func TestRubyGemsAdapter_FetchMetadata_RubyPlatform(t *testing.T) {
	created := time.Now().UTC().Add(-72 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/versions/rails.json", r.URL.Path)
		w.Write([]byte(`[
			{"number":"7.0.4","platform":"ruby","created_at":"` + created.Format(time.RFC3339) + `","licenses":["MIT"],"sha":"abc123"},
			{"number":"6.1.0","platform":"ruby","created_at":"2020-01-01T00:00:00Z","licenses":["MIT"],"sha":"old"}
		]`))
	}))
	defer srv.Close()

	a := adapters.NewRubyGemsAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "rubygems", Name: "rails", Version: "7.0.4"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, created, meta.PublishedAt, time.Second)
	assert.Equal(t, "MIT", meta.License)
	assert.Equal(t, "abc123", meta.Checksum)
}

func TestRubyGemsAdapter_FetchMetadata_MatchesPlatform(t *testing.T) {
	created := time.Now().UTC().Add(-100 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"number":"1.15.0","platform":"ruby","created_at":"2020-01-01T00:00:00Z","licenses":["MIT"],"sha":"rubysha"},
			{"number":"1.15.0","platform":"x86_64-linux","created_at":"` + created.Format(time.RFC3339) + `","licenses":["MIT"],"sha":"linuxsha"}
		]`))
	}))
	defer srv.Close()

	a := adapters.NewRubyGemsAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "rubygems", Name: "nokogiri", Version: "1.15.0-x86_64-linux"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "linuxsha", meta.Checksum)
	assert.WithinDuration(t, created, meta.PublishedAt, time.Second)
}

func TestRubyGemsAdapter_FetchMetadata_FallsBackToSecondUpstream(t *testing.T) {
	created := time.Now().UTC().Add(-72 * time.Hour)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"number":"7.0.4","platform":"ruby","created_at":"` + created.Format(time.RFC3339) + `","licenses":["MIT"],"sha":"abc123"}]`))
	}))
	defer up.Close()

	a := adapters.NewRubyGemsAdapter([]string{down.URL, up.URL})
	ref := &proxy.PackageRef{Ecosystem: "rubygems", Name: "rails", Version: "7.0.4"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "abc123", meta.Checksum)
}

func TestRubyGemsAdapter_FetchMetadata_VersionNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"number":"6.1.0","platform":"ruby","created_at":"2020-01-01T00:00:00Z","licenses":["MIT"],"sha":"x"}]`))
	}))
	defer srv.Close()

	a := adapters.NewRubyGemsAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "rubygems", Name: "rails", Version: "7.0.4"}
	_, err := a.FetchMetadata(context.Background(), ref)
	require.Error(t, err)
}

func TestRubyGemsAdapter_FetchMetadata_FallsBackWhenVersionAbsent(t *testing.T) {
	created := time.Now().UTC().Add(-72 * time.Hour)
	// First upstream is healthy (200) but only has an older version.
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"number":"6.1.0","platform":"ruby","created_at":"2020-01-01T00:00:00Z","licenses":["MIT"],"sha":"old"}]`))
	}))
	defer first.Close()
	// Second upstream has the requested version.
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"number":"7.0.4","platform":"ruby","created_at":"` + created.Format(time.RFC3339) + `","licenses":["MIT"],"sha":"newsha"}]`))
	}))
	defer second.Close()

	a := adapters.NewRubyGemsAdapter([]string{first.URL, second.URL})
	ref := &proxy.PackageRef{Ecosystem: "rubygems", Name: "rails", Version: "7.0.4"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "newsha", meta.Checksum)
}
