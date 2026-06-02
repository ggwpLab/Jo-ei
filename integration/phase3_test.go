//go:build integration

package integration_test

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockClamd starts a TCP clamd stand-in that returns the given response.
func mockClamd(t *testing.T, response string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				if _, err := r.ReadBytes(0x00); err != nil {
					return
				}
				for {
					var size uint32
					if err := binary.Read(r, binary.BigEndian, &size); err != nil {
						return
					}
					if size == 0 {
						break
					}
					io.CopyN(io.Discard, r, int64(size))
				}
				c.Write([]byte(response))
			}(conn)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// newNPMRegistry serves an npm metadata document and tarball for one version.
func newNPMRegistry(t *testing.T, name, version string, ageHours int) *httptest.Server {
	t.Helper()
	publishedAt := time.Now().UTC().Add(-time.Duration(ageHours) * time.Hour)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+name {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"time": map[string]any{version: publishedAt.Format(time.RFC3339)},
				"versions": map[string]any{
					version: map[string]any{
						"license": "MIT",
						"dist":    map[string]any{"shasum": "deadbeef"},
					},
				},
			})
			return
		}
		w.Write([]byte("tarball-bytes"))
	}))
}

// newPhase3NPMProxy wires an npm-only proxy with the given AV scanner address.
func newPhase3NPMProxy(t *testing.T, upstream *httptest.Server, clamdAddr string) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	av, err := scanner.NewClamAVScanner(clamdAddr, 5*time.Second)
	require.NoError(t, err)

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:   adapters.NewNPMAdapter([]string{upstream.URL}),
		Filter:    supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:     &localCacheAdapter{lc: lc},
		Logger:    zerolog.Nop(),
		AVScanner: av,
	})
	mux := proxy.NewMux(map[string]*proxy.Handler{"npm": h}, zerolog.Nop())
	return httptest.NewServer(mux)
}

func TestPhase3_CleanNPMPackageAllowed(t *testing.T) {
	registry := newNPMRegistry(t, "lodash", "4.17.21", 48)
	defer registry.Close()
	clamd := mockClamd(t, "stream: OK\x00")

	srv := newPhase3NPMProxy(t, registry, clamd)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/npm/lodash/-/lodash-4.17.21.tgz")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPhase3_MalwareBlocked(t *testing.T) {
	registry := newNPMRegistry(t, "evil-pkg", "1.0.0", 48)
	defer registry.Close()
	clamd := mockClamd(t, "stream: Eicar-Test-Signature FOUND\x00")

	srv := newPhase3NPMProxy(t, registry, clamd)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/npm/evil-pkg/-/evil-pkg-1.0.0.tgz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "malware_found", body["reason"])
	assert.Equal(t, "Eicar-Test-Signature", body["signature"])
}

func TestPhase3_MavenOldArtifactAllowed(t *testing.T) {
	// Maven repo serving a HEAD with an old Last-Modified, plus the jar bytes.
	lastModified := time.Now().UTC().Add(-72 * time.Hour)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Write([]byte("jar-bytes"))
	}))
	defer registry.Close()
	clamd := mockClamd(t, "stream: OK\x00")

	dir := t.TempDir()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })
	av, err := scanner.NewClamAVScanner(clamd, 5*time.Second)
	require.NoError(t, err)

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:   adapters.NewMavenAdapter([]string{registry.URL}),
		Filter:    supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:     &localCacheAdapter{lc: lc},
		Logger:    zerolog.Nop(),
		AVScanner: av,
	})
	mux := proxy.NewMux(map[string]*proxy.Handler{"maven": h}, zerolog.Nop())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/maven/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
