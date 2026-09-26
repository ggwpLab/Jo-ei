//go:build integration

package integration_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

// npmRegistry is a mock npm registry serving one package with an old and a
// fresh version. It records what it was asked and what it answered, because
// several assertions are about the request it received rather than the body.
type npmRegistry struct {
	*httptest.Server
	etag string
	gzip bool

	mu                sync.Mutex
	packumentRequests []http.Header
	bodiesServed      int
}

// newNPMMetadataRegistry serves "left-pad" with 1.2.0 published oldHours ago
// and 1.3.0 published freshHours ago, so a min_age_hours between the two
// blocks exactly one version. Named distinctly from phase3_test.go's
// newNPMRegistry, which returns a plain *httptest.Server for a different
// fixture shape and lives in the same package.
//
// gzipResponse is taken as a constructor parameter, set on reg before
// httptest.NewServer starts serving, rather than assigned afterwards: the
// server handler reads reg.gzip from its own goroutine, and every other
// mutable field on npmRegistry is guarded by reg.mu, so writing this one late
// without a lock would be the odd one out.
func newNPMMetadataRegistry(t *testing.T, oldHours, freshHours int, gzipResponse bool) *npmRegistry {
	t.Helper()
	reg := &npmRegistry{etag: `"upstream-v1"`, gzip: gzipResponse}

	packument := func() []byte {
		old := time.Now().UTC().Add(-time.Duration(oldHours) * time.Hour)
		fresh := time.Now().UTC().Add(-time.Duration(freshHours) * time.Hour)
		doc := map[string]any{
			"name":      "left-pad",
			"dist-tags": map[string]string{"latest": "1.3.0"},
			"time": map[string]string{
				"created": old.Format(time.RFC3339),
				"1.2.0":   old.Format(time.RFC3339),
				"1.3.0":   fresh.Format(time.RFC3339),
			},
			"versions": map[string]any{
				"1.2.0": map[string]any{"name": "left-pad", "version": "1.2.0", "dist": map[string]string{"shasum": "aaa"}},
				"1.3.0": map[string]any{"name": "left-pad", "version": "1.3.0", "dist": map[string]string{"shasum": "bbb"}},
			},
		}
		b, err := json.Marshal(doc)
		require.NoError(t, err)
		return b
	}

	reg.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".tgz") {
			w.Write([]byte("fake-tarball"))
			return
		}
		if r.URL.Path == "/left-pad" {
			reg.mu.Lock()
			reg.packumentRequests = append(reg.packumentRequests, r.Header.Clone())
			reg.mu.Unlock()

			w.Header().Set("ETag", reg.etag)
			w.Header().Set("Last-Modified", "Tue, 16 Apr 2024 05:01:58 GMT")
			w.Header().Set("Cache-Control", "public, max-age=300")
			w.Header().Set("Vary", "accept-encoding, accept")
			w.Header().Set("Content-Type", "application/json")

			reg.mu.Lock()
			reg.bodiesServed++
			reg.mu.Unlock()

			if reg.gzip {
				w.Header().Set("Content-Encoding", "gzip")
				zw := gzip.NewWriter(w)
				defer zw.Close()
				zw.Write(packument())
				return
			}
			w.Write(packument())
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(reg.Close)
	return reg
}

func (reg *npmRegistry) lastPackumentRequest(t *testing.T) http.Header {
	t.Helper()
	reg.mu.Lock()
	defer reg.mu.Unlock()
	require.NotEmpty(t, reg.packumentRequests, "upstream saw no packument request")
	return reg.packumentRequests[len(reg.packumentRequests)-1]
}

// newNPMProxy wires a proxy in front of reg. minAgeHours and mode drive the
// supply-chain filter; capMB is HandlerConfig.MetadataFilterMaxMB, where 0
// disables metadata filtering entirely.
func newNPMProxy(t *testing.T, reg *npmRegistry, minAgeHours int, mode string, capMB int) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:   dir,
		MaxSizeGB:  1,
		StaleAfter: 24 * time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = localCache.Close() })

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewNPMAdapter([]string{reg.URL}),
		Filter: supplychain.NewFilter(config.SupplyChainConfig{
			MinAgeHours: minAgeHours,
			Mode:        mode,
		}, nil),
		Cache:               cache.AsArtifactCache(localCache),
		Logger:              zerolog.Nop(),
		MetadataFilterMaxMB: capMB,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// getPackument fetches the packument through the proxy with the given headers.
func getPackument(t *testing.T, srv *httptest.Server, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/left-pad", nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// The default transport would add its own Accept-Encoding: gzip and
	// transparently decompress the response, deleting Content-Length along the
	// way — that would break the Content-Length assertion below against
	// correct code. Disabling transport compression keeps this test in control
	// of what encoding is requested and how the response is read.
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	return resp, body
}

func versionsOf(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	return doc.Versions
}

// Scenario A: the fresh version is hidden, and the response carries our own
// validator instead of upstream's.
func TestIntegration_NPMMetadataFilter_HidesFreshVersion(t *testing.T) {
	reg := newNPMMetadataRegistry(t, 240, 1, false)
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	versions := versionsOf(t, body)
	assert.NotContains(t, versions, "1.3.0", "a version younger than min_age must not be offered")
	assert.Contains(t, versions, "1.2.0")

	assert.True(t, strings.HasPrefix(resp.Header.Get("ETag"), `"joei.`), "got %q", resp.Header.Get("ETag"))
	assert.Empty(t, resp.Header.Get("Last-Modified"), "a date validator would let the client revalidate around us")
	assert.Equal(t, "public, max-age=300", resp.Header.Get("Cache-Control"))
	assert.Equal(t, fmt.Sprint(len(body)), resp.Header.Get("Content-Length"))
}

// Scenario G: hiding every version would break every install of the package, so
// the original document is served and the tarball still answers 423.
func TestIntegration_NPMMetadataFilter_AllVersionsBlockedServesOriginal(t *testing.T) {
	reg := newNPMMetadataRegistry(t, 2, 1, false)
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	versions := versionsOf(t, body)
	assert.Contains(t, versions, "1.2.0")
	assert.Contains(t, versions, "1.3.0")
	assert.Equal(t, `"upstream-v1"`, resp.Header.Get("ETag"), "an untouched document keeps upstream's validator")

	tarball, err := http.Get(srv.URL + "/left-pad/-/left-pad-1.3.0.tgz")
	require.NoError(t, err)
	defer tarball.Body.Close()
	assert.Equal(t, http.StatusLocked, tarball.StatusCode, "the artifact gate is still the enforcement boundary")
}

// Scenario I: the cap doubles as a kill switch.
func TestIntegration_NPMMetadataFilter_ZeroCapDisablesFiltering(t *testing.T) {
	reg := newNPMMetadataRegistry(t, 240, 1, false)
	srv := newNPMProxy(t, reg, 24, "enforce", 0)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, versionsOf(t, body), "1.3.0", "filtering is off, so nothing is hidden")
	assert.Equal(t, `"upstream-v1"`, resp.Header.Get("ETag"))
}

// Scenario H: upstream may answer gzipped, and the client must still get a
// document it can parse. The client asked for gzip, so the response must
// actually be gzip — asserting that (rather than branching on whatever
// Content-Encoding happened to come back) is what would catch a silent
// fallback to identity encoding on a compression failure.
func TestIntegration_NPMMetadataFilter_GzippedUpstream(t *testing.T) {
	reg := newNPMMetadataRegistry(t, 240, 1, true)
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, map[string]string{"Accept-Encoding": "gzip"})

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"), "the client asked for gzip and must get it")
	assert.Equal(t, fmt.Sprint(len(body)), resp.Header.Get("Content-Length"))

	zr, err := gzip.NewReader(bytes.NewReader(body))
	require.NoError(t, err)
	defer zr.Close()
	plain, err := io.ReadAll(zr)
	require.NoError(t, err)
	assert.NotContains(t, versionsOf(t, plain), "1.3.0")
}
