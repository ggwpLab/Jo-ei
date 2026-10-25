package proxy_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

const absLink = `<a href="https://files.pythonhosted.org/packages/a/b/six-1.16.0-py2.py3-none-any.whl#sha256=ab">six-1.16.0-py2.py3-none-any.whl</a>`

func indexProxy(t *testing.T, upstream http.Handler, maxMB int) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)
	srv := httptest.NewServer(proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapters.NewPyPIAdapter([]string{up.URL}),
		Filter:     supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:      newFakeCache(),
		Logger:     zerolog.Nop(),
		IndexMaxMB: maxMB,
	}))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string, header map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	// A bare transport so Go does not transparently negotiate gzip itself.
	resp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(b)
}

func TestIndex_HTMLLinksPointAtProxy(t *testing.T) {
	srv := indexProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html><body>"+absLink+"</body></html>")
	}), 0)

	resp, body := get(t, srv.URL+"/simple/six/", nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, `href="../../packages/a/b/six-1.16.0-py2.py3-none-any.whl#sha256=ab"`)
	assert.NotContains(t, body, "files.pythonhosted.org")
}

func TestIndex_GzipUpstreamIsRewritten(t *testing.T) {
	srv := indexProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Contains(t, r.Header.Get("Accept-Encoding"), "gzip")
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		io.WriteString(zw, absLink)
		zw.Close()
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(buf.Bytes())
	}), 0)

	resp, body := get(t, srv.URL+"/simple/six/", nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Content-Encoding"))
	assert.Contains(t, body, `href="../../packages/`)
}

// pip caches simple pages. A copy fetched straight from upstream carries
// upstream's validators; forwarding them could earn a 304 that keeps the client
// on the unrewritten page — and its bypass — indefinitely.
func TestIndex_ClientValidatorsNotForwarded(t *testing.T) {
	var sawINM, sawIMS string
	srv := indexProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawINM, sawIMS = r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since")
		w.Header().Set("ETag", `"upstream-tag"`)
		w.Header().Set("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT")
		io.WriteString(w, absLink)
	}), 0)

	resp, _ := get(t, srv.URL+"/simple/six/", map[string]string{
		"If-None-Match":     `"upstream-tag"`,
		"If-Modified-Since": "Mon, 01 Jan 2024 00:00:00 GMT",
	})

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, sawINM)
	assert.Empty(t, sawIMS)
	assert.True(t, strings.HasPrefix(resp.Header.Get("ETag"), `"joei.`), resp.Header.Get("ETag"))
	assert.Empty(t, resp.Header.Get("Last-Modified"))
}

func TestIndex_OurETagRevalidates(t *testing.T) {
	srv := indexProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, absLink)
	}), 0)

	first, _ := get(t, srv.URL+"/simple/six/", nil)
	again, _ := get(t, srv.URL+"/simple/six/", map[string]string{"If-None-Match": first.Header.Get("ETag")})

	assert.Equal(t, http.StatusNotModified, again.StatusCode)
}

func TestIndex_OversizedFailsClosed(t *testing.T) {
	srv := indexProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, absLink+strings.Repeat(" ", 2<<20))
	}), 1)

	resp, body := get(t, srv.URL+"/simple/six/", nil)

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.JSONEq(t, `{"error":"index_rewrite_failed"}`, body)
}

func TestIndex_UnparseableFailsClosed(t *testing.T) {
	srv := indexProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		io.WriteString(w, `{"files": [`)
	}), 0)

	resp, body := get(t, srv.URL+"/simple/six/", nil)

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.JSONEq(t, `{"error":"index_rewrite_failed"}`, body)
}

func TestIndex_Non200Relayed(t *testing.T) {
	srv := indexProxy(t, http.NotFoundHandler(), 0)

	resp, _ := get(t, srv.URL+"/simple/nope/", nil)

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// A forwarded Range header could earn a 206 slice of the index, which must not
// reach the client unrewritten.
func TestIndex_RangeNotForwardedAndPartialFailsClosed(t *testing.T) {
	var sawRange string
	srv := indexProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRange = r.Header.Get("Range")
		w.WriteHeader(http.StatusPartialContent)
		io.WriteString(w, absLink)
	}), 0)

	resp, body := get(t, srv.URL+"/simple/six/", map[string]string{"Range": "bytes=0-100"})

	assert.Empty(t, sawRange)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.NotContains(t, body, "files.pythonhosted.org")
}

// A /packages/ file the adapter cannot name must not be streamed around the
// gates: there is no package and version to check it against.
func TestHandler_UnrecognizedPackageFileFailsClosed(t *testing.T) {
	hit := false
	srv := indexProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		io.WriteString(w, "payload")
	}), 0)

	resp, body := get(t, srv.URL+"/packages/a/b/README", nil)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.NotContains(t, body, "payload")
	assert.False(t, hit, "upstream must not be fetched")
}

// pip fetches a wheel's PEP 658 core metadata (<file>.metadata) during
// resolution. It holds the METADATA text only, no code, so it passes through.
func TestHandler_CoreMetadataFilePassesThrough(t *testing.T) {
	srv := indexProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Metadata-Version: 2.1\nName: requests\n")
	}), 0)

	resp, body := get(t, srv.URL+"/packages/70/8e/abc/requests-2.31.0-py3-none-any.whl.metadata", nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, "Name: requests")
}
