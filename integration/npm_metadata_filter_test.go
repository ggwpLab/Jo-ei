//go:build integration

package integration_test

import (
	"bytes"
	"compress/flate"
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
	"github.com/ggwpLab/Jo-ei/internal/httpx"
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
	opts npmRegistryOptions

	mu                sync.Mutex
	packumentRequests []http.Header
	bodiesServed      int
}

// npmRegistryOptions configures the mock. Every knob is read by the handler
// goroutine, so all of them are set before httptest.NewServer starts rather
// than assigned afterwards.
type npmRegistryOptions struct {
	OldHours   int
	FreshHours int
	Gzip       bool
	// Deflate serves the packument deflate-compressed whatever the client
	// asked for: a coding this proxy does not decode.
	Deflate bool
	// HonourConditional makes the mock answer 304 to a matching
	// If-None-Match, the way a real registry does.
	HonourConditional bool
	// PadBytes inflates the packument with a throwaway field, so a test can
	// push the document past a byte cap.
	PadBytes int
	// Delay widens the window a packument request spends upstream, so a
	// coalescing test can launch every caller before the first returns.
	Delay time.Duration
	// Redirect answers the packument with a 302 to /moved/left-pad, which
	// serves it.
	Redirect bool
	// Garbage answers the packument with a 200 that is not JSON.
	Garbage bool
	// BadVersions serves version keys that cannot form a tarball path.
	BadVersions bool
	// RequireAuth answers the packument with 401 unless Authorization equals
	// it, the way a private registry does.
	RequireAuth string
}

// newNPMMetadataRegistry serves "left-pad" with 1.2.0 published OldHours ago
// and 1.3.0 published FreshHours ago, so a min_age_hours between the two
// blocks exactly one version. Every tarball link points at the mock itself,
// the way registry.npmjs.org links its own host.
func newNPMMetadataRegistry(t *testing.T, opts npmRegistryOptions) *npmRegistry {
	t.Helper()
	reg := &npmRegistry{etag: `"upstream-v1"`, opts: opts}

	packument := func() []byte {
		old := time.Now().UTC().Add(-time.Duration(opts.OldHours) * time.Hour)
		fresh := time.Now().UTC().Add(-time.Duration(opts.FreshHours) * time.Hour)
		version := func(v, shasum string) map[string]any {
			return map[string]any{"name": "left-pad", "version": v, "dist": map[string]string{
				"shasum":  shasum,
				"tarball": reg.URL + "/left-pad/-/left-pad-" + v + ".tgz",
			}}
		}
		doc := map[string]any{
			"name":      "left-pad",
			"dist-tags": map[string]string{"latest": "1.3.0"},
			"time": map[string]string{
				"created": old.Format(time.RFC3339),
				"1.2.0":   old.Format(time.RFC3339),
				"1.3.0":   fresh.Format(time.RFC3339),
			},
			"versions": map[string]any{"1.2.0": version("1.2.0", "aaa"), "1.3.0": version("1.3.0", "bbb")},
		}
		if opts.BadVersions {
			doc["versions"] = map[string]any{"bad version": version("bad version", "ccc")}
		}
		if opts.PadBytes > 0 {
			doc["_padding"] = strings.Repeat("x", opts.PadBytes)
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
		if r.URL.Path == "/left-pad/1.3.0" {
			w.Header().Set("ETag", `"manifest-v1"`)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name":"left-pad","version":"1.3.0","dist":{"shasum":"bbb","tarball":"` + reg.URL + `/left-pad/-/left-pad-1.3.0.tgz"}}`))
			return
		}
		if r.URL.Path == "/left-pad" || (opts.Redirect && r.URL.Path == "/moved/left-pad") {
			reg.mu.Lock()
			reg.packumentRequests = append(reg.packumentRequests, r.Header.Clone())
			reg.mu.Unlock()

			if opts.Delay > 0 {
				time.Sleep(opts.Delay) // widen the window so coalescing is observable
			}
			if opts.RequireAuth != "" && r.Header.Get("Authorization") != opts.RequireAuth {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if opts.HonourConditional && listsTag(r.Header.Values("If-None-Match"), reg.etag) {
				w.Header().Set("ETag", reg.etag)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			if opts.Redirect && r.URL.Path == "/left-pad" {
				http.Redirect(w, r, "/moved/left-pad", http.StatusFound)
				return
			}

			w.Header().Set("ETag", reg.etag)
			w.Header().Set("Last-Modified", "Tue, 16 Apr 2024 05:01:58 GMT")
			w.Header().Set("Cache-Control", "public, max-age=300")
			w.Header().Set("Vary", "accept-encoding, accept")
			w.Header().Set("Content-Type", "application/json")

			reg.mu.Lock()
			reg.bodiesServed++
			reg.mu.Unlock()

			switch {
			case opts.Garbage:
				w.Write([]byte("<html>not a packument</html>"))
			case opts.Gzip:
				w.Header().Set("Content-Encoding", "gzip")
				zw := gzip.NewWriter(w)
				defer zw.Close()
				zw.Write(packument())
			case opts.Deflate:
				w.Header().Set("Content-Encoding", "deflate")
				zw, _ := flate.NewWriter(w, flate.DefaultCompression)
				defer zw.Close()
				zw.Write(packument())
			default:
				w.Write(packument())
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(reg.Close)
	return reg
}

// listsTag reports whether any If-None-Match field line lists tag, the way a
// real registry reads a header that may be repeated or comma-joined.
func listsTag(lines []string, tag string) bool {
	for _, line := range lines {
		for _, candidate := range strings.Split(line, ",") {
			if strings.TrimSpace(candidate) == tag {
				return true
			}
		}
	}
	return false
}

func (reg *npmRegistry) lastPackumentRequest(t *testing.T) http.Header {
	t.Helper()
	reg.mu.Lock()
	defer reg.mu.Unlock()
	require.NotEmpty(t, reg.packumentRequests, "upstream saw no packument request")
	return reg.packumentRequests[len(reg.packumentRequests)-1]
}

func (reg *npmRegistry) packumentRequestCount() int {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return len(reg.packumentRequests)
}

func (reg *npmRegistry) bodyCount() int {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return reg.bodiesServed
}

// newNPMProxy wires a proxy in front of reg, mounted under /npm/ and /yarn/
// the way cmd/jo-ei mounts it. minAgeHours and mode drive the supply-chain
// filter; capMB is HandlerConfig.MetadataFilterMaxMB, where 0 means no cap.
func newNPMProxy(t *testing.T, reg *npmRegistry, minAgeHours int, mode string, capMB int) *httptest.Server {
	t.Helper()
	return newNPMProxyWithBase(t, reg, minAgeHours, mode, capMB, nil)
}

func newNPMProxyWithBase(t *testing.T, reg *npmRegistry, minAgeHours int, mode string, capMB int, base *httpx.PublicBaseResolver) *httptest.Server {
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
		PublicBase:          base,
	})
	srv := httptest.NewServer(proxy.NewMux(map[string]*proxy.Handler{"npm": h, "yarn": h}, nil, zerolog.Nop()))
	t.Cleanup(srv.Close)
	return srv
}

// getPackument fetches /npm/left-pad through the proxy with the given headers.
// It calls testify's require, so it must only ever run on the test's own
// goroutine — a concurrency test must use fetchPackument instead.
func getPackument(t *testing.T, srv *httptest.Server, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	return getPath(t, srv, "/npm/left-pad", headers)
}

func getPath(t *testing.T, srv *httptest.Server, path string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	resp, body, err := doFetch(srv, path, headers)
	require.NoError(t, err)
	return resp, body
}

// packumentResult is one worker goroutine's outcome from fetchPackument,
// collected without calling into testify from that goroutine.
type packumentResult struct {
	status int
	body   []byte
	err    error
}

func fetchPackument(srv *httptest.Server, headers map[string]string) packumentResult {
	resp, body, err := doFetch(srv, "/npm/left-pad", headers)
	if err != nil {
		return packumentResult{err: err}
	}
	return packumentResult{status: resp.StatusCode, body: body}
}

// doFetch builds the request, disables transport compression so encoding and
// Content-Length assertions see the wire, and reads the body fully. A "Host"
// entry in headers sets the request's Host.
func doFetch(srv *httptest.Server, path string, headers map[string]string) (*http.Response, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, body, nil
}

func versionsOf(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	return doc.Versions
}

// tarballLinks returns every version's dist.tarball.
func tarballLinks(t *testing.T, body []byte) map[string]string {
	t.Helper()
	var doc struct {
		Versions map[string]struct {
			Dist struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		} `json:"versions"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	out := map[string]string{}
	for v, m := range doc.Versions {
		out[v] = m.Dist.Tarball
	}
	return out
}

// assertRefused checks the fail-closed answer: 502, never the document.
func assertRefused(t *testing.T, resp *http.Response, body []byte) {
	t.Helper()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.JSONEq(t, `{"error":"metadata_rewrite_failed"}`, string(body))
}

// The fresh version is hidden, the rest link through the proxy, and the
// response carries our own validator instead of upstream's.
func TestIntegration_NPMMetadataFilter_HidesFreshVersion(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	versions := versionsOf(t, body)
	assert.NotContains(t, versions, "1.3.0", "a version younger than min_age must not be offered")
	assert.Contains(t, versions, "1.2.0")
	assert.Equal(t, map[string]string{"1.2.0": srv.URL + "/npm/left-pad/-/left-pad-1.2.0.tgz"}, tarballLinks(t, body))

	assert.True(t, strings.HasPrefix(resp.Header.Get("ETag"), `"joei.`), "got %q", resp.Header.Get("ETag"))
	assert.Empty(t, resp.Header.Get("Last-Modified"), "a date validator would let the client revalidate around us")
	assert.Equal(t, "public, max-age=300", resp.Header.Get("Cache-Control"))
	assert.Equal(t, fmt.Sprint(len(body)), resp.Header.Get("Content-Length"))
}

// Every tarball link points at the address the client used.
func TestIntegration_NPMMetadataFilter_RewritesTarballLinksToTheProxy(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 200})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, map[string]string{"Host": "joei.test:8080"})

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, map[string]string{
		"1.2.0": "http://joei.test:8080/npm/left-pad/-/left-pad-1.2.0.tgz",
		"1.3.0": "http://joei.test:8080/npm/left-pad/-/left-pad-1.3.0.tgz",
	}, tarballLinks(t, body))
	assert.NotContains(t, string(body), reg.URL, "no link may lead to upstream")
}

// One handler serves /npm/ and /yarn/; each client gets links under the
// prefix it asked through, and a scoped name in its %2f spelling resolves
// the same as the plain one.
func TestIntegration_NPMMetadataFilter_YarnRouteLinksUnderYarn(t *testing.T) {
	scoped := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/@types/node" && r.URL.Path != "/@types%2fnode" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"@types/node","versions":{"20.1.0":{"dist":{"tarball":"https://registry.npmjs.org/@types/node/-/node-20.1.0.tgz"}}}}`))
	}))
	t.Cleanup(scoped.Close)
	srv := newNPMProxy(t, &npmRegistry{Server: scoped}, 0, "enforce", 32)

	resp, body := getPath(t, srv, "/yarn/@types%2fnode", map[string]string{"Host": "joei.test:8080"})

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, map[string]string{"20.1.0": "http://joei.test:8080/yarn/@types/node/-/node-20.1.0.tgz"}, tarballLinks(t, body))
}

// Forwarding headers name the client-facing address only from a trusted peer.
func TestIntegration_NPMMetadataFilter_TrustedProxyHeaders(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 200})
	headers := map[string]string{"Host": "joei:8080", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "reg.example"}

	peers, err := httpx.ParseTrustedPeers([]string{"127.0.0.1", "::1"})
	require.NoError(t, err)
	trusting, err := httpx.NewPublicBaseResolver("", peers, zerolog.Nop())
	require.NoError(t, err)
	_, body := getPackument(t, newNPMProxyWithBase(t, reg, 24, "enforce", 32, trusting), headers)
	assert.Equal(t, "https://reg.example/npm/left-pad/-/left-pad-1.3.0.tgz", tarballLinks(t, body)["1.3.0"])

	distrusting, err := httpx.NewPublicBaseResolver("", nil, zerolog.Nop())
	require.NoError(t, err)
	_, body = getPackument(t, newNPMProxyWithBase(t, reg, 24, "enforce", 32, distrusting), headers)
	assert.Equal(t, "http://joei:8080/npm/left-pad/-/left-pad-1.3.0.tgz", tarballLinks(t, body)["1.3.0"],
		"headers from an untrusted peer must not pick the link host")
}

// A forwarding header that is not a usable host is refused before upstream is
// asked anything.
func TestIntegration_NPMMetadataFilter_BadForwardedHeaderIs400(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 200})
	peers, err := httpx.ParseTrustedPeers([]string{"127.0.0.1", "::1"})
	require.NoError(t, err)
	base, err := httpx.NewPublicBaseResolver("", peers, zerolog.Nop())
	require.NoError(t, err)
	srv := newNPMProxyWithBase(t, reg, 24, "enforce", 32, base)

	resp, body := getPackument(t, srv, map[string]string{"X-Forwarded-Host": "a.example/evil"})

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.JSONEq(t, `{"error":"bad_forwarded_header"}`, string(body))
	assert.Zero(t, reg.packumentRequestCount())
}

// The ETag covers the links, so two addresses never share a validator.
func TestIntegration_NPMMetadataFilter_ETagDiffersPerBase(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 200})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	a, _ := getPackument(t, srv, map[string]string{"Host": "a.example"})
	b, _ := getPackument(t, srv, map[string]string{"Host": "b.example"})

	assert.True(t, strings.HasPrefix(a.Header.Get("ETag"), `"joei.`))
	assert.NotEqual(t, a.Header.Get("ETag"), b.Header.Get("ETag"))
}

// A client holding a copy cached before links were rewritten revalidates with
// upstream's validators; forwarding them would let upstream's 304 keep that
// copy alive.
func TestIntegration_NPMMetadataFilter_ClientValidatorsNeverForwarded(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1, HonourConditional: true})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, map[string]string{
		"If-None-Match":     `"upstream-v1"`,
		"If-Modified-Since": "Tue, 16 Apr 2024 05:01:58 GMT",
	})

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, srv.URL+"/npm/left-pad/-/left-pad-1.2.0.tgz", tarballLinks(t, body)["1.2.0"])
	assert.Empty(t, reg.lastPackumentRequest(t).Values("If-None-Match"))
	assert.Empty(t, reg.lastPackumentRequest(t).Values("If-Modified-Since"))
}

// Every version blocked: hiding them all would break every install, so they
// stay — rewritten — and the tarball still answers 423.
func TestIntegration_NPMMetadataFilter_AllVersionsBlockedServesAllVersionsRewritten(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 2, FreshHours: 1})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, map[string]string{
		"1.2.0": srv.URL + "/npm/left-pad/-/left-pad-1.2.0.tgz",
		"1.3.0": srv.URL + "/npm/left-pad/-/left-pad-1.3.0.tgz",
	}, tarballLinks(t, body))

	tarball, err := http.Get(srv.URL + "/npm/left-pad/-/left-pad-1.3.0.tgz")
	require.NoError(t, err)
	defer tarball.Body.Close()
	assert.Equal(t, http.StatusLocked, tarball.StatusCode, "the artifact gate is still the enforcement boundary")
}

// A zero cap means no size cap, not "off".
func TestIntegration_NPMMetadataFilter_ZeroCapMeansUnlimited(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1, PadBytes: 2 << 20})
	srv := newNPMProxy(t, reg, 24, "enforce", 0)

	resp, body := getPackument(t, srv, nil)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotContains(t, versionsOf(t, body), "1.3.0")
	assert.Equal(t, srv.URL+"/npm/left-pad/-/left-pad-1.2.0.tgz", tarballLinks(t, body)["1.2.0"])
}

// Upstream may answer gzipped; the client asked for gzip and gets it.
func TestIntegration_NPMMetadataFilter_GzippedUpstream(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1, Gzip: true})
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

// A client that only accepts br still gets a document: upstream is asked for
// gzip, the one coding the proxy decodes, and the client gets identity.
func TestIntegration_NPMMetadataFilter_BrOnlyClientGetsIdentity(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, map[string]string{"Accept-Encoding": "br"})

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Content-Encoding"))
	assert.Contains(t, versionsOf(t, body), "1.2.0")
	assert.Equal(t, "gzip", reg.lastPackumentRequest(t).Get("Accept-Encoding"))
}

// A client revalidating with our tag gets a 304.
func TestIntegration_NPMMetadataFilter_RevalidateWithOurTag(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	first, _ := getPackument(t, srv, nil)
	ourTag := first.Header.Get("ETag")
	require.True(t, strings.HasPrefix(ourTag, `"joei.`))

	second, body := getPackument(t, srv, map[string]string{
		"If-None-Match":     ourTag,
		"If-Modified-Since": "Tue, 16 Apr 2024 05:01:58 GMT",
	})

	assert.Equal(t, http.StatusNotModified, second.StatusCode)
	assert.Empty(t, body)
	assert.Equal(t, ourTag, second.Header.Get("ETag"))
	assert.Equal(t, "public, max-age=300", second.Header.Get("Cache-Control"),
		"the own-304 path deliberately relays upstream's Cache-Control")
	assert.Empty(t, reg.lastPackumentRequest(t).Get("If-None-Match"),
		"our own tag must never be forwarded upstream")
	assert.Empty(t, reg.lastPackumentRequest(t).Get("If-Modified-Since"))
}

// dry_run reports but never blocks, so it must never hide either; links are
// rewritten all the same.
func TestIntegration_NPMMetadataFilter_DryRunHidesNothing(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1})
	srv := newNPMProxy(t, reg, 24, "dry_run", 32)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, srv.URL+"/npm/left-pad/-/left-pad-1.3.0.tgz", tarballLinks(t, body)["1.3.0"])
}

// Every document the proxy cannot rewrite is refused, never relayed.
func TestIntegration_NPMMetadataFilter_OverCapIs502(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1, PadBytes: 2 << 20})
	srv := newNPMProxy(t, reg, 24, "enforce", 1)
	resp, body := getPackument(t, srv, nil)
	assertRefused(t, resp, body)
}

func TestIntegration_NPMMetadataFilter_OverCapGzipIs502(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1, PadBytes: 2 << 20, Gzip: true})
	srv := newNPMProxy(t, reg, 24, "enforce", 1)
	resp, body := getPackument(t, srv, map[string]string{"Accept-Encoding": "gzip"})
	assertRefused(t, resp, body)
}

func TestIntegration_NPMMetadataFilter_UnsupportedEncodingIs502(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1, Deflate: true})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)
	resp, body := getPackument(t, srv, map[string]string{"Accept-Encoding": "deflate"})
	assertRefused(t, resp, body)
}

func TestIntegration_NPMMetadataFilter_UnparseableIs502(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{Garbage: true})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)
	resp, body := getPackument(t, srv, nil)
	assertRefused(t, resp, body)
}

// The proxy follows an upstream redirect itself, so the document the client
// gets is the one it rewrote, never a pointer to one it did not see.
func TestIntegration_NPMMetadataFilter_UpstreamRedirectFollowedAndRewritten(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 200, Redirect: true})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, nil)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, srv.URL+"/npm/left-pad/-/left-pad-1.3.0.tgz", tarballLinks(t, body)["1.3.0"])
}

func TestIntegration_NPMMetadataFilter_AllUnmappableIs502(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1, BadVersions: true})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)
	resp, body := getPackument(t, srv, nil)
	assertRefused(t, resp, body)
}

// A single-version manifest links a tarball too, so it is rewritten; the
// download is what gets blocked.
func TestIntegration_NPMMetadataFilter_VersionManifestRewritten(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPath(t, srv, "/npm/left-pad/1.3.0", nil)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var manifest struct {
		Dist map[string]string `json:"dist"`
	}
	require.NoError(t, json.Unmarshal(body, &manifest))
	assert.Equal(t, srv.URL+"/npm/left-pad/-/left-pad-1.3.0.tgz", manifest.Dist["tarball"])
	assert.Equal(t, "bbb", manifest.Dist["shasum"])

	tarball, err := http.Get(srv.URL + "/npm/left-pad/-/left-pad-1.3.0.tgz")
	require.NoError(t, err)
	defer tarball.Body.Close()
	assert.Equal(t, http.StatusLocked, tarball.StatusCode)
}

// Concurrent clients asking for one packument must cost one upstream fetch.
// Each goroutine only records its own outcome; every require/assert runs
// afterwards on the test goroutine.
func TestIntegration_NPMMetadataFilter_CoalescesConcurrentFetches(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1, Delay: 150 * time.Millisecond})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	const clients = 8
	results := make([]packumentResult, clients)
	var wg sync.WaitGroup
	wg.Add(clients)
	for i := 0; i < clients; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = fetchPackument(srv, nil)
		}(i)
	}
	wg.Wait()

	for _, res := range results {
		require.NoError(t, res.err)
		assert.Equal(t, http.StatusOK, res.status)
		assert.NotContains(t, versionsOf(t, res.body), "1.3.0")
	}

	// Every one of the 8 identical, simultaneous requests belongs to one
	// flight; this allows a little timing slop without accepting "coalescing
	// barely happened" as a pass.
	assert.LessOrEqual(t, reg.bodyCount(), 2,
		"8 simultaneous, identical clients should collapse onto (at most) one upstream fetch")
}

// Callers with different credentials must not share a flight: the leader's
// Authorization goes upstream, so a shared result would hand a private
// document to a caller without the token, or the leader's 401 to one with it.
func TestIntegration_NPMMetadataFilter_CredentialsDoNotShareAFlight(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{
		OldHours: 240, FreshHours: 200, RequireAuth: "Bearer secret", Delay: 150 * time.Millisecond,
	})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	var authed, anonymous packumentResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		anonymous = fetchPackument(srv, nil)
	}()
	time.Sleep(30 * time.Millisecond) // let the anonymous caller lead the flight
	go func() {
		defer wg.Done()
		authed = fetchPackument(srv, map[string]string{"Authorization": "Bearer secret"})
	}()
	wg.Wait()

	require.NoError(t, authed.err)
	require.NoError(t, anonymous.err)
	assert.Equal(t, http.StatusOK, authed.status, "the caller holding the token must get the document")
	assert.NotEqual(t, http.StatusOK, anonymous.status, "the caller without a token must not get it")
}
