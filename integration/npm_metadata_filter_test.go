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

	// honourConditional makes the mock answer 304 to a matching If-None-Match,
	// the way a real registry does.
	honourConditional bool

	// padBytes inflates the packument with a throwaway field, so a test can
	// push the document past a byte cap without the fixture itself needing to
	// grow. Zero means "no padding" — the ordinary small document.
	padBytes int

	// delay widens the window a packument request spends upstream, so a test
	// asserting that concurrent callers coalesce onto one fetch has room to
	// launch all of them before the first one returns. Zero means no delay.
	delay time.Duration

	mu                sync.Mutex
	packumentRequests []http.Header
	bodiesServed      int
}

// npmRegistryOptions configures the mock. Every knob is read by the handler
// goroutine, so all of them are set before httptest.NewServer starts rather
// than assigned afterwards.
type npmRegistryOptions struct {
	OldHours          int
	FreshHours        int
	Gzip              bool
	HonourConditional bool
	PadBytes          int
	Delay             time.Duration
}

// newNPMMetadataRegistry serves "left-pad" with 1.2.0 published OldHours ago
// and 1.3.0 published FreshHours ago, so a min_age_hours between the two
// blocks exactly one version. Named distinctly from phase3_test.go's
// newNPMRegistry, which returns a plain *httptest.Server for a different
// fixture shape and lives in the same package.
//
// opts is read once, into reg's fields, before httptest.NewServer starts
// serving: the server handler reads all of them from its own goroutine, and
// every other mutable field on npmRegistry is guarded by reg.mu, so writing
// any of these late without a lock would be the odd one out.
func newNPMMetadataRegistry(t *testing.T, opts npmRegistryOptions) *npmRegistry {
	t.Helper()
	reg := &npmRegistry{
		etag:              `"upstream-v1"`,
		gzip:              opts.Gzip,
		honourConditional: opts.HonourConditional,
		padBytes:          opts.PadBytes,
		delay:             opts.Delay,
	}

	packument := func() []byte {
		old := time.Now().UTC().Add(-time.Duration(opts.OldHours) * time.Hour)
		fresh := time.Now().UTC().Add(-time.Duration(opts.FreshHours) * time.Hour)
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
		if reg.padBytes > 0 {
			doc["_padding"] = strings.Repeat("x", reg.padBytes)
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
			// A single-version manifest has no "versions" map to rewrite, so
			// it must be served exactly as upstream sent it — this branch
			// exists to give that path an upstream to hit.
			w.Header().Set("ETag", `"manifest-v1"`)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name":"left-pad","version":"1.3.0","dist":{"shasum":"bbb"}}`))
			return
		}
		if r.URL.Path == "/left-pad" {
			reg.mu.Lock()
			reg.packumentRequests = append(reg.packumentRequests, r.Header.Clone())
			reg.mu.Unlock()

			if reg.delay > 0 {
				time.Sleep(reg.delay) // widen the window so coalescing is observable
			}

			if reg.honourConditional && r.Header.Get("If-None-Match") == reg.etag {
				w.Header().Set("ETag", reg.etag)
				w.WriteHeader(http.StatusNotModified)
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

func (reg *npmRegistry) bodyCount() int {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return reg.bodiesServed
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
// It calls testify's require, so it must only ever run on the test's own
// goroutine — a concurrency test that needs the fetch itself to happen on a
// worker goroutine must use fetchPackument instead.
func getPackument(t *testing.T, srv *httptest.Server, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	resp, body, err := doFetchPackument(srv, headers)
	require.NoError(t, err)
	return resp, body
}

// packumentResult is one worker goroutine's outcome from fetchPackument: the
// status and body it got, or the error it hit, collected without ever calling
// into testify from that goroutine. t.FailNow (which require/assert.FailNow
// call on failure) is documented as illegal outside the test's own goroutine,
// so a concurrency test reads err here and asserts on it after wg.Wait().
type packumentResult struct {
	status int
	body   []byte
	err    error
}

// fetchPackument is getPackument's goroutine-safe twin: same request, but every
// failure is returned rather than asserted, so it is safe to call directly
// from a worker goroutine in a concurrency test.
func fetchPackument(srv *httptest.Server, headers map[string]string) packumentResult {
	resp, body, err := doFetchPackument(srv, headers)
	if err != nil {
		return packumentResult{err: err}
	}
	return packumentResult{status: resp.StatusCode, body: body}
}

// doFetchPackument is the shared plumbing behind getPackument and
// fetchPackument: build the request, disable transport compression so
// Content-Length assertions elsewhere hold, and read the body fully before
// closing it.
func doFetchPackument(srv *httptest.Server, headers map[string]string) (*http.Response, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/left-pad", nil)
	if err != nil {
		return nil, nil, err
	}
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

// Scenario A: the fresh version is hidden, and the response carries our own
// validator instead of upstream's.
func TestIntegration_NPMMetadataFilter_HidesFreshVersion(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1})
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
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 2, FreshHours: 1})
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
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1})
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

// Scenario B: a client revalidating with our tag gets a 304, and its
// If-None-Match must not reach upstream — a 304 from upstream would leave us
// with no body to filter.
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
	assert.Empty(t, reg.lastPackumentRequest(t).Get("If-Modified-Since"),
		"a date validator paired with our tag must not reach upstream either")
}

// Scenario C: once nothing needs hiding, the client is handed upstream's own
// validator and the untouched bytes, which puts it back on the fast path.
func TestIntegration_NPMMetadataFilter_RecoversToUpstreamTag(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1})
	blocking := newNPMProxy(t, reg, 24, "enforce", 32)

	first, _ := getPackument(t, blocking, nil)
	ourTag := first.Header.Get("ETag")
	require.True(t, strings.HasPrefix(ourTag, `"joei.`))

	// min_age_hours lowered below the fresh version's age: nothing is blocked.
	allowing := newNPMProxy(t, reg, 0, "enforce", 32)
	second, body := getPackument(t, allowing, map[string]string{"If-None-Match": ourTag})

	assert.Equal(t, http.StatusOK, second.StatusCode)
	assert.Contains(t, versionsOf(t, body), "1.3.0")
	assert.Equal(t, `"upstream-v1"`, second.Header.Get("ETag"))
	assert.NotEmpty(t, second.Header.Get("Last-Modified"), "an untouched document keeps upstream's date too")
	assert.Empty(t, reg.lastPackumentRequest(t).Get("If-None-Match"),
		"the synthetic tag must be stripped on this path too, or this test cannot tell the strip from a 200 upstream never revalidated")
}

// Scenario D: a client holding an upstream tag is revalidated against upstream,
// and an upstream 304 is relayed without a body being read at all.
func TestIntegration_NPMMetadataFilter_RelaysUpstream304(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1, HonourConditional: true})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	before := reg.bodyCount()
	// Accept-Encoding is the discriminating bit here: on the base behaviour
	// (no early return), the empty 304 body still reaches writeMetadataDocument,
	// which sees the client accepts gzip and sets Content-Encoding on the
	// response — a relayed 304 never runs that code at all, so this header's
	// presence is what would catch the early return being deleted. Equal
	// StatusCode/empty-body/upstream-saw-the-tag assertions alone pass under
	// both behaviours and would not.
	resp, body := getPackument(t, srv, map[string]string{
		"If-None-Match":   `"upstream-v1"`,
		"Accept-Encoding": "gzip",
	})

	assert.Equal(t, http.StatusNotModified, resp.StatusCode)
	assert.Empty(t, body)
	assert.Empty(t, resp.Header.Get("Content-Encoding"),
		"a relayed 304 must carry only upstream's headers, not ones this proxy would add while writing a document")
	assert.Equal(t, `"upstream-v1"`, reg.lastPackumentRequest(t).Get("If-None-Match"),
		"an upstream tag must be forwarded so upstream can answer 304")
	assert.Equal(t, before, reg.bodyCount(), "the mock served no body for this request either way; this only confirms the mock's own count, not what the proxy did with it")
}

// Scenario F: dry_run reports but never blocks, so it must never hide either.
func TestIntegration_NPMMetadataFilter_DryRunHidesNothing(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1})
	srv := newNPMProxy(t, reg, 24, "dry_run", 32)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, versionsOf(t, body), "1.3.0")
	assert.Equal(t, `"upstream-v1"`, resp.Header.Get("ETag"))
}

// Scenario E: a document over the cap is served unfiltered, and the gate takes
// over at download time. This is the only test in the suite that reaches
// proxyMetadata's over-cap streaming branch at all — every other scenario's
// fixture is small enough that readMetadataDocument never trips the limit, and
// the kill-switch scenario (capMB 0) short-circuits before proxyMetadata is
// even entered. PadBytes is set through the options struct, before
// httptest.NewServer starts, so the padded packument is what the handler
// serves from its very first request rather than a size assigned too late to
// matter.
func TestIntegration_NPMMetadataFilter_OverCapFallsBackToTheGate(t *testing.T) {
	// The mock packument is a few hundred bytes; a 1 MB cap would never trip
	// against it unpadded. 2 MiB of padding against a 1 MB cap leaves no doubt
	// the document actually crosses the limit readMetadataDocument enforces
	// (capMB<<20 bytes).
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1, PadBytes: 2 << 20})
	srv := newNPMProxy(t, reg, 24, "enforce", 1)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// If this document had actually been filtered, the padding field would
	// have survived the round trip through the filterer's JSON model same as
	// "versions" would — so also require the body to be at least as large as
	// the cap, which only the unfiltered streaming path can produce. A
	// filtered rewrite is rebuilt from the parsed document and would never be
	// this large.
	assert.Greater(t, len(body), 1<<20, "the served body must itself cross the cap, or this proves nothing about the streaming path")
	assert.Contains(t, versionsOf(t, body), "1.3.0", "an oversized document is not rewritten")
	assert.Empty(t, resp.Header.Get("Content-Length"), "the length is unknown once streamed")

	tarball, err := http.Get(srv.URL + "/left-pad/-/left-pad-1.3.0.tgz")
	require.NoError(t, err)
	defer tarball.Body.Close()
	assert.Equal(t, http.StatusLocked, tarball.StatusCode)
}

// Scenario J: a single-version manifest has no version list to rewrite, so it
// is proxied untouched and the download is what gets blocked.
func TestIntegration_NPMMetadataFilter_VersionManifestUntouched(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{OldHours: 240, FreshHours: 1})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, err := http.Get(srv.URL + "/left-pad/1.3.0")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "1.3.0")
	assert.Equal(t, `"manifest-v1"`, resp.Header.Get("ETag"), "a manifest keeps upstream's validator")

	tarball, err := http.Get(srv.URL + "/left-pad/-/left-pad-1.3.0.tgz")
	require.NoError(t, err)
	defer tarball.Body.Close()
	assert.Equal(t, http.StatusLocked, tarball.StatusCode)
}

// Concurrent clients asking for one packument must cost one upstream fetch.
// Each goroutine only records its own outcome; every require/assert call that
// could call t.FailNow runs afterwards on the test goroutine, because that
// call is documented as illegal from any other goroutine.
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

	// assert.Less alone would pass at 7 of 8 fetches, which would not notice
	// coalescing degrading to nearly nothing. Every one of the 8 identical,
	// simultaneous requests belongs to one flight, so this allows a little
	// timing slop (a fetch that lands just before the delayed leader responds
	// could miss the flight and start its own) without accepting "coalescing
	// barely happened" as a pass.
	assert.LessOrEqual(t, reg.bodyCount(), 2,
		"8 simultaneous, identical clients should collapse onto (at most) one upstream fetch")
}

// Concurrent callers whose forwarded validators differ must not share a
// flight: the flight's result is handed to every caller verbatim, so if the
// leader's validator earns a 304 from upstream, a follower coalesced into the
// same flight would be handed that same bodyless 304 — including a follower
// that sent no validator at all and has nothing to revalidate against. This is
// the axis the coalescing key exists to separate.
func TestIntegration_NPMMetadataFilter_MixedValidatorsDoNotShareAFlight(t *testing.T) {
	reg := newNPMMetadataRegistry(t, npmRegistryOptions{
		OldHours: 240, FreshHours: 1, HonourConditional: true, Delay: 150 * time.Millisecond,
	})
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	var unconditional, conditional packumentResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		unconditional = fetchPackument(srv, nil)
	}()
	go func() {
		defer wg.Done()
		conditional = fetchPackument(srv, map[string]string{"If-None-Match": `"upstream-v1"`})
	}()
	wg.Wait()

	require.NoError(t, unconditional.err)
	require.NoError(t, conditional.err)

	// The request that sent no validator has no cached copy to revalidate, so
	// it must always get a real document back — never a 304, coalesced with
	// the conditional caller's flight or not.
	assert.Equal(t, http.StatusOK, unconditional.status,
		"a request with no validator must never be answered 304")
	assert.NotContains(t, versionsOf(t, unconditional.body), "1.3.0")

	// The conditional caller sent a validator the mock honours, and it is on
	// its own flight — the coalescing key differs by the forwarded validator,
	// so it is never coalesced with the unconditional request above — so it
	// deterministically gets upstream's own 304 regardless of which goroutine
	// the scheduler happens to run first.
	assert.Equal(t, http.StatusNotModified, conditional.status)
}
