//go:build integration

package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/proxy/dockerproxy"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

// switchableAV reports clean until flipped to infected.
type switchableAV struct{ infected bool }

func (s *switchableAV) Scan(context.Context, string) (*gate.AVResult, error) {
	if s.infected {
		return &gate.AVResult{Clean: false, Engine: "clamav", Signature: "EICAR"}, nil
	}
	return &gate.AVResult{Clean: true}, nil
}

// switchableCVE reports clean until flipped to vulnerable.
type switchableCVE struct{ vulnerable bool }

func (s *switchableCVE) Scan(context.Context, *gate.PackageRef) (*gate.ScanResult, error) {
	if s.vulnerable {
		return &gate.ScanResult{Findings: []gate.CVEFinding{{ID: "CVE-2026-0001", Severity: gate.SeverityCritical}}}, nil
	}
	return &gate.ScanResult{Clean: true}, nil
}

// blockOnFindings blocks whenever the scan has findings.
type blockOnFindings struct{}

func (blockOnFindings) Evaluate(_ *gate.PackageRef, res *gate.ScanResult) gate.PolicyDecision {
	if len(res.Findings) > 0 {
		return gate.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: res.Findings}
	}
	return gate.PolicyDecision{Allowed: true, Reason: "ok"}
}

type recSpy struct{ events []gate.Event }

func (r *recSpy) Record(e gate.Event) { r.events = append(r.events, e) }

// pypiUpstream serves a single PyPI-style package: metadata (published
// 72h ago, older than the 24h supply-chain floor used below) plus wheel bytes.
func pypiUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	published := time.Now().UTC().Add(-72 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pypi/victim/1.0.0/json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"info":{"name":"victim","version":"1.0.0"},` +
				`"urls":[{"upload_time_iso_8601":"` + published.Format(time.RFC3339) + `","url":"x","digests":{"sha256":"a"}}]}`))
			return
		}
		_, _ = w.Write([]byte("wheel-bytes"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestLazyRecheckEvictsNewlyInfected: a cached clean artifact whose malware
// TTL has lapsed is re-scanned on the next hit; when the scanner now reports
// infected, the pull is blocked, the binary is removed from disk, and a
// BLOCK/malware event is recorded.
func TestLazyRecheckEvictsNewlyInfected(t *testing.T) {
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	upstream := pypiUpstream(t)

	av := &switchableAV{}
	rec := &recSpy{}
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:           adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:            supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:             cache.AsArtifactCache(lc),
		Logger:            zerolog.Nop(),
		AVScanner:         av,
		Recorder:          rec,
		MalwareRecheckTTL: time.Hour,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	url := srv.URL + "/packages/py3/v/victim/victim-1.0.0-py3-none-any.whl"
	resp, err := http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed pull must pass and cache")

	ref := gate.PackageRef{Ecosystem: "pypi", Name: "victim", Version: "1.0.0"}
	entry, found := lc.Get(&ref)
	require.True(t, found)

	// Expire the malware check and flip the scanner.
	require.NoError(t, lc.MarkMalwareChecked(&ref, time.Now().Add(-72*time.Hour)))
	av.infected = true

	resp, err = http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "expired entry must be re-scanned and blocked")

	_, found = lc.Get(&ref)
	require.False(t, found, "infected artifact must be evicted from the index")
	_, statErr := os.Stat(entry.ArtifactPath)
	require.True(t, os.IsNotExist(statErr), "binary must be deleted from disk")

	last := rec.events[len(rec.events)-1]
	require.Equal(t, gate.VerdictBlock, last.Verdict)
	require.Equal(t, gate.GateMalware, last.Gate)
}

// TestLazyRecheckEvictsNewCVE: a cached clean artifact whose CVE TTL has
// lapsed is re-scanned on the next hit; when the scanner now reports a
// finding the policy blocks, the pull is blocked, the binary is removed from
// disk, and a BLOCK/cve event is recorded.
func TestLazyRecheckEvictsNewCVE(t *testing.T) {
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	upstream := pypiUpstream(t)

	cve := &switchableCVE{}
	rec := &recSpy{}
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:       adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:        supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:         cache.AsArtifactCache(lc),
		Logger:        zerolog.Nop(),
		CVEScanner:    cve,
		Policy:        blockOnFindings{},
		Recorder:      rec,
		CVERecheckTTL: time.Hour,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	url := srv.URL + "/packages/py3/v/victim/victim-1.0.0-py3-none-any.whl"
	resp, err := http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed pull must pass and cache")

	ref := gate.PackageRef{Ecosystem: "pypi", Name: "victim", Version: "1.0.0"}
	entry, found := lc.Get(&ref)
	require.True(t, found)

	// Expire the CVE check and flip the scanner.
	require.NoError(t, lc.MarkCVEChecked(&ref, time.Now().Add(-72*time.Hour)))
	cve.vulnerable = true

	resp, err = http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "expired entry must be re-scanned and blocked")

	_, found = lc.Get(&ref)
	require.False(t, found, "vulnerable artifact must be evicted from the index")
	_, statErr := os.Stat(entry.ArtifactPath)
	require.True(t, os.IsNotExist(statErr), "binary must be deleted from disk")

	last := rec.events[len(rec.events)-1]
	require.Equal(t, gate.VerdictBlock, last.Verdict)
	require.Equal(t, gate.GateCVE, last.Gate)
}

// switchableImageScanner reports no findings until flipped to vulnerable.
type switchableImageScanner struct{ vulnerable bool }

func (s *switchableImageScanner) ScanImage(context.Context, string) (*dockerproxy.ImageScanResult, error) {
	if s.vulnerable {
		return &dockerproxy.ImageScanResult{Findings: []gate.CVEFinding{{ID: "CVE-2026-7", Severity: gate.SeverityCritical}}}, nil
	}
	return &dockerproxy.ImageScanResult{}, nil
}

func (s *switchableImageScanner) Health() health.Sample {
	return health.Sample{OK: true, HasData: true}
}

type blockFindingsPolicy struct{}

func (blockFindingsPolicy) Evaluate(_ *gate.PackageRef, res *gate.ScanResult) gate.PolicyDecision {
	if len(res.Findings) > 0 {
		return gate.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: res.Findings}
	}
	return gate.PolicyDecision{Allowed: true, Reason: "ok"}
}

// manifestDigest computes the canonical sha256 digest string of a manifest
// body, matching what the adapter reports as Docker-Content-Digest.
func manifestDigest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// newOfflineTestRegistry builds a fake docker registry serving a single
// image (tag "latest") with a config blob backdated 72h (older than the 24h
// supply-chain floor used in these tests) and one layer blob. It returns the
// registry server and the manifest's canonical digest string.
func newOfflineTestRegistry(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	const (
		cfgDigest   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		layerDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)
	manifest := `{"schemaVersion":2,` +
		`"mediaType":"application/vnd.docker.distribution.manifest.v2+json",` +
		`"config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"` + cfgDigest + `","size":2},` +
		`"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"` + layerDigest + `","size":2}]}`
	configBlob := `{"created":"` + time.Now().UTC().Add(-72*time.Hour).Format(time.RFC3339) + `"}`
	digestOfManifest := manifestDigest(manifest)

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/library/app/manifests/latest", "/v2/library/app/manifests/" + digestOfManifest:
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			// A real registry reports the canonical content digest; the adapter
			// falls back to the requested reference when this is absent, which
			// would make every pull key off the tag instead of the digest.
			w.Header().Set("Docker-Content-Digest", digestOfManifest)
			_, _ = w.Write([]byte(manifest))
		case "/v2/library/app/blobs/" + cfgDigest:
			_, _ = w.Write([]byte(configBlob))
		case "/v2/library/app/blobs/" + layerDigest:
			_, _ = w.Write([]byte("xx"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(registry.Close)
	return registry, digestOfManifest
}

// stripV2Prefix strips the "/v2" mux prefix before delegating to h.
// dockerproxy.Handler expects that prefix already stripped (see ParsePath's
// doc comment); in production that stripping is done by proxy.Mux
// dispatching to rawHandlers["v2"] (cmd/jo-ei/main.go). Mirror that here
// instead of serving the handler directly, so a fake registry's real
// "/v2/..." paths route the same way a live deployment would.
func stripV2Prefix(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/v2")
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		h.ServeHTTP(w, r)
	})
}

// TestLazyRecheckDockerBlocksExpiredImage: a cached clean image verdict whose
// TTL has lapsed re-runs the gate on the next manifest pull; a scanner that
// now reports a blocking CVE turns the pull into 403 and cascades the image's
// blobs out of the cache.
func TestLazyRecheckDockerBlocksExpiredImage(t *testing.T) {
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	registry, _ := newOfflineTestRegistry(t)

	const (
		cfgDigest   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		layerDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)

	scanner := &switchableImageScanner{}
	dh := dockerproxy.New(dockerproxy.HandlerDeps{
		Upstreams:  []string{registry.URL},
		Scanner:    scanner,
		AV:         &switchableAV{},
		Filter:     supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Policy:     blockFindingsPolicy{},
		Cache:      lc,
		Logger:     zerolog.Nop(),
		RecheckTTL: time.Hour,
	})
	srv := httptest.NewServer(stripV2Prefix(dh))
	t.Cleanup(srv.Close)

	// Seed pull: clean, verdict + blobs cached.
	resp, err := http.Get(srv.URL + "/v2/library/app/manifests/latest")
	require.NoError(t, err)
	digest := resp.Header.Get("Docker-Content-Digest")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotEmpty(t, digest)

	// Precondition: the seed pull must have actually cached both blobs, or the
	// later "cascade-evicted" assertion would pass vacuously (e.g. a regression
	// that broke scanLayer's PutBlob would leave the blobs uncached from the
	// start, not evicted).
	for _, d := range []string{cfgDigest, layerDigest} {
		blobRef := gate.PackageRef{Ecosystem: "docker", Name: "blobs", Version: d}
		_, found := lc.Get(&blobRef)
		require.True(t, found, "blob %s must be cached by the seed pull", d)
	}

	// Expire the verdict, flip the scanner to a blocking CVE.
	imgRef := gate.PackageRef{Ecosystem: "docker", Name: "library/app", Version: digest}
	past := time.Now().Add(-72 * time.Hour)
	require.NoError(t, lc.MarkCVEChecked(&imgRef, past))
	require.NoError(t, lc.MarkMalwareChecked(&imgRef, past))
	scanner.vulnerable = true

	resp, err = http.Get(srv.URL + "/v2/library/app/manifests/" + digest)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "expired image must be re-gated and blocked")

	// Manifest bytes stay as the blocked-verdict record, but the blobs are gone.
	for _, d := range []string{cfgDigest, layerDigest} {
		blobRef := gate.PackageRef{Ecosystem: "docker", Name: "blobs", Version: d}
		_, found := lc.Get(&blobRef)
		require.False(t, found, "blob %s must be cascade-evicted", d)
	}
}

// TestOfflineByDigestPullSurvivesUpstreamOutage: a by-digest repeat pull with
// a fresh cached verdict is served entirely from the cache — the upstream
// registry can be down.
func TestOfflineByDigestPullSurvivesUpstreamOutage(t *testing.T) {
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	registry, manifestDigestStr := newOfflineTestRegistry(t)

	h := dockerproxy.New(dockerproxy.HandlerDeps{
		Upstreams:  []string{registry.URL},
		Scanner:    &switchableImageScanner{},
		AV:         &switchableAV{},
		Filter:     supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Policy:     blockFindingsPolicy{},
		Cache:      lc,
		Logger:     zerolog.Nop(),
		RecheckTTL: time.Hour,
	})
	srv := httptest.NewServer(stripV2Prefix(h))
	t.Cleanup(srv.Close)

	// Seed pull by tag — caches the verdict + manifest body under the digest.
	resp, err := http.Get(srv.URL + "/v2/library/app/manifests/latest")
	require.NoError(t, err)
	digest := resp.Header.Get("Docker-Content-Digest")
	body1, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, manifestDigestStr, digest)

	// Kill the upstream.
	registry.Close()

	// The by-digest repeat pull must still serve, byte-identical.
	resp, err = http.Get(srv.URL + "/v2/library/app/manifests/" + digest)
	require.NoError(t, err)
	body2, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "fresh cached verdict must serve without upstream")
	require.Equal(t, body1, body2, "served manifest must be byte-identical")
	require.Equal(t, digest, resp.Header.Get("Docker-Content-Digest"))
	require.NotEmpty(t, resp.Header.Get("Content-Type"))
}
