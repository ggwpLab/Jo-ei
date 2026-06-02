//go:build integration

package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockOSVServer builds a mock osv.dev server.
// vulnMap: "Ecosystem/name@version" → single vuln JSON object (to be wrapped in {"vulns":[...]}).
// Empty string means no vulns.
func newMockOSVServer(t *testing.T, vulnMap map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Version string `json:"version"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		key := req.Package.Ecosystem + "/" + req.Package.Name + "@" + req.Version
		vuln, ok := vulnMap[key]
		if !ok || vuln == "" {
			w.Write([]byte(`{"vulns":[]}`))
			return
		}
		w.Write([]byte(`{"vulns":[` + vuln + `]}`))
	}))
}

// newPhase2Proxy wires up a full proxy with CVE scanner and policy engine.
func newPhase2Proxy(t *testing.T, upstream, osvServer *httptest.Server, prof config.PolicyProfile) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: 24 * time.Hour})
	require.NoError(t, err)

	cveScanner := scanner.NewOSVScanner(osvServer.URL, time.Minute)
	policyEngine := policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, prof)

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:     supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:      &localCacheAdapter{lc: lc},
		Logger:     zerolog.Nop(),
		CVEScanner: cveScanner,
		Policy:     policyEngine,
	})
	return httptest.NewServer(h)
}

func TestPhase2_CleanPackageAllowed(t *testing.T) {
	registry := newTestRegistry(t, "safe-pkg", "1.0.0", 48)
	defer registry.Close()
	osvSrv := newMockOSVServer(t, map[string]string{}) // no vulns for any package
	defer osvSrv.Close()

	prof := config.PolicyProfile{CVEBlock: true, CVEMinSeverity: "HIGH"}
	srv := newPhase2Proxy(t, registry, osvSrv, prof)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/s/safe-pkg/safe_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPhase2_HighCVEBlocked(t *testing.T) {
	registry := newTestRegistry(t, "vuln-pkg", "2.0.0", 48)
	defer registry.Close()
	osvSrv := newMockOSVServer(t, map[string]string{
		"PyPI/vuln-pkg@2.0.0": `{"id":"CVE-2024-001","aliases":["CVE-2024-001"],"summary":"RCE","database_specific":{"severity":"HIGH"}}`,
	})
	defer osvSrv.Close()

	prof := config.PolicyProfile{CVEBlock: true, CVEMinSeverity: "HIGH"}
	srv := newPhase2Proxy(t, registry, osvSrv, prof)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/v/vuln-pkg/vuln_pkg-2.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "cve_found", body["reason"])
	cves, ok := body["cves"].([]any)
	require.True(t, ok)
	assert.Len(t, cves, 1)
}

func TestPhase2_MediumCVEAllowed(t *testing.T) {
	registry := newTestRegistry(t, "medium-vuln", "3.0.0", 48)
	defer registry.Close()
	osvSrv := newMockOSVServer(t, map[string]string{
		"PyPI/medium-vuln@3.0.0": `{"id":"CVE-2024-002","aliases":[],"summary":"XSS","database_specific":{"severity":"MODERATE"}}`,
	})
	defer osvSrv.Close()

	prof := config.PolicyProfile{CVEBlock: true, CVEMinSeverity: "HIGH"}
	srv := newPhase2Proxy(t, registry, osvSrv, prof)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/m/medium-vuln/medium_vuln-3.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPhase2_AllowlistedBypassesCVE(t *testing.T) {
	registry := newTestRegistry(t, "critical-but-allowed", "1.0.0", 48)
	defer registry.Close()
	osvSrv := newMockOSVServer(t, map[string]string{
		"PyPI/critical-but-allowed@1.0.0": `{"id":"CVE-2024-003","aliases":["CVE-2024-003"],"summary":"Critical","database_specific":{"severity":"CRITICAL"}}`,
	})
	defer osvSrv.Close()

	prof := config.PolicyProfile{
		CVEBlock:       true,
		CVEMinSeverity: "HIGH",
		Allowlist:      []string{"pypi/critical-but-allowed"},
	}
	srv := newPhase2Proxy(t, registry, osvSrv, prof)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/c/critical-but-allowed/critical_but_allowed-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPhase2_DenylistedBlocked(t *testing.T) {
	registry := newTestRegistry(t, "evil-pkg", "1.0.0", 48)
	defer registry.Close()
	osvSrv := newMockOSVServer(t, map[string]string{}) // no CVEs, but still denylisted
	defer osvSrv.Close()

	prof := config.PolicyProfile{
		CVEBlock:       true,
		CVEMinSeverity: "HIGH",
		Denylist:       []string{"pypi/evil-pkg"},
	}
	srv := newPhase2Proxy(t, registry, osvSrv, prof)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/e/evil-pkg/evil_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	assert.Equal(t, "denylisted", body["reason"])
}

func TestPhase2_SupplyChainBlocksBeforeCVEScan(t *testing.T) {
	// New package (blocked by supply chain) — CVE scan must not be called
	osvCallCount := 0
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		osvCallCount++
		w.Write([]byte(`{"vulns":[]}`))
	}))
	defer osvSrv.Close()

	registry := newTestRegistry(t, "brand-new", "1.0.0", 1) // 1 hour old → SC blocks
	defer registry.Close()

	prof := config.PolicyProfile{CVEBlock: true, CVEMinSeverity: "HIGH"}
	srv := newPhase2Proxy(t, registry, osvSrv, prof)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/b/brand-new/brand_new-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusLocked, resp.StatusCode)
	assert.Equal(t, 0, osvCallCount, "CVE scan must not be called when SC filter blocks")
}
