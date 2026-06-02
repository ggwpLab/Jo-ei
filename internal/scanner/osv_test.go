package scanner_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockOSV builds an httptest.Server that serves canned OSV responses.
// responses maps "Ecosystem/name@version" → OSV JSON response body string.
func newMockOSV(t *testing.T, responses map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/query", r.URL.Path)

		var req struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Version string `json:"version"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		key := req.Package.Ecosystem + "/" + req.Package.Name + "@" + req.Version
		body, ok := responses[key]
		if !ok {
			body = `{"vulns":[]}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
}

func TestOSVScanner_CleanPackage(t *testing.T) {
	srv := newMockOSV(t, map[string]string{
		"PyPI/requests@2.31.0": `{"vulns":[]}`,
	})
	defer srv.Close()

	sc := scanner.NewOSVScanner(srv.URL, time.Minute)
	result, err := sc.Scan(context.Background(), &proxy.PackageRef{
		Ecosystem: "pypi", Name: "requests", Version: "2.31.0",
	})
	require.NoError(t, err)
	assert.True(t, result.Clean)
	assert.Empty(t, result.Findings)
}

func TestOSVScanner_CriticalCVE(t *testing.T) {
	srv := newMockOSV(t, map[string]string{
		"PyPI/requests@2.28.0": `{
			"vulns": [{
				"id": "GHSA-9wx4-h78v-vm56",
				"aliases": ["CVE-2024-35195"],
				"summary": "RCE in requests",
				"database_specific": {"severity": "CRITICAL"}
			}]
		}`,
	})
	defer srv.Close()

	sc := scanner.NewOSVScanner(srv.URL, time.Minute)
	result, err := sc.Scan(context.Background(), &proxy.PackageRef{
		Ecosystem: "pypi", Name: "requests", Version: "2.28.0",
	})
	require.NoError(t, err)
	assert.False(t, result.Clean)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "CVE-2024-35195", result.Findings[0].ID)
	assert.Equal(t, proxy.SeverityCritical, result.Findings[0].Severity)
	assert.Equal(t, "RCE in requests", result.Findings[0].Summary)
	assert.NotEmpty(t, result.ScanJSON)
}

func TestOSVScanner_ModerateIsMedium(t *testing.T) {
	srv := newMockOSV(t, map[string]string{
		"PyPI/flask@2.0.0": `{
			"vulns": [{
				"id": "PYSEC-2024-001",
				"aliases": [],
				"summary": "XSS in flask",
				"database_specific": {"severity": "MODERATE"}
			}]
		}`,
	})
	defer srv.Close()

	sc := scanner.NewOSVScanner(srv.URL, time.Minute)
	result, err := sc.Scan(context.Background(), &proxy.PackageRef{
		Ecosystem: "pypi", Name: "flask", Version: "2.0.0",
	})
	require.NoError(t, err)
	assert.False(t, result.Clean)
	assert.Equal(t, proxy.SeverityMedium, result.Findings[0].Severity)
	// When no CVE alias, should use the PYSEC id
	assert.Equal(t, "PYSEC-2024-001", result.Findings[0].ID)
}

func TestOSVScanner_CachesResults(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write([]byte(`{"vulns":[]}`))
	}))
	defer srv.Close()

	sc := scanner.NewOSVScanner(srv.URL, time.Minute)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "django", Version: "4.0.0"}

	_, err := sc.Scan(context.Background(), ref)
	require.NoError(t, err)
	_, err = sc.Scan(context.Background(), ref)
	require.NoError(t, err)

	assert.Equal(t, 1, callCount, "second call should hit cache, not upstream")
}

func TestOSVScanner_CacheExpires(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write([]byte(`{"vulns":[]}`))
	}))
	defer srv.Close()

	sc := scanner.NewOSVScanner(srv.URL, 10*time.Millisecond) // very short TTL
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "pillow", Version: "9.0.0"}

	_, err := sc.Scan(context.Background(), ref)
	require.NoError(t, err)

	time.Sleep(20 * time.Millisecond) // cache expired

	_, err = sc.Scan(context.Background(), ref)
	require.NoError(t, err)

	assert.Equal(t, 2, callCount, "expired cache should trigger new upstream call")
}

func TestOSVScanner_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sc := scanner.NewOSVScanner(srv.URL, time.Minute)
	_, err := sc.Scan(context.Background(), &proxy.PackageRef{
		Ecosystem: "pypi", Name: "broken", Version: "1.0.0",
	})
	require.Error(t, err)
}

func TestOSVScanner_RubyGemsStripsPlatformSuffix(t *testing.T) {
	srv := newMockOSV(t, map[string]string{
		"RubyGems/nokogiri@1.15.0": `{
			"vulns": [{
				"id": "GHSA-xxxx",
				"aliases": ["CVE-2023-0001"],
				"summary": "vuln in nokogiri",
				"database_specific": {"severity": "HIGH"}
			}]
		}`,
	})
	defer srv.Close()

	sc := scanner.NewOSVScanner(srv.URL, time.Minute)
	result, err := sc.Scan(context.Background(), &proxy.PackageRef{
		Ecosystem: "rubygems", Name: "nokogiri", Version: "1.15.0-x86_64-linux",
	})
	require.NoError(t, err)
	require.False(t, result.Clean)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "CVE-2023-0001", result.Findings[0].ID)
}

func TestOSVScanner_EcosystemMapping(t *testing.T) {
	var capturedEcosystem string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		capturedEcosystem = req.Package.Ecosystem
		w.Write([]byte(`{"vulns":[]}`))
	}))
	defer srv.Close()

	sc := scanner.NewOSVScanner(srv.URL, time.Minute)

	cases := []struct{ ecosystem, want string }{
		{"pypi", "PyPI"},
		{"npm", "npm"},
		{"maven", "Maven"},
		{"go", "Go"},
		{"rubygems", "RubyGems"},
	}
	for _, c := range cases {
		sc.Scan(context.Background(), &proxy.PackageRef{Ecosystem: c.ecosystem, Name: "x", Version: "1.0.0"})
		assert.Equal(t, c.want, capturedEcosystem, "ecosystem %q", c.ecosystem)
	}
}
