// Package adapters implements per-registry RegistryAdapter implementations.
package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// pypiJSONResponse represents the PyPI JSON API response for a specific version.
type pypiJSONResponse struct {
	Info struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		License string `json:"license"`
		Author  string `json:"author"`
	} `json:"info"`
	URLs []struct {
		UploadTimeISO string `json:"upload_time_iso_8601"`
		URL           string `json:"url"`
		Digests       struct {
			SHA256 string `json:"sha256"`
		} `json:"digests"`
	} `json:"urls"`
}

// PyPIAdapter implements proxy.RegistryAdapter for PyPI.
type PyPIAdapter struct {
	upstreams  []string
	httpClient *http.Client
}

// NewPyPIAdapter creates a PyPI adapter over the given ordered upstream URLs.
func NewPyPIAdapter(upstreams []string) *PyPIAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &PyPIAdapter{
		upstreams:  trimmed,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *PyPIAdapter) Name() string { return "pypi" }

// packagePathRe matches PyPI artifact download paths (e.g. /packages/...).
var packagePathRe = regexp.MustCompile(`^/packages/`)

// NormalizeRequest extracts a PackageRef from download requests.
// Returns false for /simple/ and /pypi/ (metadata) requests.
func (a *PyPIAdapter) NormalizeRequest(r *http.Request) (*proxy.PackageRef, bool) {
	if !packagePathRe.MatchString(r.URL.Path) {
		return nil, false
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 2 {
		return nil, false
	}

	filename := parts[len(parts)-1]
	// Strip hash fragment if present (e.g., filename.whl#sha256=...)
	if idx := strings.Index(filename, "#"); idx != -1 {
		filename = filename[:idx]
	}

	name, version, ok := parsePyPIFilename(filename)
	if !ok {
		return nil, false
	}

	return &proxy.PackageRef{
		Ecosystem: "pypi",
		Name:      name,
		Version:   version,
	}, true
}

// FetchMetadata walks the configured upstreams in order, returning the first
// success. If all upstreams fail, the last error is returned.
func (a *PyPIAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	lastErr := fmt.Errorf("no upstreams configured for pypi")
	for _, base := range a.upstreams {
		meta, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (a *PyPIAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	apiURL := fmt.Sprintf("%s/pypi/%s/%s/json", base, ref.Name, ref.Version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building metadata request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching pypi metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %s@%s not found on PyPI", ref.Name, ref.Version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi returned HTTP %d", resp.StatusCode)
	}

	var info pypiJSONResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding pypi response: %w", err)
	}
	if len(info.URLs) == 0 {
		return nil, fmt.Errorf("no download URLs in pypi response for %s@%s", ref.Name, ref.Version)
	}

	publishedAt, err := time.Parse(time.RFC3339, info.URLs[0].UploadTimeISO)
	if err != nil {
		publishedAt, err = time.Parse("2006-01-02T15:04:05.999999Z07:00", info.URLs[0].UploadTimeISO)
		if err != nil {
			return nil, fmt.Errorf("parsing upload_time_iso_8601 %q: %w", info.URLs[0].UploadTimeISO, err)
		}
	}
	return &proxy.PackageMetadata{
		PublishedAt: publishedAt.UTC(),
		Maintainer:  info.Info.Author,
		License:     info.Info.License,
		Checksum:    info.URLs[0].Digests.SHA256,
	}, nil
}

// UpstreamURLs returns one candidate URL per configured upstream, in order.
func (a *PyPIAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}

// parsePyPIFilename extracts the normalized package name and version from a filename.
// Handles wheels (.whl), source distributions (.tar.gz, .zip).
func parsePyPIFilename(filename string) (name, version string, ok bool) {
	switch {
	case strings.HasSuffix(filename, ".whl"):
		// Wheel: {dist}-{version}(-{build})?-{python}-{abi}-{platform}.whl
		parts := strings.SplitN(strings.TrimSuffix(filename, ".whl"), "-", 3)
		if len(parts) >= 2 {
			return normalizePyPIName(parts[0]), parts[1], true
		}
	case strings.HasSuffix(filename, ".tar.gz"):
		base := strings.TrimSuffix(filename, ".tar.gz")
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			return normalizePyPIName(base[:idx]), base[idx+1:], true
		}
	case strings.HasSuffix(filename, ".zip"):
		base := strings.TrimSuffix(filename, ".zip")
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			return normalizePyPIName(base[:idx]), base[idx+1:], true
		}
	}
	return "", "", false
}

// normalizePyPIName converts distribution name to canonical form (lowercase, _ → -).
func normalizePyPIName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}
