package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// npmMetadata is the subset of the npm registry document we consume.
type npmMetadata struct {
	Time     map[string]string `json:"time"`
	Versions map[string]struct {
		License string `json:"license"`
		Dist    struct {
			Shasum string `json:"shasum"`
		} `json:"dist"`
	} `json:"versions"`
}

// NPMAdapter implements proxy.RegistryAdapter for the npm registry.
type NPMAdapter struct {
	upstreams  []string
	httpClient *http.Client
}

// NewNPMAdapter creates an npm adapter over the given ordered upstream URLs.
func NewNPMAdapter(upstreams []string) *NPMAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &NPMAdapter{
		upstreams:  trimmed,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *NPMAdapter) Name() string { return "npm" }

// NormalizeRequest intercepts tarball downloads (path contains "/-/" and ends ".tgz").
// Metadata documents (e.g. "/lodash") are proxied transparently.
func (a *NPMAdapter) NormalizeRequest(r *http.Request) (*proxy.PackageRef, bool) {
	path := r.URL.Path
	if !strings.HasSuffix(path, ".tgz") {
		return nil, false
	}
	idx := strings.Index(path, "/-/")
	if idx == -1 {
		return nil, false
	}
	name := strings.TrimPrefix(path[:idx], "/")
	filename := path[idx+len("/-/"):]
	version, ok := parseNPMVersion(name, filename)
	if !ok {
		return nil, false
	}
	return &proxy.PackageRef{Ecosystem: "npm", Name: name, Version: version}, true
}

// parseNPMVersion extracts the version from a tarball filename "<unscoped>-<version>.tgz".
func parseNPMVersion(name, filename string) (string, bool) {
	base := strings.TrimSuffix(filename, ".tgz")
	unscoped := name
	if idx := strings.LastIndex(name, "/"); idx != -1 {
		unscoped = name[idx+1:]
	}
	prefix := unscoped + "-"
	if !strings.HasPrefix(base, prefix) {
		return "", false
	}
	version := strings.TrimPrefix(base, prefix)
	if version == "" {
		return "", false
	}
	return version, true
}

// FetchMetadata walks the configured upstreams in order, returning the first success.
func (a *NPMAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	lastErr := fmt.Errorf("no upstreams configured for npm")
	for _, base := range a.upstreams {
		meta, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (a *NPMAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	apiURL := base + "/" + ref.Name

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building npm metadata request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching npm metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm returned HTTP %d for %s", resp.StatusCode, ref.Name)
	}

	var doc npmMetadata
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding npm response: %w", err)
	}
	publishedStr, ok := doc.Time[ref.Version]
	if !ok {
		return nil, fmt.Errorf("version %s not found in npm metadata for %s", ref.Version, ref.Name)
	}
	publishedAt, err := time.Parse(time.RFC3339, publishedStr)
	if err != nil {
		return nil, fmt.Errorf("parsing npm publish time %q: %w", publishedStr, err)
	}
	versionInfo, ok := doc.Versions[ref.Version]
	if !ok {
		return nil, fmt.Errorf("version %s missing from npm versions map for %s", ref.Version, ref.Name)
	}
	return &proxy.PackageMetadata{
		PublishedAt: publishedAt.UTC(),
		License:     versionInfo.License,
		Checksum:    versionInfo.Dist.Shasum,
	}, nil
}

// UpstreamURLs returns one candidate URL per configured upstream, in order.
func (a *NPMAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}
