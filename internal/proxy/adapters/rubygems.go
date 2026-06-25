package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// rubygemsVersion is one entry in the /api/v1/versions/<gem>.json array.
type rubygemsVersion struct {
	Number    string   `json:"number"`
	Platform  string   `json:"platform"`
	CreatedAt string   `json:"created_at"`
	Licenses  []string `json:"licenses"`
	SHA       string   `json:"sha"`
}

// RubyGemsAdapter implements proxy.RegistryAdapter for a RubyGems repository.
type RubyGemsAdapter struct {
	upstreams  []string
	httpClient *http.Client
}

// NewRubyGemsAdapter creates a RubyGems adapter over the given ordered upstream
// URLs (e.g. "https://rubygems.org"). Upstreams are tried in order.
func NewRubyGemsAdapter(upstreams []string, opts ...Option) *RubyGemsAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &RubyGemsAdapter{
		upstreams:  trimmed,
		httpClient: resolveClient(opts),
	}
}

func (a *RubyGemsAdapter) Name() string { return "rubygems" }

// NormalizeRequest intercepts gem downloads: /gems/<name>-<version>[-<platform>].gem.
// API/index paths (/api/, /info/, /versions, /quick/, /specs*) are proxied transparently.
func (a *RubyGemsAdapter) NormalizeRequest(r *http.Request) (*proxy.PackageRef, bool) {
	path := r.URL.Path
	if !strings.HasSuffix(path, ".gem") {
		return nil, false
	}
	idx := strings.LastIndex(path, "/gems/")
	if idx == -1 {
		return nil, false
	}
	filename := path[idx+len("/gems/"):]
	if strings.Contains(filename, "/") {
		return nil, false
	}
	name, version, ok := parseGemFilename(filename)
	if !ok {
		return nil, false
	}
	return &proxy.PackageRef{Ecosystem: "rubygems", Name: name, Version: version}, true
}

// parseGemFilename parses "<name>-<version>[-<platform>].gem". The version is the
// first hyphen-separated segment beginning with a digit (gem versions contain no
// hyphens); everything before it is the name; any trailing segments are the
// platform. Returns the name and an encoded version: "<number>" for pure-ruby
// gems or "<number>-<platform>" for platform gems.
func parseGemFilename(filename string) (name, version string, ok bool) {
	base := strings.TrimSuffix(filename, ".gem")
	segs := strings.Split(base, "-")
	verIdx := -1
	for i, s := range segs {
		if s != "" && s[0] >= '0' && s[0] <= '9' {
			verIdx = i
			break
		}
	}
	if verIdx <= 0 { // no digit-led segment found (-1), or it is the first segment (no name before it)
		return "", "", false
	}
	name = strings.Join(segs[:verIdx], "-")
	number := segs[verIdx]
	platform := strings.Join(segs[verIdx+1:], "-")
	if name == "" {
		return "", "", false
	}
	if platform == "" {
		return name, number, true
	}
	return name, number + "-" + platform, true
}

// UpstreamURLs returns one candidate URL per configured upstream, in order.
func (a *RubyGemsAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}

// FetchMetadata walks the configured upstreams in order, returning the first
// success. If all upstreams fail, the last error is returned.
func (a *RubyGemsAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	lastErr := fmt.Errorf("no upstreams configured for rubygems")
	for _, base := range a.upstreams {
		meta, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (a *RubyGemsAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	number, platform := splitGemVersion(ref.Version)
	apiURL := fmt.Sprintf("%s/api/v1/versions/%s.json", base, ref.Name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building rubygems metadata request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching rubygems metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rubygems returned HTTP %d for %s", resp.StatusCode, ref.Name)
	}

	var versions []rubygemsVersion
	if err := json.NewDecoder(resp.Body).Decode(&versions); err != nil {
		return nil, fmt.Errorf("decoding rubygems response: %w", err)
	}

	for _, v := range versions {
		if v.Number == number && v.Platform == platform {
			publishedAt, err := time.Parse(time.RFC3339, v.CreatedAt)
			if err != nil {
				return nil, fmt.Errorf("parsing rubygems created_at %q: %w", v.CreatedAt, err)
			}
			return &proxy.PackageMetadata{
				PublishedAt: publishedAt.UTC(),
				License:     strings.Join(v.Licenses, ", "),
				Checksum:    v.SHA,
			}, nil
		}
	}
	return nil, fmt.Errorf("version %s (platform %s) not found for rubygems gem %s", number, platform, ref.Name)
}

// splitGemVersion decodes an encoded ref version into (number, platform).
// "1.15.0" -> ("1.15.0", "ruby"); "1.15.0-x86_64-linux" -> ("1.15.0", "x86_64-linux").
func splitGemVersion(version string) (number, platform string) {
	parts := strings.SplitN(version, "-", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return parts[0], "ruby"
}
