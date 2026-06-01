package adapters

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// mavenArtifactExts are the binary artifact extensions we intercept and scan.
var mavenArtifactExts = []string{".jar", ".war", ".aar"}

// MavenAdapter implements proxy.RegistryAdapter for a Maven repository.
type MavenAdapter struct {
	upstreams  []string
	httpClient *http.Client
}

// NewMavenAdapter creates a Maven adapter over the given ordered upstream URLs
// (e.g. "https://repo1.maven.org/maven2"). Upstreams are tried in order.
func NewMavenAdapter(upstreams []string) *MavenAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &MavenAdapter{
		upstreams:  trimmed,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *MavenAdapter) Name() string { return "maven" }

// NormalizeRequest intercepts binary artifact downloads (.jar/.war/.aar).
// Sidecar files (.pom, .sha1, .md5, .asc) are proxied transparently.
func (a *MavenAdapter) NormalizeRequest(r *http.Request) (*proxy.PackageRef, bool) {
	if !hasMavenArtifactExt(r.URL.Path) {
		return nil, false
	}
	name, version, ok := parseMavenPath(r.URL.Path)
	if !ok {
		return nil, false
	}
	return &proxy.PackageRef{Ecosystem: "maven", Name: name, Version: version}, true
}

func hasMavenArtifactExt(path string) bool {
	for _, ext := range mavenArtifactExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// parseMavenPath parses "/<group/as/path>/<artifact>/<version>/<file>" into
// name "group:artifact" and the version.
func parseMavenPath(path string) (name, version string, ok bool) {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segs) < 4 {
		return "", "", false
	}
	version = segs[len(segs)-2]
	artifact := segs[len(segs)-3]
	group := strings.Join(segs[:len(segs)-3], ".")
	if group == "" || artifact == "" || version == "" {
		return "", "", false
	}
	return group + ":" + artifact, version, true
}

// FetchMetadata walks the configured upstreams in order, returning the first
// success. If all upstreams fail, the last error is returned.
func (a *MavenAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	lastErr := fmt.Errorf("no upstreams configured for maven")
	for _, base := range a.upstreams {
		meta, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (a *MavenAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	parts := strings.SplitN(ref.Name, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid maven name %q (want group:artifact)", ref.Name)
	}
	group, artifact := parts[0], parts[1]
	groupPath := strings.ReplaceAll(group, ".", "/")
	pomURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom",
		base, groupPath, artifact, ref.Version, artifact, ref.Version)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, pomURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building maven HEAD request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching maven artifact head: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("maven returned HTTP %d for %s", resp.StatusCode, ref.Key())
	}

	meta := &proxy.PackageMetadata{}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			meta.PublishedAt = t.UTC()
		}
	}
	return meta, nil
}

// UpstreamURLs returns one candidate URL per configured upstream, in order.
func (a *MavenAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}
