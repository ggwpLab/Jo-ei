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
	upstream   string
	httpClient *http.Client
}

// NewMavenAdapter creates a Maven adapter pointing at the given upstream URL
// (e.g. "https://repo1.maven.org/maven2").
func NewMavenAdapter(upstream string) *MavenAdapter {
	return &MavenAdapter{
		upstream:   strings.TrimRight(upstream, "/"),
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

// FetchMetadata issues a HEAD request to the artifact's .jar URL and reads the
// Last-Modified header as the publish time. A missing/unparseable header yields
// a zero PublishedAt (the supply chain filter treats it as old).
func (a *MavenAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	parts := strings.SplitN(ref.Name, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid maven name %q (want group:artifact)", ref.Name)
	}
	group, artifact := parts[0], parts[1]
	groupPath := strings.ReplaceAll(group, ".", "/")
	artifactURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.jar",
		a.upstream, groupPath, artifact, ref.Version, artifact, ref.Version)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, artifactURL, nil)
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

// UpstreamURL returns the upstream URL for a proxy request.
func (a *MavenAdapter) UpstreamURL(r *http.Request) string {
	return a.upstream + r.URL.RequestURI()
}
