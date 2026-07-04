package adapters

import (
	"context"
	"net/http"
	"strings"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// mavenArtifactExts are the binary artifact extensions we intercept and scan.
var mavenArtifactExts = []string{".jar", ".war", ".aar"}

// MavenAdapter implements gate.RegistryAdapter for a Maven repository.
type MavenAdapter struct {
	upstreams  []string
	httpClient *http.Client
}

// NewMavenAdapter creates a Maven adapter over the given ordered upstream URLs
// (e.g. "https://repo1.maven.org/maven2"). Upstreams are tried in order.
func NewMavenAdapter(upstreams []string, opts ...Option) *MavenAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &MavenAdapter{
		upstreams:  trimmed,
		httpClient: resolveClient(opts),
	}
}

func (a *MavenAdapter) Name() string { return "maven" }

// NormalizeRequest intercepts binary artifact downloads (.jar/.war/.aar).
// Sidecar files (.pom, .sha1, .md5, .asc) are proxied transparently.
func (a *MavenAdapter) NormalizeRequest(r *http.Request) (*gate.PackageRef, bool) {
	if !hasMavenArtifactExt(r.URL.Path) {
		return nil, false
	}
	name, version, classifier, ok := parseMavenPath(r.URL.Path)
	if !ok {
		return nil, false
	}
	return &gate.PackageRef{
		Ecosystem:  "maven",
		Name:       name,
		Version:    version,
		Classifier: classifier,
	}, true
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
// name "group:artifact", the version, and the optional classifier.
//
// The file name follows "<artifact>-<version>[-<classifier>].<ext>". The
// classifier (e.g. "sources", "javadoc") is returned separately so it can
// disambiguate the cache key: without it, "foo-1.0.jar" and
// "foo-1.0-sources.jar" would share one cache slot and serve each other's bytes.
func parseMavenPath(path string) (name, version, classifier string, ok bool) {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segs) < 4 {
		return "", "", "", false
	}
	file := segs[len(segs)-1]
	version = segs[len(segs)-2]
	artifact := segs[len(segs)-3]
	group := strings.Join(segs[:len(segs)-3], ".")
	if group == "" || artifact == "" || version == "" {
		return "", "", "", false
	}
	classifier = mavenClassifier(file, artifact, version)
	return group + ":" + artifact, version, classifier, true
}

// mavenClassifier extracts the classifier token from an artifact file name of
// the form "<artifact>-<version>[-<classifier>].<ext>". It returns "" for the
// main artifact or when the name does not match the expected prefix.
func mavenClassifier(file, artifact, version string) string {
	prefix := artifact + "-" + version
	rest, ok := strings.CutPrefix(file, prefix)
	if !ok {
		return ""
	}
	// rest is ".<ext>" (main) or "-<classifier>.<ext>".
	if dot := strings.LastIndex(rest, "."); dot >= 0 {
		rest = rest[:dot]
	}
	return strings.TrimPrefix(rest, "-")
}

// FetchMetadata is a no-op for Maven: there is no separate metadata API to call.
// The publish-date proxy (the artifact's Last-Modified) is read from the
// download response instead — see MetadataFromHeader — so a pull costs one GET
// rather than an extra HEAD on the .pom. MavenAdapter implements
// gate.DownloadMetadataExtractor, so the handler never calls this; it exists to
// satisfy the RegistryAdapter contract.
func (a *MavenAdapter) FetchMetadata(_ context.Context, _ *gate.PackageRef) (*gate.PackageMetadata, error) {
	return &gate.PackageMetadata{}, nil
}

// MetadataFromHeader derives package metadata from an artifact download
// response. Maven Central serves artifacts as static files, so the .jar's
// Last-Modified is a sound proxy for the publish date used by the supply-chain
// age check. A missing/unparseable header yields a zero PublishedAt (treated as
// old), matching the previous behavior when the .pom carried no Last-Modified.
func (a *MavenAdapter) MetadataFromHeader(h http.Header) *gate.PackageMetadata {
	meta := &gate.PackageMetadata{}
	if lm := h.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			meta.PublishedAt = t.UTC()
		}
	}
	return meta
}

// UpstreamURLs returns one candidate URL per configured upstream, in order.
func (a *MavenAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}
