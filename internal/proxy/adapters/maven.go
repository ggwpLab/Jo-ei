package adapters

import (
	"context"
	"net/http"
	"strings"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// mavenSidecarExts are the extensions of files that sit beside an artifact and
// carry no code: the POM, Gradle module metadata, repository metadata,
// checksums and signatures. Every other file in a version directory is an
// artifact and goes through the gates — native executables, archives and
// plugin bundles ship code as surely as a jar does.
var mavenSidecarExts = []string{".pom", ".module", ".xml", ".md5", ".sha1", ".sha256", ".sha512", ".asc", ".sig"}

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

// NormalizeRequest intercepts artifact downloads: any file in a version
// directory except the sidecars in mavenSidecarExts, which are proxied
// transparently.
func (a *MavenAdapter) NormalizeRequest(r *http.Request) (*gate.PackageRef, bool) {
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

// IsArtifactPath implements gate.ArtifactPathMatcher. In the Maven layout an
// artifact is recognised by the same rule that names it, so every artifact
// path NormalizeRequest sees is one it can parse.
func (a *MavenAdapter) IsArtifactPath(r *http.Request) bool {
	_, _, _, ok := parseMavenPath(r.URL.Path)
	return ok
}

func isMavenSidecar(file string) bool {
	for _, ext := range mavenSidecarExts {
		if strings.HasSuffix(file, ext) {
			return true
		}
	}
	return false
}

// parseMavenPath parses "/<group/as/path>/<artifact>/<version>/<file>" into
// name "group:artifact", the version, and the classifier that keeps the file's
// cache slot apart from its siblings'. It reports false for anything that is
// not an artifact file: a sidecar, a directory listing, or a file whose name
// does not start with "<artifact>-", which every file Maven or Gradle resolves
// from coordinates does.
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
	if !strings.HasPrefix(file, artifact+"-") || isMavenSidecar(file) {
		return "", "", "", false
	}
	return group + ":" + artifact, version, mavenClassifier(file, artifact, version), true
}

// mavenClassifier names a file within its version directory, for the cache
// key. A file "<artifact>-<version>[-<classifier>].<ext>" yields the classifier
// token ("" for the main jar, "sources" for the sources jar) with ".<ext>"
// appended unless the extension is "jar" — so "app-1.0.zip" (".zip") and
// "app-1.0.jar" ("") do not share a slot, and jar keys stay as they were. Any
// other name — notably a timestamped snapshot build such as
// "foo-1.0-20231010.123456-1.jar" in directory "1.0-SNAPSHOT" — yields the
// whole file name, which is unique within the directory.
func mavenClassifier(file, artifact, version string) string {
	rest, ok := strings.CutPrefix(file, artifact+"-"+version)
	if !ok || rest == "" {
		return file
	}
	var cls, ext string
	switch {
	case strings.HasPrefix(rest, "-"):
		cls, ext, _ = strings.Cut(rest[1:], ".")
	case strings.HasPrefix(rest, "."):
		ext = rest[1:]
	default:
		return file
	}
	if ext == "jar" {
		return cls
	}
	return cls + "." + ext
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
// age check. A missing/unparseable header yields a zero PublishedAt, which the
// age check treats as old.
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
