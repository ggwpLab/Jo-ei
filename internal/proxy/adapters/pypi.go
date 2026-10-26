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

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
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
		Filename      string `json:"filename"`
		UploadTimeISO string `json:"upload_time_iso_8601"`
		URL           string `json:"url"`
	} `json:"urls"`
}

// PyPIAdapter implements gate.RegistryAdapter for PyPI.
type PyPIAdapter struct {
	upstreams  []string
	httpClient *http.Client
}

// NewPyPIAdapter creates a PyPI adapter over the given ordered upstream URLs.
func NewPyPIAdapter(upstreams []string, opts ...Option) *PyPIAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &PyPIAdapter{
		upstreams:  trimmed,
		httpClient: resolveClient(opts),
	}
}

func (a *PyPIAdapter) Name() string { return "pypi" }

// packagePathRe matches PyPI artifact download paths (e.g. /packages/...).
var packagePathRe = regexp.MustCompile(`^/packages/`)

// NormalizeRequest extracts a PackageRef from download requests.
// Returns false for /simple/ and /pypi/ (metadata) requests.
func (a *PyPIAdapter) NormalizeRequest(r *http.Request) (*gate.PackageRef, bool) {
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

	// A release holds many files (an sdist and a wheel per platform), so the
	// file name is the classifier: it gives each file its own cache slot and
	// lets FetchMetadata date the file actually requested.
	return &gate.PackageRef{
		Ecosystem:  "pypi",
		Name:       name,
		Version:    version,
		Classifier: filename,
	}, true
}

// IsArtifactPath implements gate.ArtifactPathMatcher: everything under
// /packages/ is a distribution file, except a distribution's PEP 658 core
// metadata (<file>.metadata) — the METADATA text pip reads while resolving,
// which carries no code and is proxied as-is.
func (a *PyPIAdapter) IsArtifactPath(r *http.Request) bool {
	if !packagePathRe.MatchString(r.URL.Path) {
		return false
	}
	if dist, ok := strings.CutSuffix(r.URL.Path, ".metadata"); ok {
		if _, _, parsed := parsePyPIFilename(dist[strings.LastIndex(dist, "/")+1:]); parsed {
			return false
		}
	}
	return true
}

// FetchMetadata walks the configured upstreams in order, returning the first
// success. When every upstream fails, the returned error is an
// upstream.Attempts carrying each mirror's own outcome.
func (a *PyPIAdapter) FetchMetadata(ctx context.Context, ref *gate.PackageRef) (*gate.PackageMetadata, error) {
	if len(a.upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured for pypi")
	}
	var atts upstream.Attempts
	for _, base := range a.upstreams {
		start := time.Now()
		meta, url, status, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		atts.Add(url, status, err, time.Since(start))
	}
	return nil, atts
}

func (a *PyPIAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *gate.PackageRef) (*gate.PackageMetadata, string, int, error) {
	apiURL := fmt.Sprintf("%s/pypi/%s/%s/json", base, ref.Name, ref.Version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, apiURL, 0, fmt.Errorf("building metadata request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, apiURL, 0, fmt.Errorf("fetching pypi metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, apiURL, resp.StatusCode, fmt.Errorf("package %s@%s not found on PyPI", ref.Name, ref.Version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apiURL, resp.StatusCode, fmt.Errorf("pypi returned HTTP %d", resp.StatusCode)
	}

	var info pypiJSONResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, apiURL, resp.StatusCode, fmt.Errorf("decoding pypi response: %w", err)
	}
	if len(info.URLs) == 0 {
		return nil, apiURL, resp.StatusCode, fmt.Errorf("no download URLs in pypi response for %s@%s", ref.Name, ref.Version)
	}

	// The age check dates the requested file, not the release: PyPI accepts
	// new files into an existing release, so a wheel uploaded today to a
	// two-year-old version must count as today's. Without a file name (a ref
	// built elsewhere) the newest file stands for the release, the stricter
	// choice.
	var (
		publishedAt time.Time
		found       bool
	)
	for _, f := range info.URLs {
		if ref.Classifier != "" && f.Filename != ref.Classifier {
			continue
		}
		t, err := parsePyPIUploadTime(f.UploadTimeISO)
		if err != nil {
			return nil, apiURL, resp.StatusCode, err
		}
		if !found || t.After(publishedAt) {
			publishedAt = t
		}
		found = true
	}
	if !found {
		return nil, apiURL, resp.StatusCode, fmt.Errorf("file %s not listed in pypi release %s@%s", ref.Classifier, ref.Name, ref.Version)
	}
	return &gate.PackageMetadata{
		PublishedAt: publishedAt.UTC(),
		Maintainer:  info.Info.Author,
		License:     info.Info.License,
	}, apiURL, resp.StatusCode, nil
}

// parsePyPIUploadTime parses upload_time_iso_8601, which PyPI writes with
// microseconds.
func parsePyPIUploadTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05.999999Z07:00", s)
		if err != nil {
			return time.Time{}, fmt.Errorf("parsing upload_time_iso_8601 %q: %w", s, err)
		}
	}
	return t, nil
}

// UpstreamURLs returns one candidate URL per configured upstream, in order.
func (a *PyPIAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}

// sdistExts are the source-distribution suffixes pip accepts, longest first so
// ".tar.gz" wins over ".gz"-less ".tar".
var sdistExts = []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma", ".tar.lz", ".tgz", ".tbz", ".txz", ".tlz", ".tar", ".zip"}

// parsePyPIFilename extracts the normalized package name and version from a
// filename: wheels and eggs ({dist}-{version}-...), and sdists
// ({dist}-{version}.<ext>). Extensions compare case-insensitively, as pip
// does.
func parsePyPIFilename(filename string) (name, version string, ok bool) {
	lower := strings.ToLower(filename)
	for _, ext := range []string{".whl", ".egg"} {
		if strings.HasSuffix(lower, ext) {
			// {dist}-{version}(-{build})?-{python}-{abi}-{platform}.whl
			// {dist}-{version}(-{python})?.egg
			parts := strings.SplitN(filename[:len(filename)-len(ext)], "-", 3)
			if len(parts) >= 2 {
				return normalizePyPIName(parts[0]), parts[1], true
			}
			return "", "", false
		}
	}
	for _, ext := range sdistExts {
		if strings.HasSuffix(lower, ext) {
			base := filename[:len(filename)-len(ext)]
			if idx := strings.LastIndex(base, "-"); idx > 0 {
				return normalizePyPIName(base[:idx]), base[idx+1:], true
			}
			return "", "", false
		}
	}
	return "", "", false
}

// pypiNameSeparators matches the runs PEP 503 folds into one "-".
var pypiNameSeparators = regexp.MustCompile(`[-_.]+`)

// normalizePyPIName converts a distribution name to its PEP 503 canonical
// form: lowercase, every run of "-", "_" and "." folded into one "-".
func normalizePyPIName(name string) string {
	return pypiNameSeparators.ReplaceAllString(strings.ToLower(name), "-")
}
