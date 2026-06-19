package adapters

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
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
	name, version, classifier, ok := parseMavenPath(r.URL.Path)
	if !ok {
		return nil, false
	}
	return &proxy.PackageRef{
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

	resp, err := a.headWithRetry(ctx, pomURL)
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

// Maven Central rate-limits bursts with HTTP 429. We retry a bounded number of
// times, honoring Retry-After when present, so transient throttling does not
// fail an otherwise-valid download.
const (
	mavenMaxMetadataRetries = 3
	mavenRetryBaseDelay     = 500 * time.Millisecond
	mavenRetryMaxDelay      = 10 * time.Second
)

// headWithRetry performs a HEAD request, retrying on 429/503 with backoff that
// honors the Retry-After header. It returns the last response (which the caller
// inspects) or a transport/context error.
func (a *MavenAdapter) headWithRetry(ctx context.Context, url string) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			return nil, fmt.Errorf("building maven HEAD request: %w", err)
		}
		resp, err := a.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests &&
			resp.StatusCode != http.StatusServiceUnavailable {
			return resp, nil
		}
		if attempt >= mavenMaxMetadataRetries {
			// Out of retries: hand the throttled response back to the caller,
			// which turns it into a "maven returned HTTP 429" error.
			return resp, nil
		}
		delay := retryAfterDelay(resp.Header.Get("Retry-After"), attempt)
		resp.Body.Close()
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// retryAfterDelay computes how long to wait before the next attempt. It honors
// a Retry-After header (delta-seconds or HTTP-date) when valid, otherwise falls
// back to exponential backoff. The result is capped at mavenRetryMaxDelay.
func retryAfterDelay(header string, attempt int) time.Duration {
	if header != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && secs >= 0 {
			return capDelay(time.Duration(secs) * time.Second)
		}
		if t, err := http.ParseTime(header); err == nil {
			if d := time.Until(t); d > 0 {
				return capDelay(d)
			}
			return 0
		}
	}
	// Exponential backoff: base * 2^attempt.
	return capDelay(mavenRetryBaseDelay << attempt)
}

func capDelay(d time.Duration) time.Duration {
	if d > mavenRetryMaxDelay {
		return mavenRetryMaxDelay
	}
	if d < 0 {
		return 0
	}
	return d
}

// UpstreamURLs returns one candidate URL per configured upstream, in order.
func (a *MavenAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}
