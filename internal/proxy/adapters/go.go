package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// decodeGoPath reverses Go module case-encoding: a '!' followed by a lowercase
// ASCII letter becomes that letter uppercased (e.g. "!azure" -> "Azure"). Input
// without '!' is returned unchanged. A '!' that is trailing, or followed by any
// byte other than [a-z], is invalid and yields ("", false) — reject, never guess.
func decodeGoPath(s string) (string, bool) {
	if !strings.Contains(s, "!") {
		return s, true
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '!' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			return "", false
		}
		n := s[i+1]
		if n < 'a' || n > 'z' {
			return "", false
		}
		b.WriteByte(n - ('a' - 'A'))
		i++
	}
	return b.String(), true
}

// encodeGoPath applies Go module case-encoding: each uppercase ASCII letter
// becomes '!' followed by its lowercase form. It is the inverse of decodeGoPath.
func encodeGoPath(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteByte(c + ('a' - 'A'))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// GoAdapter implements gate.RegistryAdapter for the Go module proxy protocol
// (GOPROXY). It intercepts module zip downloads for gating and proxies the rest
// of the protocol (list/.info/.mod/@latest) transparently.
type GoAdapter struct {
	upstreams  []string
	httpClient *http.Client
}

// NewGoAdapter creates a Go module adapter over the given ordered upstream URLs.
func NewGoAdapter(upstreams []string, opts ...Option) *GoAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &GoAdapter{
		upstreams:  trimmed,
		httpClient: resolveClient(opts),
	}
}

func (a *GoAdapter) Name() string { return "go" }

// NormalizeRequest intercepts module zip downloads (path contains "/@v/" and
// ends ".zip"). list/.info/.mod/@latest requests are proxied transparently.
// The case-encoded module path and version are decoded to canonical coordinates
// for OSV / allowlist lookups.
func (a *GoAdapter) NormalizeRequest(r *http.Request) (*gate.PackageRef, bool) {
	path := r.URL.Path
	if !strings.HasSuffix(path, ".zip") {
		return nil, false
	}
	idx := strings.Index(path, "/@v/")
	if idx == -1 {
		return nil, false
	}
	encModule := strings.TrimPrefix(path[:idx], "/")
	encVersion := strings.TrimSuffix(path[idx+len("/@v/"):], ".zip")
	if encModule == "" || encVersion == "" {
		return nil, false
	}
	module, ok := decodeGoPath(encModule)
	if !ok {
		return nil, false
	}
	version, ok := decodeGoPath(encVersion)
	if !ok {
		return nil, false
	}
	return &gate.PackageRef{Ecosystem: "go", Name: module, Version: version}, true
}

// UpstreamURLs returns one candidate URL per configured upstream, in order.
// The client already sent case-encoded paths, so RequestURI() is forwarded
// verbatim.
func (a *GoAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}

// goInfo is the subset of the GOPROXY .info document we consume. encoding/json
// parses the RFC3339 Time string into time.Time automatically.
type goInfo struct {
	Version string
	Time    time.Time
}

// FetchMetadata fetches the module version's .info document from each upstream
// in order, returning the first success. The .info Time is the publish date;
// the Go protocol carries no license or (SHA256) checksum there, so those stay
// empty.
func (a *GoAdapter) FetchMetadata(ctx context.Context, ref *gate.PackageRef) (*gate.PackageMetadata, error) {
	lastErr := fmt.Errorf("no upstreams configured for go")
	encModule := encodeGoPath(ref.Name)
	encVersion := encodeGoPath(ref.Version)
	for _, base := range a.upstreams {
		meta, err := a.fetchInfoFrom(ctx, base, encModule, encVersion)
		if err == nil {
			return meta, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (a *GoAdapter) fetchInfoFrom(ctx context.Context, base, encModule, encVersion string) (*gate.PackageMetadata, error) {
	apiURL := base + "/" + encModule + "/@v/" + encVersion + ".info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building go info request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching go info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("go proxy returned HTTP %d for %s", resp.StatusCode, apiURL)
	}
	var info goInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding go info: %w", err)
	}
	if info.Time.IsZero() {
		return nil, fmt.Errorf("go info for %s has no Time", encVersion)
	}
	return &gate.PackageMetadata{PublishedAt: info.Time.UTC()}, nil
}
