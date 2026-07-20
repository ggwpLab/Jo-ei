package adapters

import (
	"net/http"
	"strings"

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
