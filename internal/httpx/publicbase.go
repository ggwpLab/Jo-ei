package httpx

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ErrBadForwardedHeader means the address a request names for this proxy —
// its Host, or a forwarding header from a trusted proxy — is not a usable URL
// authority, scheme or path prefix.
var ErrBadForwardedHeader = errors.New("malformed host or forwarding header")

// PublicBaseResolver derives the base URL a client used to reach this proxy,
// for links the proxy writes into documents it serves. A configured public URL
// wins outright; otherwise a trusted reverse proxy's X-Forwarded-Proto,
// X-Forwarded-Host, X-Forwarded-Port and X-Forwarded-Prefix (or the proto= and
// host= of Forwarded) describe it; otherwise the request's own Host and TLS
// state do. Forwarding headers from any other peer are ignored: a client
// could name any host in them.
//
// A nil *PublicBaseResolver trusts no proxy and has no public URL.
type PublicBaseResolver struct {
	fixed   *url.URL
	trusted TrustedPeers
}

// NewPublicBaseResolver builds a resolver. publicURL is server.public_url and
// may be empty; when set it must be an absolute http or https URL without a
// query or fragment.
func NewPublicBaseResolver(publicURL string, trusted TrustedPeers) (*PublicBaseResolver, error) {
	p := &PublicBaseResolver{trusted: trusted}
	if publicURL == "" {
		return p, nil
	}
	u, err := ParsePublicURL(publicURL)
	if err != nil {
		return nil, err
	}
	p.fixed = u
	return p, nil
}

// ParsePublicURL validates a configured public base URL and returns it with
// any trailing slash removed.
func ParsePublicURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("public URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("public URL %q: scheme must be http or https", raw)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("public URL %q: want scheme://host[:port][/path] only", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// Base returns the client-facing base URL for r: scheme, host and path prefix,
// with no trailing slash. An error wraps ErrBadForwardedHeader.
func (p *PublicBaseResolver) Base(r *http.Request) (*url.URL, error) {
	if p != nil && p.fixed != nil {
		u := *p.fixed
		return &u, nil
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	var prefix, port string

	if p != nil && p.trusted.PeerTrusted(r) {
		proto, fwdHost := firstValue(r, "X-Forwarded-Proto"), firstValue(r, "X-Forwarded-Host")
		if proto == "" && fwdHost == "" {
			proto, fwdHost = forwardedProtoHost(r)
		}
		if proto != "" {
			scheme = strings.ToLower(proto)
		}
		if fwdHost != "" {
			host = fwdHost
			port = firstValue(r, "X-Forwarded-Port")
		}
		prefix = firstValue(r, "X-Forwarded-Prefix")
	}

	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q", ErrBadForwardedHeader, scheme)
	}
	if !validAuthority(host) {
		return nil, fmt.Errorf("%w: host %q", ErrBadForwardedHeader, host)
	}
	if port != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), port)
			if !validAuthority(host) {
				return nil, fmt.Errorf("%w: port %q", ErrBadForwardedHeader, port)
			}
		}
	}
	if prefix != "" {
		if !strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "?#") {
			return nil, fmt.Errorf("%w: prefix %q", ErrBadForwardedHeader, prefix)
		}
		prefix = strings.TrimRight(prefix, "/")
	}
	return &url.URL{Scheme: scheme, Host: host, Path: prefix}, nil
}

// firstValue returns the first comma-separated entry of header name. Chained
// proxies append to the list, so the first entry is the one the client saw.
func firstValue(r *http.Request, name string) string {
	v, _, _ := strings.Cut(r.Header.Get(name), ",")
	return strings.TrimSpace(v)
}

// forwardedProtoHost reads proto= and host= from the first RFC 7239 Forwarded
// element.
func forwardedProtoHost(r *http.Request) (proto, host string) {
	element, _, _ := strings.Cut(r.Header.Get(HeaderForwarded), ",")
	for _, param := range strings.Split(element, ";") {
		k, v, found := strings.Cut(strings.TrimSpace(param), "=")
		if !found {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "proto":
			proto = v
		case "host":
			host = v
		}
	}
	return proto, host
}

// validAuthority reports whether host is a bare host[:port] that a URL carries
// unchanged — no path, userinfo, spaces or other smuggled syntax.
func validAuthority(host string) bool {
	if host == "" || strings.ContainsAny(host, " /\\?#@") {
		return false
	}
	u, err := url.Parse("http://" + host)
	return err == nil && u.Host == host && u.Path == ""
}
