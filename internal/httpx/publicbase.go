package httpx

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/rs/zerolog"
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
// state do. Forwarding headers from any other peer are ignored, with a
// one-time warning: a client could name any host in them.
//
// A nil *PublicBaseResolver trusts no proxy and has no public URL.
type PublicBaseResolver struct {
	fixed   *url.URL
	trusted TrustedPeers
	log     zerolog.Logger
	warned  atomic.Bool
}

// NewPublicBaseResolver builds a resolver. publicURL is server.public_url and
// may be empty; when set it must be an absolute http or https URL without a
// query or fragment.
func NewPublicBaseResolver(publicURL string, trusted TrustedPeers, log zerolog.Logger) (*PublicBaseResolver, error) {
	p := &PublicBaseResolver{trusted: trusted, log: log}
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

	switch {
	case p != nil && p.trusted.PeerTrusted(r):
		proto, fwdHost := lastValue(r, "X-Forwarded-Proto"), lastValue(r, "X-Forwarded-Host")
		if proto == "" && fwdHost == "" {
			proto, fwdHost = forwardedProtoHost(r)
		}
		if proto != "" {
			scheme = strings.ToLower(proto)
		}
		if fwdHost != "" {
			host = fwdHost
		}
		port = lastValue(r, "X-Forwarded-Port")
		prefix = lastValue(r, "X-Forwarded-Prefix")
	case p != nil && hasLinkForwarding(r) && p.warned.CompareAndSwap(false, true):
		// Behind a reverse proxy that is not trusted, every link would name
		// the address the proxy connects to, and installs would fail with
		// nothing in the log saying why.
		peer, _, _ := peerAddr(r)
		p.log.Warn().Str("peer", peer.String()).
			Msg("forwarding header from an untrusted peer ignored for download links; if Jo-ei runs behind a reverse proxy, set server.trusted_proxies or server.public_url")
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

// lastValue returns the last comma-separated entry of header name across all
// its field lines. A proxy that appends leaves whatever the client sent on the
// left, so only the rightmost entry is the trusted proxy's own.
func lastValue(r *http.Request, name string) string {
	values := r.Header.Values(name)
	if len(values) == 0 {
		return ""
	}
	last := values[len(values)-1]
	if i := strings.LastIndexByte(last, ','); i != -1 {
		last = last[i+1:]
	}
	return strings.TrimSpace(last)
}

// hasLinkForwarding reports whether r carries any header Base reads from a
// trusted proxy.
func hasLinkForwarding(r *http.Request) bool {
	for _, h := range []string{"X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Prefix", HeaderForwarded} {
		if len(r.Header.Values(h)) > 0 {
			return true
		}
	}
	return false
}

// forwardedProtoHost reads proto= and host= from the last RFC 7239 Forwarded
// element, the one the trusted proxy appended.
func forwardedProtoHost(r *http.Request) (proto, host string) {
	element := lastValue(r, HeaderForwarded)
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
