package httpx

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/rs/zerolog"
)

// Forwarding headers a trusted reverse proxy may use to convey the client IP.
const (
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"
	HeaderForwarded     = "Forwarded"
)

// ClientIPResolver determines the originating client IP of a request. The
// forwarding header is honoured only when the direct peer is a trusted proxy;
// otherwise the header is attacker-controlled and the peer address is used.
type ClientIPResolver struct {
	trusted TrustedPeers
	header  string
	log     zerolog.Logger
	warned  atomic.Bool
}

// NewClientIPResolver builds a resolver. trusted entries are CIDRs or bare IPs;
// header is one of the Header* constants (empty selects X-Forwarded-For).
func NewClientIPResolver(trusted []string, header string, log zerolog.Logger) (*ClientIPResolver, error) {
	switch {
	case header == "":
		header = HeaderXForwardedFor
	case strings.EqualFold(header, HeaderXForwardedFor):
		header = HeaderXForwardedFor
	case strings.EqualFold(header, HeaderXRealIP):
		header = HeaderXRealIP
	case strings.EqualFold(header, HeaderForwarded):
		header = HeaderForwarded
	default:
		return nil, fmt.Errorf("unsupported client IP header %q (want %s|%s|%s)",
			header, HeaderXForwardedFor, HeaderXRealIP, HeaderForwarded)
	}
	peers, err := ParseTrustedPeers(trusted)
	if err != nil {
		return nil, err
	}
	return &ClientIPResolver{trusted: peers, header: header, log: log}, nil
}

// ClientIP returns the client IP (no port) for r.
func (c *ClientIPResolver) ClientIP(r *http.Request) string {
	peer, raw, ok := peerAddr(r)
	if !ok {
		return raw
	}

	if !c.trusted.Contains(peer) {
		if c.hasForwardingHeader(r) && c.warned.CompareAndSwap(false, true) {
			c.log.Warn().Str("peer", peer.String()).
				Msg("forwarding header from an untrusted peer ignored; if Jo-ei runs behind a reverse proxy, set server.trusted_proxies")
		}
		return peer.String()
	}

	// Walk right to left: entries nearer the peer were written by proxies we
	// trust; the first valid untrusted address is the client. Anything to its
	// left is client-supplied and ignored, junk included. A malformed or
	// obfuscated entry met before that address means the chain cannot be
	// trusted, so the peer is used.
	hops, ok := c.hops(r)
	if !ok || len(hops) == 0 {
		return peer.String()
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !hops[i].valid {
			return peer.String()
		}
		if !c.trusted.Contains(hops[i].addr) {
			return hops[i].addr.String()
		}
	}
	return hops[0].addr.String()
}

func (c *ClientIPResolver) hasForwardingHeader(r *http.Request) bool {
	for _, h := range []string{HeaderXForwardedFor, HeaderXRealIP, HeaderForwarded} {
		if len(r.Header.Values(h)) > 0 {
			return true
		}
	}
	return false
}

// hop is one forwarding-header entry; valid is false when it is not an IP
// (malformed, empty, or an RFC 7239 obfuscated identifier like _hidden).
type hop struct {
	addr  netip.Addr
	valid bool
}

// hops returns the entries named by the configured header, left to right.
// ok is false when the header is absent, or for X-Real-IP when it does not
// hold exactly one entry.
func (c *ClientIPResolver) hops(r *http.Request) ([]hop, bool) {
	values := r.Header.Values(c.header)
	if len(values) == 0 {
		return nil, false
	}
	var out []hop
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if c.header == HeaderForwarded {
				if part == "" || !hasForParam(part) {
					continue // element without a for= parameter
				}
				part = forwardedFor(part)
			}
			a, valid := parseHop(part)
			out = append(out, hop{addr: a, valid: valid})
		}
	}
	if c.header == HeaderXRealIP && len(out) != 1 {
		return nil, false
	}
	return out, true
}

// hasForParam reports whether a Forwarded element carries a for= parameter.
func hasForParam(element string) bool {
	for _, param := range strings.Split(element, ";") {
		k, _, found := strings.Cut(strings.TrimSpace(param), "=")
		if found && strings.EqualFold(strings.TrimSpace(k), "for") {
			return true
		}
	}
	return false
}

// forwardedFor extracts the for= value of one RFC 7239 Forwarded element.
func forwardedFor(element string) string {
	for _, param := range strings.Split(element, ";") {
		k, v, found := strings.Cut(strings.TrimSpace(param), "=")
		if found && strings.EqualFold(strings.TrimSpace(k), "for") {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// parseHop accepts an IP optionally wrapped in brackets and/or followed by a port.
func parseHop(s string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if a, err := netip.ParseAddr(s[1 : len(s)-1]); err == nil {
			return a.Unmap(), true
		}
	}
	return netip.Addr{}, false
}
