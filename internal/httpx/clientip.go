package httpx

import (
	"fmt"
	"net"
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
	trusted []netip.Prefix
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
	prefixes := make([]netip.Prefix, 0, len(trusted))
	for i, entry := range trusted {
		p, err := parseTrusted(entry)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy [%d]: %w", i, err)
		}
		prefixes = append(prefixes, p)
	}
	return &ClientIPResolver{trusted: prefixes, header: header, log: log}, nil
}

func parseTrusted(entry string) (netip.Prefix, error) {
	entry = strings.TrimSpace(entry)
	if strings.Contains(entry, "/") {
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func (c *ClientIPResolver) isTrusted(a netip.Addr) bool {
	for _, p := range c.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP returns the client IP (no port) for r.
func (c *ClientIPResolver) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()

	if !c.isTrusted(peer) {
		if c.hasForwardingHeader(r) && c.warned.CompareAndSwap(false, true) {
			c.log.Warn().Str("peer", peer.String()).
				Msg("forwarding header from an untrusted peer ignored; if Jo-ei runs behind a reverse proxy, set server.trusted_proxies")
		}
		return peer.String()
	}

	hops, ok := c.hops(r)
	if !ok || len(hops) == 0 {
		return peer.String()
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !c.isTrusted(hops[i]) {
			return hops[i].String()
		}
	}
	return hops[0].String()
}

func (c *ClientIPResolver) hasForwardingHeader(r *http.Request) bool {
	for _, h := range []string{HeaderXForwardedFor, HeaderXRealIP, HeaderForwarded} {
		if len(r.Header.Values(h)) > 0 {
			return true
		}
	}
	return false
}

// hops returns the addresses named by the configured header, left to right.
// ok is false when the header is absent or any entry is malformed.
func (c *ClientIPResolver) hops(r *http.Request) ([]netip.Addr, bool) {
	values := r.Header.Values(c.header)
	if len(values) == 0 {
		return nil, false
	}
	var raw []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if c.header == HeaderForwarded {
				part = forwardedFor(part)
			}
			if part == "" {
				if c.header == HeaderForwarded {
					continue // element without a for= parameter
				}
				return nil, false
			}
			raw = append(raw, part)
		}
	}
	if c.header == HeaderXRealIP && len(raw) != 1 {
		return nil, false
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		a, ok := parseHop(s)
		if !ok {
			return nil, false
		}
		out = append(out, a)
	}
	return out, true
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
