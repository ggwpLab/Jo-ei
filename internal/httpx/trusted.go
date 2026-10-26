package httpx

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedPeers is the set of reverse proxies whose forwarding headers are
// believed. A peer outside it can forge any forwarding header, so every
// resolver that reads one consults this set first.
type TrustedPeers []netip.Prefix

// ParseTrustedPeers parses server.trusted_proxies entries: CIDRs or bare IPs.
func ParseTrustedPeers(entries []string) (TrustedPeers, error) {
	peers := make(TrustedPeers, 0, len(entries))
	for i, entry := range entries {
		p, err := parseTrusted(entry)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy [%d]: %w", i, err)
		}
		peers = append(peers, p)
	}
	return peers, nil
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

// Contains reports whether a is a trusted proxy address.
func (t TrustedPeers) Contains(a netip.Addr) bool {
	for _, p := range t {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// peerAddr parses the direct peer of r. ok is false when RemoteAddr is not an
// IP, in which case raw is what RemoteAddr held.
func peerAddr(r *http.Request) (addr netip.Addr, raw string, ok bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, host, false
	}
	return a.Unmap(), host, true
}

// PeerTrusted reports whether r arrived directly from a trusted proxy.
func (t TrustedPeers) PeerTrusted(r *http.Request) bool {
	a, _, ok := peerAddr(r)
	return ok && t.Contains(a)
}
