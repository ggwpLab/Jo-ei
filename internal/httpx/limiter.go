// Package httpx provides small HTTP transport helpers shared across the proxy.
package httpx

import (
	"net/http"
	"sync"
)

// ConcurrencyLimiter is an http.RoundTripper that caps the number of concurrent
// in-flight requests per destination host. Parallel dependency resolution
// (Gradle, Maven, npm) fans out many simultaneous requests to a single registry;
// left unbounded that burst trips the registry's rate limit, which responds with
// HTTP 429. The cap keeps outbound concurrency under the limit so throttling does
// not happen in the first place.
//
// Requests beyond the cap block until a slot frees or the request's context is
// cancelled. A single limiter is meant to be shared by every http.Client that
// talks to upstreams (metadata, transparent proxy, artifact download) so the cap
// is per host across all of them, not per client.
type ConcurrencyLimiter struct {
	base http.RoundTripper
	max  int

	mu    sync.Mutex
	hosts map[string]chan struct{}
}

// NewConcurrencyLimiter wraps base, capping concurrent requests to maxPerHost per
// destination host. A nil base uses http.DefaultTransport; maxPerHost <= 0
// disables limiting (every request passes straight through).
func NewConcurrencyLimiter(base http.RoundTripper, maxPerHost int) *ConcurrencyLimiter {
	if base == nil {
		base = http.DefaultTransport
	}
	return &ConcurrencyLimiter{base: base, max: maxPerHost, hosts: make(map[string]chan struct{})}
}

// sem returns the semaphore channel for host, creating it on first use.
func (l *ConcurrencyLimiter) sem(host string) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.hosts[host]
	if !ok {
		s = make(chan struct{}, l.max)
		l.hosts[host] = s
	}
	return s
}

// RoundTrip acquires a per-host slot (respecting context cancellation), runs the
// request, then releases the slot.
func (l *ConcurrencyLimiter) RoundTrip(req *http.Request) (*http.Response, error) {
	if l.max <= 0 {
		return l.base.RoundTrip(req)
	}
	sem := l.sem(req.URL.Host)
	select {
	case sem <- struct{}{}:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	defer func() { <-sem }()
	return l.base.RoundTrip(req)
}
