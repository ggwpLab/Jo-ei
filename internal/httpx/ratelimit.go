package httpx

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter is an http.RoundTripper that caps the request *rate* to each
// destination host using a token bucket. A concurrency cap alone does not bound
// rate — a few fast workers can still emit hundreds of requests per second — and
// registries such as Maven Central throttle by rate, so this is what actually
// prevents HTTP 429 under sustained load. Requests block until a token is
// available or the request's context is cancelled.
type RateLimiter struct {
	base  http.RoundTripper
	rate  float64 // tokens (requests) per second, per host
	burst float64 // maximum token accumulation (allowed short burst)

	mu      sync.Mutex
	buckets map[string]*tokenBucket
	now     func() time.Time // overridable in tests
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter wraps base, limiting requests to perSecond per destination host
// with the given burst (clamped to >= 1). A nil base uses http.DefaultTransport;
// perSecond <= 0 disables limiting (every request passes straight through).
func NewRateLimiter(base http.RoundTripper, perSecond float64, burst int) *RateLimiter {
	if base == nil {
		base = http.DefaultTransport
	}
	b := float64(burst)
	if b < 1 {
		b = 1
	}
	return &RateLimiter{
		base:    base,
		rate:    perSecond,
		burst:   b,
		buckets: make(map[string]*tokenBucket),
		now:     time.Now,
	}
}

// reserve consumes one token for host and returns how long to wait before it is
// available. Tokens may go negative: each caller reserves a distinct slot, so
// concurrent callers wait staggered amounts rather than waking together.
func (l *RateLimiter) reserve(host string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[host]
	if !ok {
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[host] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	b.tokens--
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / l.rate * float64(time.Second))
}

// RoundTrip waits for a per-host token (respecting context cancellation), then
// runs the request.
func (l *RateLimiter) RoundTrip(req *http.Request) (*http.Response, error) {
	if l.rate <= 0 {
		return l.base.RoundTrip(req)
	}
	if wait := l.reserve(req.URL.Host); wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-t.C:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	return l.base.RoundTrip(req)
}
