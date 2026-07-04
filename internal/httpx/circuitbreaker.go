package httpx

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrCircuitOpen is returned (wrapped) when a request is fast-failed because the
// destination host is in its post-throttle cooldown.
var ErrCircuitOpen = errors.New("upstream throttled: circuit open")

// CircuitBreaker is an http.RoundTripper that fast-fails requests to a host that
// recently returned HTTP 429/503 instead of retrying it. Retrying a throttled
// upstream "harder" only deepens the penalty (per Sonatype's Maven Central
// guidance), so on a 429/503 the breaker opens for a cooldown — honoring
// Retry-After, else jittered exponential backoff — during which every request to
// that host fails immediately with ErrCircuitOpen. The handler's multi-upstream
// fallback then serves from a mirror right away instead of waiting on or
// hammering the throttled host. The breaker closes on the first success after
// the cooldown.
//
// It performs no retries and never blocks, so it does not consume the caller's
// request timeout while a host is throttled.
type CircuitBreaker struct {
	base      http.RoundTripper
	baseDelay time.Duration
	maxDelay  time.Duration

	mu    sync.Mutex
	hosts map[string]*breakerState
	now   func() time.Time // overridable in tests
}

type breakerState struct {
	openUntil time.Time
	fails     int // consecutive throttles, for exponential cooldown growth
}

// NewCircuitBreaker wraps base. baseDelay and maxDelay bound the exponential
// cooldown used when an upstream sends no Retry-After. A nil base uses
// http.DefaultTransport.
func NewCircuitBreaker(base http.RoundTripper, baseDelay, maxDelay time.Duration) *CircuitBreaker {
	if base == nil {
		base = http.DefaultTransport
	}
	return &CircuitBreaker{
		base:      base,
		baseDelay: baseDelay,
		maxDelay:  maxDelay,
		hosts:     make(map[string]*breakerState),
		now:       time.Now,
	}
}

// RoundTrip fast-fails when the host's circuit is open; otherwise it sends the
// request, opening the circuit on a 429/503 and resetting it on success.
func (c *CircuitBreaker) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	if c.isOpen(host) {
		return nil, fmt.Errorf("%s: %w", host, ErrCircuitOpen)
	}
	resp, err := c.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		c.trip(host, resp.Header.Get("Retry-After"))
		return resp, nil
	}
	c.reset(host)
	return resp, nil
}

func (c *CircuitBreaker) isOpen(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.hosts[host]
	return st != nil && c.now().Before(st.openUntil)
}

// trip opens (or extends) the host circuit after a 429/503.
func (c *CircuitBreaker) trip(host, retryAfter string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.hosts[host]
	if st == nil {
		st = &breakerState{}
		c.hosts[host] = st
	}
	st.fails++

	var delay time.Duration
	if d, ok := parseRetryAfter(retryAfter, c.now()); ok {
		delay = d + c.jitter()
	} else {
		shift := min(st.fails-1, 16) // guard against overflow on pathological streaks
		delay = c.baseDelay<<shift + c.jitter()
	}
	if delay > c.maxDelay {
		delay = c.maxDelay
	}
	if until := c.now().Add(delay); until.After(st.openUntil) {
		st.openUntil = until
	}
}

// reset closes the host circuit after a success.
func (c *CircuitBreaker) reset(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st := c.hosts[host]; st != nil {
		st.fails = 0
		st.openUntil = time.Time{}
	}
}

// jitter returns a random duration in [0, baseDelay] so probes after a shared
// cooldown do not re-synchronize.
func (c *CircuitBreaker) jitter() time.Duration {
	if c.baseDelay <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(c.baseDelay) + 1)) // #nosec G404 -- retry jitter, not cryptographic
}

// parseRetryAfter parses a Retry-After header (delta-seconds or HTTP-date)
// relative to now. ok is false when absent or unparseable.
func parseRetryAfter(header string, now time.Time) (time.Duration, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(header); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(header); err == nil {
		if d := t.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}
