package httpx

import (
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AdaptiveBackoff is an http.RoundTripper that reacts to upstream throttling
// (HTTP 429/503) with a per-host cooldown shared across all in-flight requests,
// then retries. When one request is throttled, every other request to that host
// waits out the cooldown instead of continuing to hammer the upstream during its
// penalty window — which is what stops a single 429 from cascading into a storm
// of failures. The cooldown honors Retry-After when present, otherwise grows
// exponentially with consecutive throttles; it resets on the first success.
//
// Only idempotent requests (GET/HEAD, or those with a replayable body) are
// retried; others return the throttled response after recording the cooldown.
type AdaptiveBackoff struct {
	base       http.RoundTripper
	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration

	mu    sync.Mutex
	hosts map[string]*hostThrottle
	now   func() time.Time // overridable in tests
}

type hostThrottle struct {
	until time.Time // requests to this host wait until here
	fails int       // consecutive throttles, for exponential backoff
}

// NewAdaptiveBackoff wraps base. maxRetries bounds retries per request; baseDelay
// and maxDelay bound the exponential cooldown used when no Retry-After is given.
// A nil base uses http.DefaultTransport.
func NewAdaptiveBackoff(base http.RoundTripper, maxRetries int, baseDelay, maxDelay time.Duration) *AdaptiveBackoff {
	if base == nil {
		base = http.DefaultTransport
	}
	return &AdaptiveBackoff{
		base:       base,
		maxRetries: maxRetries,
		baseDelay:  baseDelay,
		maxDelay:   maxDelay,
		hosts:      make(map[string]*hostThrottle),
		now:        time.Now,
	}
}

// RoundTrip waits out any active cooldown for the request's host, sends the
// request, and on a 429/503 records a cooldown and retries (idempotent requests
// only) up to maxRetries.
func (a *AdaptiveBackoff) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	for attempt := 0; ; attempt++ {
		if wait := a.cooldown(host); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			}
		}

		resp, err := a.base.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
			a.onSuccess(host)
			return resp, nil
		}

		a.onThrottle(host, resp.Header.Get("Retry-After"))
		if attempt >= a.maxRetries || !retriable(req) {
			return resp, nil
		}
		drainClose(resp.Body)
	}
}

// cooldown returns how long the host is still throttled for, or 0.
func (a *AdaptiveBackoff) cooldown(host string) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	ht := a.hosts[host]
	if ht == nil {
		return 0
	}
	if d := ht.until.Sub(a.now()); d > 0 {
		return d
	}
	return 0
}

// onThrottle extends the host cooldown after a 429/503, honoring Retry-After or
// falling back to jittered exponential backoff.
func (a *AdaptiveBackoff) onThrottle(host, retryAfter string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ht := a.hosts[host]
	if ht == nil {
		ht = &hostThrottle{}
		a.hosts[host] = ht
	}
	ht.fails++

	var delay time.Duration
	if d, ok := parseRetryAfter(retryAfter, a.now()); ok {
		delay = d + a.jitter()
	} else {
		shift := min(ht.fails-1, 16) // guard against overflow on pathological streaks
		delay = a.baseDelay<<shift + a.jitter()
	}
	if delay > a.maxDelay {
		delay = a.maxDelay
	}
	if until := a.now().Add(delay); until.After(ht.until) {
		ht.until = until
	}
}

// onSuccess clears the consecutive-failure count for the host.
func (a *AdaptiveBackoff) onSuccess(host string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ht := a.hosts[host]; ht != nil {
		ht.fails = 0
	}
}

// jitter returns a small random duration in [0, baseDelay] to de-synchronize
// retries that wake from the same cooldown.
func (a *AdaptiveBackoff) jitter() time.Duration {
	if a.baseDelay <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(a.baseDelay) + 1))
}

// retriable reports whether req may be safely re-sent: an idempotent method with
// no body, or a body that can be replayed.
func retriable(req *http.Request) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}
	return req.Body == nil || req.GetBody != nil
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

// drainClose drains a bounded amount of the body then closes it, so the
// underlying connection can be reused on the retry.
func drainClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
	_ = body.Close()
}
