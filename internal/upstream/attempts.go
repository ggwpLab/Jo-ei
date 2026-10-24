// Package upstream records one entry per attempted upstream mirror so a fetch
// that failed across every mirror can be logged with each mirror's own error.
// Retry loops used to keep a single lastErr variable, which meant a mirror's
// TLS or DNS failure was silently replaced by the next mirror's plain 404.
package upstream

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
)

// Attempt is one mirror's outcome. Status is the upstream HTTP status, or 0
// when the request never produced a response at all (TLS verification, DNS,
// connection refused, timeout, an open circuit breaker). That distinction is
// the reason this type exists: a 0 and a 404 mean very different things to an
// operator, and collapsing them hides misconfigured mirrors.
type Attempt struct {
	URL      string
	Status   int
	Err      error
	Duration time.Duration
}

// Attempts is the ordered list of mirror outcomes for one logical fetch. It
// implements error, so a retry loop can return it directly, and
// zerolog.LogArrayMarshaler, so a log site can render every attempt as one
// structured array field.
type Attempts []Attempt

// Add appends one outcome. Credentials embedded in rawURL are stripped from
// the resulting URL field only. err's own text is not sanitised: it is the
// caller's responsibility. In practice net/http masks a *url.Error's password
// but leaves the username, and http.NewRequestWithContext on a malformed URL
// returns the raw URL unmasked.
func (a *Attempts) Add(rawURL string, status int, err error, d time.Duration) {
	*a = append(*a, Attempt{
		URL:      SanitizeURL(rawURL),
		Status:   status,
		Err:      err,
		Duration: d,
	})
}

// Error renders every attempt, so the flat message of a wrapped error still
// carries all mirrors even where the structured array is unavailable.
func (a Attempts) Error() string {
	if len(a) == 0 {
		return "no upstream attempts were made"
	}
	parts := make([]string, 0, len(a))
	for _, at := range a {
		msg := "unknown error"
		if at.Err != nil {
			msg = at.Err.Error()
		}
		parts = append(parts, at.URL+": "+msg)
	}
	return fmt.Sprintf("all %d upstreams failed: %s", len(a), strings.Join(parts, "; "))
}

// Unwrap exposes the individual errors to errors.Is / errors.As.
func (a Attempts) Unwrap() []error {
	errs := make([]error, 0, len(a))
	for _, at := range a {
		if at.Err != nil {
			errs = append(errs, at.Err)
		}
	}
	return errs
}

// AllNotFound reports whether every mirror answered 404 or 410 — the condition
// under which the proxy returns 404 rather than 502. An empty list is false:
// nothing was tried, so nothing proved the artifact absent.
func (a Attempts) AllNotFound() bool {
	if len(a) == 0 {
		return false
	}
	for _, at := range a {
		if at.Status != http.StatusNotFound && at.Status != http.StatusGone {
			return false
		}
	}
	return true
}

// ThrottleLookup reports whether an upstream host is in a post-throttle
// cooldown: the status that opened it (429 or 503) and the time left on it.
// *httpx.CircuitBreaker implements it; host is in URL.Host form.
type ThrottleLookup interface {
	Throttle(host string) (status int, retryIn time.Duration, ok bool)
}

// Throttled reports whether the fetch failed only because some mirror was
// throttling us: every attempt answered 404/410 or was throttled (an upstream
// 429/503, or a circuit-breaker fast-fail), and at least one was throttled.
// Such a failure is not proof of absence (the throttled mirror may have the
// artifact) and not an outage either, so the proxy answers with the throttle
// status instead of 404 or 502. status is 429 when any throttle was a 429,
// else 503; a fast-failed mirror takes the status that opened its circuit
// (429 when t is nil or does not know the host). retryAfter is the shortest
// cooldown t reports among the throttled hosts, 0 when it knows none.
func (a Attempts) Throttled(t ThrottleLookup) (status int, retryAfter time.Duration, ok bool) {
	for _, at := range a {
		s := at.Status
		switch {
		case s == http.StatusNotFound || s == http.StatusGone:
			continue
		case s == http.StatusTooManyRequests || s == http.StatusServiceUnavailable:
		case s == 0 && errors.Is(at.Err, httpx.ErrCircuitOpen):
			s = http.StatusTooManyRequests
		default:
			return 0, 0, false
		}
		if t != nil {
			if u, err := url.Parse(at.URL); err == nil {
				if ts, in, known := t.Throttle(u.Host); known {
					if at.Status == 0 {
						s = ts
					}
					if in > 0 && (retryAfter == 0 || in < retryAfter) {
						retryAfter = in
					}
				}
			}
		}
		if status != http.StatusTooManyRequests {
			status = s
		}
		ok = true
	}
	if !ok {
		return 0, 0, false
	}
	return status, retryAfter, true
}

// MarshalZerologArray renders the attempts as an array of objects.
func (a Attempts) MarshalZerologArray(arr *zerolog.Array) {
	for _, at := range a {
		d := zerolog.Dict().
			Str("url", at.URL).
			Int("status", at.Status).
			Int64("ms", at.Duration.Milliseconds())
		if at.Err != nil {
			d = d.Str("error", at.Err.Error())
		}
		arr.Dict(d)
	}
}

// AttemptsFrom recovers the attempts from err, including when err wraps them.
// Log sites use it to attach the structured array to an error they did not
// produce themselves.
func AttemptsFrom(err error) (Attempts, bool) {
	var a Attempts
	if errors.As(err, &a) {
		return a, true
	}
	return nil, false
}

// SanitizeURL removes any userinfo component. An unparseable URL is returned
// unchanged: it came from configuration, and hiding it entirely would be worse
// than logging it verbatim.
func SanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}
