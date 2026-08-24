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

// Add appends one outcome. Credentials embedded in rawURL are stripped so they
// never reach the log.
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
