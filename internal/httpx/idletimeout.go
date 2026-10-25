package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultUpstreamIdleTimeout is how long an upstream may stay silent — no
// response headers, or no body bytes — before the request is aborted.
const DefaultUpstreamIdleTimeout = 60 * time.Second

// IdleTimeout is an http.RoundTripper that aborts a request when it stops
// making progress, instead of capping its total duration: a multi-GB artifact
// arriving steadily over minutes succeeds, a stalled one fails after idle.
// Progress is the response headers arriving, then every body read that
// returns bytes. The request context is derived from the caller's, so caller
// cancellation still aborts the request.
type IdleTimeout struct {
	next http.RoundTripper
	idle time.Duration
}

// NewIdleTimeout wraps next with an idle timeout. Place it inside any
// queueing round-trippers (rate and concurrency limits) so time spent waiting
// for a slot does not count as upstream silence.
func NewIdleTimeout(next http.RoundTripper, idle time.Duration) *IdleTimeout {
	return &IdleTimeout{next: next, idle: idle}
}

// RoundTrip implements http.RoundTripper.
func (t *IdleTimeout) RoundTrip(req *http.Request) (*http.Response, error) {
	errIdle := fmt.Errorf("upstream idle for %s: %w", t.idle, context.DeadlineExceeded)
	ctx, cancel := context.WithCancelCause(req.Context())
	timer := time.AfterFunc(t.idle, func() { cancel(errIdle) })

	resp, err := t.next.RoundTrip(req.WithContext(ctx))
	if err != nil {
		timer.Stop()
		idled := context.Cause(ctx) == errIdle
		cancel(nil)
		if idled {
			return nil, errIdle
		}
		return nil, err
	}
	timer.Reset(t.idle)
	resp.Body = &idleBody{rc: resp.Body, timer: timer, idle: t.idle, ctx: ctx, cancel: cancel, errIdle: errIdle}
	return resp, nil
}

// idleBody re-arms the idle timer on every read that makes progress and
// releases the timer and the derived context on close.
type idleBody struct {
	rc      io.ReadCloser
	timer   *time.Timer
	idle    time.Duration
	ctx     context.Context
	cancel  context.CancelCauseFunc
	errIdle error
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.timer.Reset(b.idle)
	}
	switch {
	case err == io.EOF:
		b.timer.Stop()
	case err != nil && context.Cause(b.ctx) == b.errIdle:
		return n, b.errIdle
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	err := b.rc.Close()
	b.cancel(nil)
	return err
}
