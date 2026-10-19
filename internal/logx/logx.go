// Package logx holds the logging conventions shared by every Jōei component,
// so a log line reads the same whichever subsystem wrote it.
//
// Every request gets one ID, minted by Middleware at the edge of the server.
// It reaches the client as the X-Request-Id header, the request's log lines as
// the request_id field, JSON error bodies and the console request feed — so
// one ID ties together everything a single request left behind.
//
// Field vocabulary (use these names, never synonyms):
//
//	component        subsystem that wrote the line: server, proxy,
//	                 metadata_filter, docker, console, telemetry, auth
//	request_id       the request's ID (via Logger, never set by hand)
//	ecosystem        pypi | npm | maven | rubygems | go | docker
//	package          package name (Docker: the repository)
//	version          package version (Docker: tag or digest as requested)
//	classifier       Maven classifier, when present
//	digest           Docker content digest
//	path             request path, for requests that name no package
//	verdict, gate,   outcome of a gated request (see Outcome)
//	reason, status,
//	duration_ms
//	upstream_attempts  per-mirror attempt list (upstream.Attempts)
//	error            the error (zerolog's Err)
//
// Messages are short lowercase phrases without a subsystem prefix; the
// component field carries the subsystem.
package logx

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// HeaderRequestID is the response header that carries the request ID.
const HeaderRequestID = "X-Request-Id"

// MsgOutcome is the message of the single line each gated request ends with.
const MsgOutcome = "request gated"

type requestIDKey struct{}

// WithRequestID returns ctx carrying id as the request ID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the request ID carried by ctx, or "" when there is none.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// Ensure returns r carrying a request ID, minting one when r has none, and
// that ID. Handlers call it so they work the same mounted behind Middleware or
// used directly.
func Ensure(r *http.Request) (*http.Request, string) {
	if id := RequestID(r.Context()); id != "" {
		return r, id
	}
	id := uuid.New().String()
	return r.WithContext(WithRequestID(r.Context(), id)), id
}

// Middleware gives every request an ID and returns it in the X-Request-Id
// response header.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, id := Ensure(r)
		w.Header().Set(HeaderRequestID, id)
		next.ServeHTTP(w, r)
	})
}

// Logger returns base with the request_id field of ctx's request, or base
// unchanged outside a request.
func Logger(ctx context.Context, base zerolog.Logger) zerolog.Logger {
	if id := RequestID(ctx); id != "" {
		return base.With().Str("request_id", id).Logger()
	}
	return base
}

// Outcome writes the one line a gated request ends with, mirroring the
// telemetry event it records. log must already carry the request's identity
// fields (request_id, ecosystem, package, version). PASS and CACHE log at info,
// BLOCK and client-side errors (4xx) at warn, other errors at error.
func Outcome(log zerolog.Logger, ev gate.Event) {
	var e *zerolog.Event
	switch {
	case ev.Verdict == gate.VerdictBlock:
		e = log.Warn()
	case ev.Verdict == gate.VerdictError && ev.HTTPStatus < 500:
		e = log.Warn()
	case ev.Verdict == gate.VerdictError:
		e = log.Error()
	default:
		e = log.Info()
	}
	e = e.Str("verdict", ev.Verdict).Str("gate", ev.Gate).Str("reason", ev.Reason).
		Int("status", ev.HTTPStatus).Int64("duration_ms", ev.LatencyMS)
	if len(ev.BlockedBy) > 0 {
		e = e.Strs("blocked_by", ev.BlockedBy)
	}
	if len(ev.CVEs) > 0 {
		ids := make([]string, len(ev.CVEs))
		for i, f := range ev.CVEs {
			ids[i] = f.ID
		}
		e = e.Strs("cves", ids)
	}
	if ev.MalwareEngine != "" {
		e = e.Str("engine", ev.MalwareEngine)
	}
	if ev.MalwareSignature != "" {
		e = e.Str("signature", ev.MalwareSignature)
	}
	e = timeIfSet(e, "published_at", ev.PublishedAt)
	e = timeIfSet(e, "block_until", ev.BlockUntil)
	e.Msg(MsgOutcome)
}

func timeIfSet(e *zerolog.Event, key string, t time.Time) *zerolog.Event {
	if t.IsZero() {
		return e
	}
	return e.Time(key, t)
}
