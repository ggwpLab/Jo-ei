package httpx

import (
	"io"
	"net/http"
	"sync"
	"time"
)

// DefaultBodyReadIdleTimeout is how long a request body may go without a byte
// before reading it fails.
const DefaultBodyReadIdleTimeout = 60 * time.Second

// BodyReadDeadline bounds how slowly a client may send a request body, the job
// a server-wide ReadTimeout would do if it did not also cancel long-running
// handlers. For a request with a body, a read deadline of idle is armed and
// re-armed on every read that makes progress; it is cleared as soon as the
// body hits EOF, so the server's background read (which starts at EOF) never
// inherits it. A body abandoned before EOF keeps its deadline, which also
// bounds the server's own drain of the remainder after the handler returns.
// Requests without a body pass straight through.
func BodyReadDeadline(next http.Handler, idle time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		rc := http.NewResponseController(w)
		if rc.SetReadDeadline(time.Now().Add(idle)) != nil {
			next.ServeHTTP(w, r) // no deadline support: nothing to bound with
			return
		}
		r.Body = &deadlineBody{rc: r.Body, ctl: rc, idle: idle}
		next.ServeHTTP(w, r)
	})
}

// deadlineBody re-arms the connection's read deadline while the body makes
// progress and clears it at EOF.
type deadlineBody struct {
	rc   io.ReadCloser
	ctl  *http.ResponseController
	idle time.Duration
	eof  sync.Once
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	switch {
	case err == io.EOF:
		b.eof.Do(func() { _ = b.ctl.SetReadDeadline(time.Time{}) })
	case err == nil && n > 0:
		_ = b.ctl.SetReadDeadline(time.Now().Add(b.idle))
	}
	return n, err
}

func (b *deadlineBody) Close() error { return b.rc.Close() }
