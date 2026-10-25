package httpx

import (
	"errors"
	"io"
	"net/http"
	"time"
)

// DefaultWriteIdleTimeout bounds how long one chunk written to a client may
// take, so a client that stops reading cannot pin a serving goroutine forever.
const DefaultWriteIdleTimeout = 60 * time.Second

// copyChunk is the unit each write deadline covers.
const copyChunk = 256 << 10

// CopyWithWriteDeadline copies src to w in chunks of up to 256 KiB, arming a write
// deadline of idle before each chunk, so a transfer is bounded by progress
// rather than total time: a multi-GB artifact to a slow but reading client
// succeeds, a stalled client is dropped after idle. A writer without deadline
// support is copied without them. The deadline is cleared on return.
func CopyWithWriteDeadline(w http.ResponseWriter, src io.Reader, idle time.Duration) (int64, error) {
	rc := http.NewResponseController(w)
	arm := func(t time.Time) bool {
		return !errors.Is(rc.SetWriteDeadline(t), http.ErrNotSupported)
	}
	if !arm(time.Now().Add(idle)) {
		return io.Copy(w, src)
	}
	defer arm(time.Time{})

	buf := make([]byte, copyChunk)
	var written int64
	for {
		// One Read per chunk, not ReadFull: a streamed response must reach
		// the client as it arrives rather than once a whole chunk piles up.
		n, rerr := src.Read(buf)
		if n > 0 {
			arm(time.Now().Add(idle))
			m, werr := w.Write(buf[:n])
			written += int64(m)
			if werr != nil {
				return written, werr
			}
		}
		switch {
		case rerr == io.EOF:
			return written, nil
		case rerr != nil:
			return written, rerr
		}
	}
}
