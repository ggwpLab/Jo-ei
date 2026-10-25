package httpx

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyWithWriteDeadline_CopiesAll(t *testing.T) {
	src := bytes.Repeat([]byte("j"), 1<<20+7)
	rec := httptest.NewRecorder()

	n, err := CopyWithWriteDeadline(rec, bytes.NewReader(src), time.Second)

	require.NoError(t, err)
	assert.Equal(t, int64(len(src)), n)
	assert.Equal(t, src, rec.Body.Bytes())
}

// deadlineWriter is a ResponseWriter whose write deadlines are recorded, as
// http.ResponseController finds them through SetWriteDeadline.
type deadlineWriter struct {
	httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineWriter) SetWriteDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

func TestCopyWithWriteDeadline_ArmsDeadlinePerChunk(t *testing.T) {
	w := &deadlineWriter{ResponseRecorder: *httptest.NewRecorder()}
	src := bytes.Repeat([]byte("j"), 600<<10)
	start := time.Now()

	_, err := CopyWithWriteDeadline(w, bytes.NewReader(src), 5*time.Second)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(w.deadlines), 4, "three 256 KiB chunks armed, then cleared")
	armed, last := w.deadlines[:len(w.deadlines)-1], w.deadlines[len(w.deadlines)-1]
	for _, d := range armed {
		assert.False(t, d.Before(start), "deadline in the past")
		assert.False(t, d.After(time.Now().Add(5*time.Second)), "deadline beyond idle")
	}
	assert.True(t, last.IsZero(), "deadline cleared on return")
	assert.Equal(t, src, w.Body.Bytes())
}

var _ http.ResponseWriter = (*deadlineWriter)(nil)

// firstWrite signals when the first bytes reach the client.
type firstWrite struct {
	httptest.ResponseRecorder
	got chan []byte
}

func (f *firstWrite) Write(p []byte) (int, error) {
	select {
	case f.got <- append([]byte(nil), p...):
	default:
	}
	return len(p), nil
}

// SetWriteDeadline puts firstWrite on the deadline-armed path.
func (f *firstWrite) SetWriteDeadline(time.Time) error { return nil }

// A streamed upstream response must reach the client as it arrives, not once a
// whole chunk has accumulated: a slow mirror would otherwise starve a client
// with a short read timeout.
func TestCopyWithWriteDeadline_ForwardsPartialReadsAtOnce(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	w := &firstWrite{ResponseRecorder: *httptest.NewRecorder(), got: make(chan []byte, 1)}
	go func() { _, _ = CopyWithWriteDeadline(w, pr, time.Second) }()

	_, err := pw.Write([]byte("first bytes"))
	require.NoError(t, err)

	select {
	case got := <-w.got:
		assert.Equal(t, "first bytes", string(got))
	case <-time.After(time.Second):
		t.Fatal("partial read was held back instead of forwarded")
	}
}
