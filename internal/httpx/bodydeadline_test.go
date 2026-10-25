package httpx

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawRequest opens a TCP connection to srv and sends a request head that
// announces a body of length bodyLen, plus the first part of that body.
func rawRequest(t *testing.T, srv *httptest.Server, bodyLen int, firstPart string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	_, err = fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", bodyLen, firstPart)
	require.NoError(t, err)
	return conn
}

// A client that sends its headers and then trickles nothing must not hold the
// handler on the body read forever.
func TestBodyReadDeadline_StalledBodyFails(t *testing.T) {
	readErr := make(chan error, 1)
	srv := httptest.NewServer(BodyReadDeadline(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		readErr <- err
	}), 150*time.Millisecond))
	defer srv.Close()

	rawRequest(t, srv, 10, "a")

	select {
	case err := <-readErr:
		assert.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("body read did not time out")
	}
}

// Once the body is read, the deadline must be gone: a gated request keeps
// working for minutes after it has its body, and an expired read deadline
// would cancel its context through the server's background read.
func TestBodyReadDeadline_ClearedAfterBody(t *testing.T) {
	ctxErr := make(chan error, 1)
	srv := httptest.NewServer(BodyReadDeadline(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			ctxErr <- err
			return
		}
		time.Sleep(400 * time.Millisecond) // well past the 150 ms idle
		ctxErr <- r.Context().Err()
		_, _ = io.WriteString(w, "ok")
	}), 150*time.Millisecond))
	defer srv.Close()

	resp, err := http.Post(srv.URL, "text/plain", strings.NewReader("hello"))
	require.NoError(t, err)
	resp.Body.Close()

	assert.NoError(t, <-ctxErr)
}

// A body that keeps arriving, however slowly, is progress.
func TestBodyReadDeadline_SlowSteadyBodySucceeds(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(BodyReadDeadline(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}), 150*time.Millisecond))
	defer srv.Close()

	conn := rawRequest(t, srv, 5, "")
	for _, c := range "abcde" {
		time.Sleep(80 * time.Millisecond)
		_, err := conn.Write([]byte(string(c)))
		require.NoError(t, err)
	}

	select {
	case body := <-got:
		assert.Equal(t, "abcde", body)
	case <-time.After(2 * time.Second):
		t.Fatal("handler never finished reading")
	}
}
