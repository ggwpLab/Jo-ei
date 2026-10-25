package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func idleClient(idle time.Duration) *http.Client {
	return &http.Client{Transport: NewIdleTimeout(http.DefaultTransport.(*http.Transport).Clone(), idle)}
}

func TestIdleTimeout_NoHeadersAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(300 * time.Millisecond):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	resp, err := idleClient(100 * time.Millisecond).Get(srv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestIdleTimeout_StalledBodyAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("x"))
		w.(http.Flusher).Flush()
		select {
		case <-time.After(300 * time.Millisecond):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	resp, err := idleClient(100 * time.Millisecond).Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestIdleTimeout_SlowSteadyBodySucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 10; i++ {
			_, _ = w.Write([]byte("chunk"))
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer srv.Close()

	resp, err := idleClient(150 * time.Millisecond).Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, strings.Repeat("chunk", 10), string(body))
}

func TestIdleTimeout_ParentCancelAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := idleClient(10 * time.Second).Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "got %v", err)
	assert.Less(t, time.Since(start), time.Second)
}

// ctxRecorder captures the context each request was sent with.
type ctxRecorder struct {
	next http.RoundTripper
	ctx  context.Context
}

func (c *ctxRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	c.ctx = req.Context()
	return c.next.RoundTrip(req)
}

func TestIdleTimeout_CloseReleasesContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("done"))
	}))
	defer srv.Close()
	rec := &ctxRecorder{next: http.DefaultTransport.(*http.Transport).Clone()}
	client := &http.Client{Transport: NewIdleTimeout(rec, 50*time.Millisecond)}

	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	time.Sleep(150 * time.Millisecond)

	// Close released the request context with a plain cancel; had the idle
	// timer still fired, the cause would be the deadline error.
	cause := context.Cause(rec.ctx)
	assert.ErrorIs(t, cause, context.Canceled)
	assert.NotErrorIs(t, cause, context.DeadlineExceeded)
}
