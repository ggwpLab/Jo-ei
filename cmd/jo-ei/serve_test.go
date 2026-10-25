package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
)

func TestServeListener_ShutsDownOnContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: http.NewServeMux()}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- serveListener(ctx, srv, ln, 5*time.Second, zerolog.Nop()) }()

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("serveListener did not return after context cancel")
	}
}

// A server whose listener is already closed fails at once; serveAll must
// return that error and shut the healthy server down with it.
func TestServeAll_OneFailureStopsOthers(t *testing.T) {
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, lnA.Close())
	srvA := &http.Server{Handler: http.NewServeMux()}

	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srvB := &http.Server{Handler: http.NewServeMux()}
	urlB := "http://" + lnB.Addr().String() + "/"

	done := make(chan error, 1)
	go func() {
		done <- serveAll(context.Background(), boundServer{srvA, lnA, time.Second, zerolog.Nop()}, boundServer{srvB, lnB, time.Second, zerolog.Nop()})
	}()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("serveAll did not return after one server failed")
	}

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(urlB)
	if err == nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "healthy server must be shut down when another fails")
}

func TestServeAll_CtxCancelShutsDownAll(t *testing.T) {
	var servers []boundServer
	for range 2 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		servers = append(servers, boundServer{&http.Server{Handler: http.NewServeMux()}, ln, time.Second, zerolog.Nop()})
	}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- serveAll(ctx, servers...) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("serveAll did not return after context cancel")
	}
	for _, s := range servers {
		_, err := net.DialTimeout("tcp", s.ln.Addr().String(), time.Second)
		require.Error(t, err, "listener %s still accepting", s.ln.Addr())
	}
}

func TestBindServers_MainServerTimeouts(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Listen = "127.0.0.1:0"
	a := &app{}
	defer a.close()

	servers, err := bindServers(a, cfg, http.NewServeMux(), nil, zerolog.Nop())
	require.NoError(t, err)
	require.Len(t, servers, 1)

	srv := servers[0].srv
	// ReadTimeout would also cancel a running handler's context once it
	// expires, and WriteTimeout would cut long gated downloads.
	assert.Zero(t, srv.ReadTimeout)
	assert.Zero(t, srv.WriteTimeout)
	assert.Equal(t, 10*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 120*time.Second, srv.IdleTimeout)
}

// Shutdown hooks (which end SSE streams) run at once, while an ordinary
// in-flight request still drains to completion.
func TestServeListener_ShutdownHooksRunAndDrain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	streamDone := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("done"))
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-streamDone
	})
	srv := &http.Server{Handler: mux}
	srv.RegisterOnShutdown(func() { close(streamDone) })
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- serveListener(ctx, srv, ln, 5*time.Second, zerolog.Nop()) }()

	base := "http://" + ln.Addr().String()
	slow := make(chan string, 1)
	go func() {
		resp, err := http.Get(base + "/slow")
		if err != nil {
			slow <- err.Error()
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		slow <- string(b)
	}()
	stream, err := http.Get(base + "/stream")
	require.NoError(t, err)
	defer stream.Body.Close()
	time.Sleep(50 * time.Millisecond)

	cancel()

	assert.Equal(t, "done", <-slow)
	select {
	case err := <-served:
		assert.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("serveListener did not return; the stream held the drain")
	}
}

// A request that never finishes must not hold the process past the drain
// deadline, and running out the deadline is not an error.
func TestServeListener_DeadlineClosesStragglers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	block := make(chan struct{})
	defer close(block)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-block
	})}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- serveListener(ctx, srv, ln, 200*time.Millisecond, zerolog.Nop()) }()

	resp, err := http.Get("http://" + ln.Addr().String())
	require.NoError(t, err)
	defer resp.Body.Close()
	cancel()

	select {
	case err := <-served:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("serveListener did not return after the drain deadline")
	}
}
