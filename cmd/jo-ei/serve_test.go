package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestServe_ShutsDownOnContextCancel(t *testing.T) {
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: http.NewServeMux()}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- serve(ctx, srv) }()

	time.Sleep(50 * time.Millisecond) // let the listener bind
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not return after context cancel")
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
		done <- serveAll(context.Background(), boundServer{srvA, lnA}, boundServer{srvB, lnB})
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
		servers = append(servers, boundServer{&http.Server{Handler: http.NewServeMux()}, ln})
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
