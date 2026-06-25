package httpx_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
)

// A 429 opens the circuit for the host: subsequent requests fast-fail with
// ErrCircuitOpen without touching the upstream (no retry storm).
func TestCircuitBreaker_OpensAndFastFails(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	cb := httpx.NewCircuitBreaker(http.DefaultTransport, time.Second, 30*time.Second)
	client := &http.Client{Transport: cb}

	// First request reaches the upstream and trips the breaker.
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("first status = %d, want 429", resp.StatusCode)
	}

	// Second request must fast-fail without reaching the upstream.
	_, err = client.Get(srv.URL)
	if !errors.Is(err, httpx.ErrCircuitOpen) {
		t.Fatalf("second request error = %v, want ErrCircuitOpen", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1 (breaker must not hammer a throttled host)", hits.Load())
	}
}

// After the cooldown elapses the circuit closes and requests reach the upstream
// again; a success resets it.
func TestCircuitBreaker_ClosesAfterCooldownAndResetsOnSuccess(t *testing.T) {
	var throttle atomic.Bool
	throttle.Store(true)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if throttle.Load() {
			w.Header().Set("Retry-After", "0") // ~immediate cooldown
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cb := httpx.NewCircuitBreaker(http.DefaultTransport, time.Millisecond, 10*time.Millisecond)
	client := &http.Client{Transport: cb}

	resp, err := client.Get(srv.URL) // trips with ~0 cooldown
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp.Body.Close()

	throttle.Store(false)
	time.Sleep(15 * time.Millisecond) // let the short cooldown elapse

	resp, err = client.Get(srv.URL)
	if err != nil {
		t.Fatalf("post-cooldown request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-cooldown status = %d, want 200 (circuit should have closed)", resp.StatusCode)
	}
}

// A healthy host is never fast-failed.
func TestCircuitBreaker_PassesThroughHealthyHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: httpx.NewCircuitBreaker(http.DefaultTransport, time.Second, time.Minute)}
	for range 5 {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	}
}
