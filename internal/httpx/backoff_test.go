package httpx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
)

func TestAdaptiveBackoff_RetriesThrottleThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: httpx.NewAdaptiveBackoff(http.DefaultTransport, 3, time.Millisecond, 10*time.Millisecond)}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after retry", resp.StatusCode)
	}
	if calls.Load() < 2 {
		t.Fatalf("calls = %d, want >= 2 (a retry after 429)", calls.Load())
	}
}

func TestAdaptiveBackoff_ExhaustsBudgetReturns429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := &http.Client{Transport: httpx.NewAdaptiveBackoff(http.DefaultTransport, 2, time.Millisecond, 10*time.Millisecond)}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 after exhausting retries", resp.StatusCode)
	}
	if got := calls.Load(); got != 3 { // 1 initial + 2 retries
		t.Fatalf("calls = %d, want 3 (initial + maxRetries)", got)
	}
}

// A 429 puts the host into a cooldown shared by all requests: a second request
// issued right after must wait it out rather than hammering the upstream.
func TestAdaptiveBackoff_ThrottlePausesOtherRequests(t *testing.T) {
	var throttleOnce atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if throttleOnce.CompareAndSwap(false, true) {
			w.Header().Set("Retry-After", "1") // 1s cooldown
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: httpx.NewAdaptiveBackoff(http.DefaultTransport, 3, 10*time.Millisecond, 5*time.Second)}
	// First request trips the cooldown and retries after ~1s.
	start := time.Now()
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if elapsed := time.Since(start); elapsed < 800*time.Millisecond {
		t.Fatalf("request returned in %v, want >= ~1s honoring Retry-After", elapsed)
	}
}

func TestAdaptiveBackoff_ContextCancelDuringCooldown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := &http.Client{Transport: httpx.NewAdaptiveBackoff(http.DefaultTransport, 3, time.Second, time.Minute)}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)

	start := time.Now()
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancelled request blocked %v, want prompt return", elapsed)
	}
}
