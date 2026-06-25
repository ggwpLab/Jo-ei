package httpx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
)

func okServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRateLimiter_LimitsRate(t *testing.T) {
	srv := okServer(t)
	// 50 req/s, burst 1: after the first token, each request waits ~20ms, so five
	// sequential requests take at least ~80ms.
	client := &http.Client{Transport: httpx.NewRateLimiter(http.DefaultTransport, 50, 1)}

	start := time.Now()
	for range 5 {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
	}
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Fatalf("five requests took %v, want >= ~80ms under a 50 req/s limit", elapsed)
	}
}

func TestRateLimiter_DisabledWhenRateZero(t *testing.T) {
	srv := okServer(t)
	client := &http.Client{Transport: httpx.NewRateLimiter(http.DefaultTransport, 0, 0)}

	start := time.Now()
	for range 20 {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
	}
	// rate<=0 disables limiting; 20 local requests must not be throttled.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("disabled limiter throttled requests: %v", elapsed)
	}
}

func TestRateLimiter_ContextCancelWhileWaiting(t *testing.T) {
	srv := okServer(t)
	// 1 req/s, burst 1: the first request drains the bucket, the next must wait
	// ~1s — but a cancelled context returns promptly instead.
	client := &http.Client{Transport: httpx.NewRateLimiter(http.DefaultTransport, 1, 1)}
	resp, err := client.Get(srv.URL) // consumes the only token
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp.Body.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)

	start := time.Now()
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("cancelled request blocked %v, want prompt return", elapsed)
	}
}
