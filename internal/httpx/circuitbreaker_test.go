package httpx_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
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

type throttlingRT struct{}

func (throttlingRT) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": []string{"1"}},
		Body:       http.NoBody,
	}, nil
}

// OpenHosts lists hosts whose circuit is currently open, and drops them once
// the cooldown has elapsed.
func TestCircuitBreaker_OpenHosts(t *testing.T) {
	const cooldown = 80 * time.Millisecond
	cb := httpx.NewCircuitBreaker(throttlingRT{}, time.Millisecond, cooldown) // maxDelay caps the 1s Retry-After
	if got := cb.OpenHosts(); len(got) != 0 {
		t.Fatalf("OpenHosts() before any request = %v, want empty", got)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://a:443/x", nil)
	resp, err := cb.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	resp.Body.Close()

	if got := cb.OpenHosts(); !reflect.DeepEqual(got, []string{"a:443"}) {
		t.Fatalf("OpenHosts() = %v, want [a:443]", got)
	}

	time.Sleep(cooldown + 40*time.Millisecond)
	if got := cb.OpenHosts(); len(got) != 0 {
		t.Fatalf("OpenHosts() after cooldown = %v, want empty", got)
	}
}

// statusRT answers every request with a fixed status and Retry-After.
type statusRT struct {
	status     int
	retryAfter string
}

func (s statusRT) RoundTrip(*http.Request) (*http.Response, error) {
	h := http.Header{}
	if s.retryAfter != "" {
		h.Set("Retry-After", s.retryAfter)
	}
	return &http.Response{StatusCode: s.status, Header: h, Body: http.NoBody}, nil
}

// Throttle reports the status that opened a host's circuit and the time left
// on its cooldown, so a handler can tell 429 from 503 and set Retry-After.
func TestCircuitBreaker_Throttle(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		cb := httpx.NewCircuitBreaker(statusRT{status: status, retryAfter: "7"}, time.Millisecond, time.Minute)
		if _, _, ok := cb.Throttle("a:443"); ok {
			t.Fatalf("Throttle before any request: ok = true, want false")
		}

		req, _ := http.NewRequest(http.MethodGet, "https://a:443/x", nil)
		resp, err := cb.RoundTrip(req)
		if err != nil {
			t.Fatalf("round trip: %v", err)
		}
		resp.Body.Close()

		got, retryIn, ok := cb.Throttle("a:443")
		if !ok || got != status {
			t.Fatalf("Throttle = (%d, %v, %v), want status %d and ok", got, retryIn, ok, status)
		}
		// Retry-After 7s plus at most baseDelay (1ms) of jitter.
		if retryIn <= 6*time.Second || retryIn > 7*time.Second+time.Millisecond {
			t.Fatalf("retryIn = %v, want ~7s", retryIn)
		}
		if _, _, ok := cb.Throttle("b:443"); ok {
			t.Fatalf("Throttle for an untouched host: ok = true, want false")
		}
	}
}

// A closed circuit (cooldown elapsed) reports no throttle.
func TestCircuitBreaker_ThrottleClearsAfterCooldown(t *testing.T) {
	const cooldown = 40 * time.Millisecond
	cb := httpx.NewCircuitBreaker(statusRT{status: http.StatusTooManyRequests}, cooldown, cooldown)
	req, _ := http.NewRequest(http.MethodGet, "https://a:443/x", nil)
	resp, err := cb.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	resp.Body.Close()

	time.Sleep(cooldown + 40*time.Millisecond)
	if _, _, ok := cb.Throttle("a:443"); ok {
		t.Fatalf("Throttle after cooldown: ok = true, want false")
	}
}

func TestSetRetryAfter(t *testing.T) {
	for _, tt := range []struct {
		d    time.Duration
		want string
	}{
		{0, ""},
		{-time.Second, ""},
		{time.Millisecond, "1"},
		{30 * time.Second, "30"},
		{30*time.Second + time.Millisecond, "31"},
	} {
		h := http.Header{}
		httpx.SetRetryAfter(h, tt.d)
		if got := h.Get("Retry-After"); got != tt.want {
			t.Fatalf("SetRetryAfter(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
