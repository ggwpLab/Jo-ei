package httpx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
)

// trackingServer reports the peak number of simultaneously in-flight requests it
// observed, so a test can assert the limiter never let more than N through.
func trackingServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var inflight, peak int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&inflight, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if n <= old || atomic.CompareAndSwapInt32(&peak, old, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&inflight, -1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &peak
}

func TestConcurrencyLimiter_CapsPerHost(t *testing.T) {
	srv, peak := trackingServer(t)
	client := &http.Client{Transport: httpx.NewConcurrencyLimiter(http.DefaultTransport, 3)}

	var wg sync.WaitGroup
	for range 15 {
		wg.Go(func() {
			resp, err := client.Get(srv.URL)
			if err == nil {
				resp.Body.Close()
			}
		})
	}
	wg.Wait()

	if got := atomic.LoadInt32(peak); got > 3 {
		t.Fatalf("peak concurrency = %d, want <= 3", got)
	}
}

func TestConcurrencyLimiter_HostsAreIndependent(t *testing.T) {
	srvA, peakA := trackingServer(t)
	srvB, peakB := trackingServer(t)
	limiter := httpx.NewConcurrencyLimiter(http.DefaultTransport, 2)
	client := &http.Client{Transport: limiter}

	var wg sync.WaitGroup
	for _, url := range []string{srvA.URL, srvB.URL} {
		for range 6 {
			wg.Go(func() {
				resp, err := client.Get(url)
				if err == nil {
					resp.Body.Close()
				}
			})
		}
	}
	wg.Wait()

	// Each host has its own cap of 2; one host's load must not starve the other.
	if a, b := atomic.LoadInt32(peakA), atomic.LoadInt32(peakB); a > 2 || b > 2 {
		t.Fatalf("per-host peaks A=%d B=%d, want both <= 2", a, b)
	}
}

func TestConcurrencyLimiter_ContextCancelReleasesWaiter(t *testing.T) {
	// One slot, held by a slow in-flight request; a second request whose context
	// is cancelled while queued must return promptly with the context error
	// rather than blocking until the slot frees.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(block)

	client := &http.Client{Transport: httpx.NewConcurrencyLimiter(http.DefaultTransport, 1)}
	go func() { _, _ = client.Get(srv.URL) }() // occupies the only slot
	time.Sleep(20 * time.Millisecond)

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()

	start := time.Now()
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("queued request blocked %v after cancel, want prompt return", elapsed)
	}
}
