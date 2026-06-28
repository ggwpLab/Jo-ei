package scanner_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
)

// blockingScanner records peak concurrency and blocks in Scan until released.
type blockingScanner struct {
	entered  chan struct{} // signalled when a scan begins
	release  chan struct{} // scans return once this is closed
	inFlight int32
	peak     int32
}

func (b *blockingScanner) Scan(_ context.Context, _ string) (*proxy.AVResult, error) {
	cur := atomic.AddInt32(&b.inFlight, 1)
	for {
		p := atomic.LoadInt32(&b.peak)
		if cur <= p || atomic.CompareAndSwapInt32(&b.peak, p, cur) {
			break
		}
	}
	b.entered <- struct{}{}
	<-b.release
	atomic.AddInt32(&b.inFlight, -1)
	return &proxy.AVResult{Clean: true, Engine: "stub"}, nil
}

func TestLimitedScanner_CapsConcurrency(t *testing.T) {
	const limit = 2
	const total = 5
	inner := &blockingScanner{
		entered: make(chan struct{}, total),
		release: make(chan struct{}),
	}
	lim := scanner.NewLimitedScanner(inner, limit)

	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = lim.Scan(context.Background(), "/tmp/x")
		}()
	}

	// Exactly `limit` scans should reach the inner scanner concurrently.
	for i := 0; i < limit; i++ {
		select {
		case <-inner.entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d scans entered, want %d", i, limit)
		}
	}
	// No further scan may enter while the slots are held.
	select {
	case <-inner.entered:
		t.Fatal("a third scan entered before a slot was freed")
	case <-time.After(100 * time.Millisecond):
	}

	close(inner.release)
	wg.Wait()
	assert.LessOrEqual(t, inner.peak, int32(limit), "peak concurrency exceeded the limit")
}

func TestLimitedScanner_PassesResultThrough(t *testing.T) {
	infected := stubScanner{result: &proxy.AVResult{Clean: false, Signature: "EICAR", Engine: "clamav"}}
	lim := scanner.NewLimitedScanner(infected, 1)
	res, err := lim.Scan(context.Background(), "/tmp/x")
	require.NoError(t, err)
	assert.False(t, res.Clean)
	assert.Equal(t, "EICAR", res.Signature)
}

func TestLimitedScanner_PassesErrorThrough(t *testing.T) {
	failing := stubScanner{err: fmt.Errorf("clamd down")}
	lim := scanner.NewLimitedScanner(failing, 1)
	_, err := lim.Scan(context.Background(), "/tmp/x")
	assert.Error(t, err)
}

func TestLimitedScanner_ContextCancelledWhileWaiting(t *testing.T) {
	inner := &blockingScanner{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	lim := scanner.NewLimitedScanner(inner, 1)

	// Occupy the only slot.
	go func() { _, _ = lim.Scan(context.Background(), "/tmp/held") }()
	<-inner.entered

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := lim.Scan(ctx, "/tmp/x")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	close(inner.release)
}

func TestLimitedScanner_NonPositiveLimitDisablesLimiting(t *testing.T) {
	inner := clean("clamav")
	lim := scanner.NewLimitedScanner(inner, 0)
	assert.Equal(t, proxy.AVScanner(inner), lim, "limit <= 0 should return the scanner unwrapped")
}
