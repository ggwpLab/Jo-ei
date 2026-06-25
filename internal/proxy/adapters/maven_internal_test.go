package adapters

import (
	"testing"
	"time"
)

// jitteredBackoff must keep the exponential delay within "equal jitter" bounds
// [d/2, d] where d = capDelay(base << attempt), so retries never fire instantly
// yet still spread out to avoid a thundering herd of simultaneous retries.
func TestJitteredBackoff_WithinEqualJitterBounds(t *testing.T) {
	for attempt := range 6 {
		d := capDelay(mavenRetryBaseDelay << attempt)
		half := d / 2
		for range 200 {
			got := jitteredBackoff(attempt)
			if got < half || got > d {
				t.Fatalf("attempt %d: delay %v out of bounds [%v, %v]", attempt, got, half, d)
			}
		}
	}
}

// jitteredBackoff must actually vary; a constant delay would defeat the point of
// jitter (de-synchronizing concurrent retries).
func TestJitteredBackoff_Varies(t *testing.T) {
	seen := make(map[time.Duration]bool)
	for range 100 {
		seen[jitteredBackoff(3)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected jittered backoff to vary, got %d distinct value(s)", len(seen))
	}
}

// A Retry-After value below the cap must be honored (we wait at least that long)
// but carry bounded jitter so concurrent throttled requests don't re-synchronize.
func TestRetryAfterDelay_HonorsHeaderPlusJitter(t *testing.T) {
	for range 100 {
		d := retryAfterDelay("1", 0)
		if d < time.Second {
			t.Fatalf("delay %v < server-requested 1s", d)
		}
		if d > mavenRetryMaxDelay {
			t.Fatalf("delay %v exceeds cap %v", d, mavenRetryMaxDelay)
		}
	}
}

// The Retry-After jitter must vary, otherwise it does not de-synchronize.
func TestRetryAfterDelay_JitterVaries(t *testing.T) {
	seen := make(map[time.Duration]bool)
	for range 100 {
		seen[retryAfterDelay("1", 0)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected Retry-After jitter to vary, got %d distinct value(s)", len(seen))
	}
}

// A server demanding a very long pause is capped so a stuck pull fails fast
// instead of blocking for the full Retry-After.
func TestRetryAfterDelay_CapsLargeHeader(t *testing.T) {
	if d := retryAfterDelay("600", 0); d != mavenRetryMaxDelay {
		t.Fatalf("delay %v, want cap %v for an over-cap Retry-After", d, mavenRetryMaxDelay)
	}
}
