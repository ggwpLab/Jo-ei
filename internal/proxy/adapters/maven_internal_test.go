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
