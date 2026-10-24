package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLimiter_SweepIsThrottled(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := NewLoginLimiter(func() time.Time { return now })
	fill := func(prefix string) {
		for i := 0; i <= sweepThreshold; i++ {
			l.entries[fmt.Sprintf("%s%d", prefix, i)] = &window{start: now.Add(-2 * LoginWindow), count: 1}
		}
	}

	fill("a")
	l.Allow("admin", "1.1.1.1")
	assert.Len(t, l.entries, 2, "expired windows are swept once the map is large")

	fill("b")
	now = now.Add(sweepInterval - time.Second)
	l.Allow("admin", "1.1.1.1")
	assert.Greater(t, len(l.entries), sweepThreshold, "no second sweep inside the interval")

	now = now.Add(time.Second)
	l.Allow("admin", "1.1.1.1")
	assert.Len(t, l.entries, 2, "the next sweep runs once the interval has passed")
}
