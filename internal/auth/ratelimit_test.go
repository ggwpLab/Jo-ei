package auth_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestLimiter() (*auth.LoginLimiter, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	return auth.NewLoginLimiter(c.Now), c
}

func TestLimiter_PairBlocksAfterFive(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < auth.LoginPairLimit; i++ {
		_, ok := l.Allow("admin", "1.1.1.1")
		assert.True(t, ok, "attempt %d", i+1)
	}
	retry, ok := l.Allow("admin", "1.1.1.1")
	assert.False(t, ok)
	assert.Equal(t, auth.LoginWindow, retry)

	_, ok = l.Allow("admin", "2.2.2.2")
	assert.True(t, ok)
	_, ok = l.Allow("ADMIN", "1.1.1.1")
	assert.False(t, ok)
}

func TestLimiter_BlockedAttemptIsNotCounted(t *testing.T) {
	l, c := newTestLimiter()
	for i := 0; i < auth.LoginPairLimit; i++ {
		l.Allow("admin", "1.1.1.1")
	}
	for i := 0; i < 50; i++ {
		_, ok := l.Allow("admin", "1.1.1.1")
		assert.False(t, ok)
	}
	// 5 admitted attempts on this IP, so 15 more fit under the IP limit.
	for i := 0; i < auth.LoginIPLimit-auth.LoginPairLimit; i++ {
		_, ok := l.Allow(fmt.Sprintf("other%d", i), "1.1.1.1")
		assert.True(t, ok, "attempt %d", i+1)
	}
	c.Advance(auth.LoginWindow)
	_, ok := l.Allow("admin", "1.1.1.1")
	assert.True(t, ok, "waiting out the window is always enough")
}

func TestLimiter_WindowExpires(t *testing.T) {
	l, c := newTestLimiter()
	for i := 0; i < auth.LoginPairLimit; i++ {
		l.Allow("admin", "1.1.1.1")
	}
	_, ok := l.Allow("admin", "1.1.1.1")
	assert.False(t, ok)
	c.Advance(auth.LoginWindow + time.Second)
	_, ok = l.Allow("admin", "1.1.1.1")
	assert.True(t, ok)
}

func TestLimiter_IPBlocksAcrossUsernames(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < auth.LoginIPLimit; i++ {
		_, ok := l.Allow(fmt.Sprintf("user%d", i), "1.1.1.1")
		assert.True(t, ok)
	}
	_, ok := l.Allow("fresh", "1.1.1.1")
	assert.False(t, ok)
	_, ok = l.Allow("fresh", "2.2.2.2")
	assert.True(t, ok)
}

func TestLimiter_SuccessResetsPair(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < 4; i++ {
		l.Allow("admin", "1.1.1.1")
	}
	_, ok := l.Allow("admin", "1.1.1.1")
	require.True(t, ok)
	l.Success("admin", "1.1.1.1")
	for i := 0; i < 4; i++ {
		l.Allow("admin", "1.1.1.1")
	}
	_, ok = l.Allow("admin", "1.1.1.1")
	assert.True(t, ok)
}

func TestLimiter_SuccessDoesNotCountAgainstIP(t *testing.T) {
	l, _ := newTestLimiter()
	// 40 successful logins from one IP (an office behind NAT) never block it.
	for i := 0; i < 2*auth.LoginIPLimit; i++ {
		_, ok := l.Allow("admin", "1.1.1.1")
		require.True(t, ok, "attempt %d", i+1)
		l.Success("admin", "1.1.1.1")
	}
}

func TestLimiter_SuccessKeepsIPFailures(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < auth.LoginIPLimit-1; i++ {
		l.Allow(fmt.Sprintf("user%d", i), "1.1.1.1")
	}
	_, ok := l.Allow("admin", "1.1.1.1")
	require.True(t, ok)
	l.Success("admin", "1.1.1.1")
	_, ok = l.Allow("fresh", "1.1.1.1")
	assert.True(t, ok, "the successful attempt itself is refunded")
	_, ok = l.Allow("fresh2", "1.1.1.1")
	assert.False(t, ok, "earlier failures on the IP survive a success")
}

func TestLimiter_InvalidUsernameCountsAgainstIPOnly(t *testing.T) {
	l, _ := newTestLimiter()
	// "ivan petrov" fails users.ValidateUsername: no pair key, so the pair
	// limit never applies — but every attempt still counts against the IP.
	for i := 0; i < auth.LoginIPLimit; i++ {
		_, ok := l.Allow("ivan petrov", "1.1.1.1")
		assert.True(t, ok, "attempt %d", i+1)
	}
	_, ok := l.Allow("admin", "1.1.1.1")
	assert.False(t, ok)
}

func TestLimiter_Concurrent(t *testing.T) {
	l, _ := newTestLimiter()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := fmt.Sprintf("user%d", i%5)
			for j := 0; j < 20; j++ {
				l.Allow(u, "1.1.1.1")
			}
			l.Success(u, "1.1.1.1")
		}(i)
	}
	wg.Wait()
}
