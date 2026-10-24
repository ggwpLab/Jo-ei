package auth_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

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
		assert.True(t, ok)
		l.Failure("admin", "1.1.1.1")
	}
	retry, ok := l.Allow("admin", "1.1.1.1")
	assert.False(t, ok)
	assert.Equal(t, auth.LoginWindow, retry)

	_, ok = l.Allow("admin", "2.2.2.2")
	assert.True(t, ok)
	_, ok = l.Allow("ADMIN", "1.1.1.1")
	assert.False(t, ok)
}

func TestLimiter_WindowExpires(t *testing.T) {
	l, c := newTestLimiter()
	for i := 0; i < auth.LoginPairLimit; i++ {
		l.Failure("admin", "1.1.1.1")
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
		l.Failure(fmt.Sprintf("user%d", i), "1.1.1.1")
	}
	_, ok := l.Allow("fresh", "1.1.1.1")
	assert.False(t, ok)
	_, ok = l.Allow("fresh", "2.2.2.2")
	assert.True(t, ok)
}

func TestLimiter_SuccessResetsPair(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < 4; i++ {
		l.Failure("admin", "1.1.1.1")
	}
	l.Success("admin", "1.1.1.1")
	for i := 0; i < 4; i++ {
		l.Failure("admin", "1.1.1.1")
	}
	_, ok := l.Allow("admin", "1.1.1.1")
	assert.True(t, ok)
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
				l.Failure(u, "1.1.1.1")
			}
			l.Success(u, "1.1.1.1")
		}(i)
	}
	wg.Wait()
}
