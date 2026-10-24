package auth

import (
	"strings"
	"sync"
	"time"
)

// Login throttling limits: failures per (username, client IP) pair and per
// client IP within a fixed window.
const (
	LoginPairLimit = 5
	LoginIPLimit   = 20
	LoginWindow    = 15 * time.Minute

	sweepThreshold = 10000
)

type window struct {
	start time.Time
	count int
}

// LoginLimiter throttles failed console logins. Each key uses a fixed window
// that starts at the key's first failure. Safe for concurrent use.
type LoginLimiter struct {
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*window
}

// NewLoginLimiter returns a limiter; a nil now defaults to time.Now.
func NewLoginLimiter(now func() time.Time) *LoginLimiter {
	if now == nil {
		now = time.Now
	}
	return &LoginLimiter{now: now, entries: make(map[string]*window)}
}

func pairKey(username, ip string) string {
	return "p\x00" + strings.ToLower(username) + "\x00" + ip
}

func ipKey(ip string) string { return "i\x00" + ip }

// Allow reports whether a login attempt may proceed. When blocked it returns
// the time left until the blocking window ends (the larger one if both block).
func (l *LoginLimiter) Allow(username, ip string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var retry time.Duration
	if d := l.blocked(pairKey(username, ip), LoginPairLimit, now); d > retry {
		retry = d
	}
	if d := l.blocked(ipKey(ip), LoginIPLimit, now); d > retry {
		retry = d
	}
	return retry, retry == 0
}

// Failure records a failed attempt against both the pair and the IP.
func (l *LoginLimiter) Failure(username, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.entries) > sweepThreshold {
		l.sweep(now)
	}
	l.bump(pairKey(username, ip), now)
	l.bump(ipKey(ip), now)
}

// Success clears the pair's failures; the per-IP count is left intact.
func (l *LoginLimiter) Success(username, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, pairKey(username, ip))
}

// blocked returns the remaining block time for key, dropping it if expired.
func (l *LoginLimiter) blocked(key string, limit int, now time.Time) time.Duration {
	w, ok := l.entries[key]
	if !ok {
		return 0
	}
	end := w.start.Add(LoginWindow)
	if !now.Before(end) {
		delete(l.entries, key)
		return 0
	}
	if w.count >= limit {
		return end.Sub(now)
	}
	return 0
}

func (l *LoginLimiter) bump(key string, now time.Time) {
	w, ok := l.entries[key]
	if !ok || !now.Before(w.start.Add(LoginWindow)) {
		l.entries[key] = &window{start: now, count: 1}
		return
	}
	w.count++
}

func (l *LoginLimiter) sweep(now time.Time) {
	for k, w := range l.entries {
		if !now.Before(w.start.Add(LoginWindow)) {
			delete(l.entries, k)
		}
	}
}
