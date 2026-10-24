package auth

import (
	"strings"
	"sync"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/users"
)

// Login throttling limits: failures per (username, client IP) pair and per
// client IP within a fixed window.
const (
	LoginPairLimit = 5
	LoginIPLimit   = 20
	LoginWindow    = 15 * time.Minute

	// Above sweepThreshold keys, expired windows are swept at most once per
	// sweepInterval, so a flood of distinct keys costs one scan per interval
	// rather than one per attempt.
	sweepThreshold = 10000
	sweepInterval  = LoginWindow / 15
)

type window struct {
	start time.Time
	count int
}

// LoginLimiter throttles console logins. Each key uses a fixed window that
// starts at the key's first counted attempt. Safe for concurrent use.
//
// Allow reserves the attempt — counts it as a failure in progress — before
// the caller checks the password, so N parallel requests cannot all slip
// through a check-then-record gap. Success takes the reservation back.
type LoginLimiter struct {
	now func() time.Time

	mu        sync.Mutex
	entries   map[string]*window
	nextSweep time.Time
}

// NewLoginLimiter returns a limiter; a nil now defaults to time.Now.
func NewLoginLimiter(now func() time.Time) *LoginLimiter {
	if now == nil {
		now = time.Now
	}
	return &LoginLimiter{now: now, entries: make(map[string]*window)}
}

// pairKey returns the (username, ip) key, or "" when username is not a valid
// username: such a name can never log in, and keying on arbitrary client
// strings would let one client mint unlimited keys. Invalid names count
// against the IP key only.
func pairKey(username, ip string) string {
	if users.ValidateUsername(username) != nil {
		return ""
	}
	return "p\x00" + strings.ToLower(username) + "\x00" + ip
}

func ipKey(ip string) string { return "i\x00" + ip }

// Allow reports whether a login attempt may proceed and, if so, counts it
// against both the pair and the IP until Success takes it back. When blocked
// it returns the time left until the blocking window ends (the larger one if
// both block); a blocked attempt is not counted, so waiting out Retry-After
// is always enough.
func (l *LoginLimiter) Allow(username, ip string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.entries) > sweepThreshold && !now.Before(l.nextSweep) {
		l.sweep(now)
		l.nextSweep = now.Add(sweepInterval)
	}
	pk := pairKey(username, ip)
	var retry time.Duration
	if pk != "" {
		retry = l.blocked(pk, LoginPairLimit, now)
	}
	if d := l.blocked(ipKey(ip), LoginIPLimit, now); d > retry {
		retry = d
	}
	if retry > 0 {
		return retry, false
	}
	if pk != "" {
		l.bump(pk, now)
	}
	l.bump(ipKey(ip), now)
	return 0, true
}

// Success records that the attempt Allow admitted succeeded: the pair's
// failures are cleared and the attempt's own reservation is taken back from
// the IP. Earlier failures on the IP are left intact.
func (l *LoginLimiter) Success(username, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if pk := pairKey(username, ip); pk != "" {
		delete(l.entries, pk)
	}
	if w, ok := l.entries[ipKey(ip)]; ok && w.count > 0 {
		w.count--
	}
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
