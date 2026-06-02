package scanner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

func TestOSVScanner_JanitorEvictsExpired(t *testing.T) {
	s := NewOSVScanner("http://example.invalid", 20*time.Millisecond)
	defer s.Close()

	s.mu.Lock()
	s.cache["pypi/x@1.0"] = &cveEntry{
		result:    &proxy.ScanResult{Clean: true},
		expiresAt: time.Now().Add(-time.Hour), // already expired
	}
	s.mu.Unlock()

	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.cache) == 0
	}, time.Second, 10*time.Millisecond, "janitor should remove expired entries")
}

func TestOSVScanner_CloseStopsJanitor(t *testing.T) {
	s := NewOSVScanner("http://example.invalid", time.Hour)
	require.NoError(t, s.Close())
	assert.NoError(t, s.Close()) // idempotent
}
