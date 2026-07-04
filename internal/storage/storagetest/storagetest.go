// Package storagetest provides test helpers for SQLite-backed tests.
package storagetest

import (
	"os"
	"testing"
	"time"
)

// TempDir returns a temporary directory suitable for a throwaway SQLite
// database, removed when the test finishes.
//
// Use it instead of t.TempDir for directories that hold a storage.DB file. On
// Windows the pure-Go SQLite driver can release its file handle a few
// milliseconds after Close returns; the delete-pending file makes a bare
// RemoveAll fail with ERROR_DIR_NOT_EMPTY, and t.TempDir's cleanup does not
// retry that error, failing the test. This cleanup retries removal briefly
// (one 10ms retry suffices in practice) before reporting the error.
func TempDir(tb testing.TB) string {
	tb.Helper()
	dir, err := os.MkdirTemp("", "joei-test")
	if err != nil {
		tb.Fatalf("storagetest: creating temp dir: %v", err)
	}
	tb.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := os.RemoveAll(dir)
			if err == nil {
				return
			}
			if time.Now().After(deadline) {
				tb.Errorf("storagetest: removing temp dir %s: %v", dir, err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	return dir
}
