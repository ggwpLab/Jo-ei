package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "art.bin")
	require.NoError(t, os.WriteFile(p, []byte(content), 0644))
	return p
}

func TestLocalCache_EvictToSizeRemovesEntries(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	for _, n := range []string{"a", "b", "c"} {
		ref := &proxy.PackageRef{Ecosystem: "pypi", Name: n, Version: "1.0"}
		require.NoError(t, lc.Put(ref, writeTemp(t, "data-"+n), true, ""))
	}
	before, err := lc.index.Count()
	require.NoError(t, err)
	require.Equal(t, int64(3), before)

	// 1-byte budget forces eviction of everything over the limit.
	lc.evictToSize(1)

	after, err := lc.index.Count()
	require.NoError(t, err)
	require.Less(t, after, before)
}

func TestLocalCache_ConcurrentPutsAreSafe(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	const n = 20
	paths := make([]string, n)
	for i := range paths {
		paths[i] = writeTemp(t, "data")
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ref := &proxy.PackageRef{Ecosystem: "pypi", Name: fmt.Sprintf("pkg%d", i), Version: "1.0"}
			_ = lc.Put(ref, paths[i], true, "")
		}(i)
	}
	wg.Wait()

	count, err := lc.index.Count()
	require.NoError(t, err)
	require.Equal(t, int64(n), count)
}

func TestLocalCache_CloseIsIdempotent(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	require.NoError(t, lc.Close())
	require.NoError(t, lc.Close())
}
