package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/stretchr/testify/require"
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

func TestLocalCache_CloseIsIdempotent(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	require.NoError(t, lc.Close())
	require.NoError(t, lc.Close())
}
