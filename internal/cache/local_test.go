package cache_test

import (
	"os"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLocalCache(t *testing.T) cache.Cache {
	t.Helper()
	dir := t.TempDir()
	c, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:  dir,
		MaxSizeGB: 1,
		TTL:       24 * time.Hour,
	})
	require.NoError(t, err)
	return c
}

func makeTempArtifact(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "artifact-*.whl")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestLocalCache_PutAndGet(t *testing.T) {
	c := newTestLocalCache(t)

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0"}
	tmpPath := makeTempArtifact(t, "fake-wheel-content")

	err := c.Put(&ref, tmpPath, true, `{"clean":true}`)
	require.NoError(t, err)

	entry, found := c.Get(&ref)
	require.True(t, found)
	assert.True(t, entry.ScanClean)
	assert.FileExists(t, entry.ArtifactPath)

	data, err := os.ReadFile(entry.ArtifactPath)
	require.NoError(t, err)
	assert.Equal(t, "fake-wheel-content", string(data))
}

func TestLocalCache_GetMiss(t *testing.T) {
	c := newTestLocalCache(t)
	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "nonexistent", Version: "1.0.0"}
	_, found := c.Get(&ref)
	assert.False(t, found)
}

func TestLocalCache_Invalidate(t *testing.T) {
	c := newTestLocalCache(t)

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "flask", Version: "3.0.0"}
	tmpPath := makeTempArtifact(t, "content")
	require.NoError(t, c.Put(&ref, tmpPath, true, ""))

	entry, found := c.Get(&ref)
	require.True(t, found)
	artifactPath := entry.ArtifactPath

	require.NoError(t, c.Invalidate(&ref))

	_, found = c.Get(&ref)
	assert.False(t, found)
	assert.NoFileExists(t, artifactPath)
}

func TestLocalCache_Stats(t *testing.T) {
	c := newTestLocalCache(t)

	ref1 := proxy.PackageRef{Ecosystem: "pypi", Name: "a", Version: "1.0"}
	ref2 := proxy.PackageRef{Ecosystem: "pypi", Name: "b", Version: "1.0"}
	require.NoError(t, c.Put(&ref1, makeTempArtifact(t, "aaaa"), true, ""))
	require.NoError(t, c.Put(&ref2, makeTempArtifact(t, "bbbbbbbb"), true, ""))

	stats, err := c.Stats()
	require.NoError(t, err)
	assert.Equal(t, int64(2), stats.Entries)
	assert.Greater(t, stats.SizeBytes, int64(0))
}
