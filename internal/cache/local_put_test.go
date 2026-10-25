package cache_test

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
)

func newRootedLocalCache(t *testing.T) (cache.Cache, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, StaleAfter: 24 * time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c, dir
}

var putRef = &gate.PackageRef{Ecosystem: "pypi", Name: "torch", Version: "2.5.0"}

// Two cold requests for one artifact both Put it. The second Put must not
// disturb the first request, which is still streaming the file it opened.
func TestPut_ConcurrentReaderSeesCompleteFile(t *testing.T) {
	c, _ := newRootedLocalCache(t)
	a := strings.Repeat("a", 1<<20)
	b := strings.Repeat("b", 2<<20)

	require.NoError(t, c.Put(putRef, makeTempArtifact(t, a), true, ""))
	entry, ok := c.Get(putRef)
	require.True(t, ok)
	reader, err := os.Open(entry.ArtifactPath)
	require.NoError(t, err)
	defer reader.Close()

	require.NoError(t, c.Put(putRef, makeTempArtifact(t, b), true, ""))

	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, len(a), len(got), "open reader must see the complete old file")
	assert.True(t, string(got) == a, "open reader saw different bytes")

	entry, ok = c.Get(putRef)
	require.True(t, ok)
	fresh, err := os.ReadFile(entry.ArtifactPath)
	require.NoError(t, err)
	assert.True(t, string(fresh) == b, "fresh read must see the new file")
}

func TestPut_LeavesNoTempFiles(t *testing.T) {
	c, root := newRootedLocalCache(t)
	require.NoError(t, c.Put(putRef, makeTempArtifact(t, "one"), true, ""))
	require.NoError(t, c.Put(putRef, makeTempArtifact(t, "two"), true, ""))

	var leftovers []string
	require.NoError(t, filepath.WalkDir(filepath.Join(root, "artifacts"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), ".put-") {
			leftovers = append(leftovers, p)
		}
		return err
	}))
	assert.Empty(t, leftovers)
}

func TestPut_FailedCopyKeepsOldEntry(t *testing.T) {
	c, _ := newRootedLocalCache(t)
	require.NoError(t, c.Put(putRef, makeTempArtifact(t, "old"), true, ""))

	err := c.Put(putRef, filepath.Join(t.TempDir(), "missing"), true, "")
	require.Error(t, err)

	entry, ok := c.Get(putRef)
	require.True(t, ok)
	got, err := os.ReadFile(entry.ArtifactPath)
	require.NoError(t, err)
	assert.Equal(t, "old", string(got))
}
