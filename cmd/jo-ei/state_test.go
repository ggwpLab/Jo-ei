package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareTempDir_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache", "tmp")

	require.NoError(t, prepareTempDir(dir))

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestPrepareTempDir_RemovesLeftovers(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"jo-ei-artifact-123", "jo-ei-layer-9", "keep.txt"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600))
	}

	require.NoError(t, prepareTempDir(dir))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{"keep.txt"}, names)
}
