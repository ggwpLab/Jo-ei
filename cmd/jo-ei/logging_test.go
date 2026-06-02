package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogWriter_StdoutStderrDefault(t *testing.T) {
	for _, out := range []string{"", "stderr"} {
		w, closeFn, err := logWriter(out)
		require.NoError(t, err)
		assert.Equal(t, os.Stderr, w)
		require.NoError(t, closeFn())
	}
	w, closeFn, err := logWriter("stdout")
	require.NoError(t, err)
	assert.Equal(t, os.Stdout, w)
	require.NoError(t, closeFn())
}

func TestLogWriter_FilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w, closeFn, err := logWriter(path)
	require.NoError(t, err)
	_, err = w.Write([]byte("hello\n"))
	require.NoError(t, err)
	require.NoError(t, closeFn())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "hello")
}

func TestLogWriter_BadPathIsError(t *testing.T) {
	_, _, err := logWriter(filepath.Join(t.TempDir(), "no-such-dir", "app.log"))
	require.Error(t, err)
}
