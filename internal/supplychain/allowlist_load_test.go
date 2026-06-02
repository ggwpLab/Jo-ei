package supplychain_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

func TestLoadAllowlist_ParsesEntriesIgnoringCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	content := "# comment\npypi/requests\n\n  npm/left-pad@1.3.0  \n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	al, err := supplychain.LoadAllowlist(path)
	require.NoError(t, err)

	assert.True(t, al.Contains(&proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "9.9.9"}))
	assert.True(t, al.Contains(&proxy.PackageRef{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}))
	assert.False(t, al.Contains(&proxy.PackageRef{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0"}))
}

func TestLoadAllowlist_MissingFileIsError(t *testing.T) {
	_, err := supplychain.LoadAllowlist(filepath.Join(t.TempDir(), "nope.txt"))
	require.Error(t, err)
}
