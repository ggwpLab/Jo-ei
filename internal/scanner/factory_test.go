package scanner_test

import (
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_ClamAV(t *testing.T) {
	av, err := scanner.New(config.ScannerConfig{Type: "clamav", Address: "tcp:127.0.0.1:3310"})
	require.NoError(t, err)
	assert.IsType(t, &scanner.ClamAVScanner{}, av)
}

func TestNew_ICAP(t *testing.T) {
	av, err := scanner.New(config.ScannerConfig{Type: "icap", Address: "tcp:127.0.0.1:1344", Service: "avscan"})
	require.NoError(t, err)
	assert.IsType(t, &scanner.ICAPScanner{}, av)
}

func TestNew_UnknownType(t *testing.T) {
	_, err := scanner.New(config.ScannerConfig{Type: "bogus", Address: "tcp:x:1"})
	assert.Error(t, err)
}
