package scanner_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
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

func TestNew_NamedICAPReportsNameAsEngine(t *testing.T) {
	addr := newMockICAP(t, "ICAP/1.0 200 OK\r\nX-Virus-ID: EICAR-Test-File\r\n\r\n")
	av, err := scanner.New(config.ScannerConfig{Type: "icap", Name: "kaspersky", Address: addr, Service: "avscan"})
	require.NoError(t, err)

	res, err := av.Scan(context.Background(), writeEICAR(t))
	require.NoError(t, err)
	assert.Equal(t, "kaspersky", res.Engine)
}

func TestNew_UnnamedICAPReportsService(t *testing.T) {
	addr := newMockICAP(t, "ICAP/1.0 204 No Content\r\n\r\n")
	av, err := scanner.New(config.ScannerConfig{Type: "icap", Address: addr, Service: "avscan"})
	require.NoError(t, err)

	res, err := av.Scan(context.Background(), writeEICAR(t))
	require.NoError(t, err)
	assert.Equal(t, "icap:avscan", res.Engine)
}

func TestNew_NamedClamAVReportsNameAsEngine(t *testing.T) {
	addr := newMockClamd(t, "stream: Eicar-Test-Signature FOUND\x00")
	av, err := scanner.New(config.ScannerConfig{Type: "clamav", Name: "clamav-eu", Address: addr})
	require.NoError(t, err)

	res, err := av.Scan(context.Background(), writeTempFile(t, "payload"))
	require.NoError(t, err)
	assert.Equal(t, "clamav-eu", res.Engine)
}
