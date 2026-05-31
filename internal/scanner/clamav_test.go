package scanner_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockClamd starts a TCP server that consumes an INSTREAM request and then
// writes the given canned response. Returns a "tcp:host:port" address.
func newMockClamd(t *testing.T, response string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				consumeINSTREAM(c)
				c.Write([]byte(response))
			}(conn)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// consumeINSTREAM reads the zINSTREAM command and its length-prefixed chunks
// up to (and including) the zero-length terminator.
func consumeINSTREAM(c net.Conn) {
	r := bufio.NewReader(c)
	if _, err := r.ReadBytes(0x00); err != nil { // command up to NUL
		return
	}
	for {
		var size uint32
		if err := binary.Read(r, binary.BigEndian, &size); err != nil {
			return
		}
		if size == 0 {
			return
		}
		if _, err := io.CopyN(io.Discard, r, int64(size)); err != nil {
			return
		}
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact.bin")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

func TestClamAVScanner_CleanFile(t *testing.T) {
	addr := newMockClamd(t, "stream: OK\x00")
	sc, err := scanner.NewClamAVScanner(addr, 5*time.Second)
	require.NoError(t, err)

	res, err := sc.Scan(context.Background(), writeTempFile(t, "harmless content"))
	require.NoError(t, err)
	assert.True(t, res.Clean)
	assert.Equal(t, "", res.Signature)
}

func TestClamAVScanner_InfectedFile(t *testing.T) {
	addr := newMockClamd(t, "stream: Eicar-Test-Signature FOUND\x00")
	sc, err := scanner.NewClamAVScanner(addr, 5*time.Second)
	require.NoError(t, err)

	res, err := sc.Scan(context.Background(), writeTempFile(t, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"))
	require.NoError(t, err)
	assert.False(t, res.Clean)
	assert.Equal(t, "Eicar-Test-Signature", res.Signature)
}

func TestClamAVScanner_ErrorResponse(t *testing.T) {
	addr := newMockClamd(t, "INSTREAM size limit exceeded. ERROR\x00")
	sc, err := scanner.NewClamAVScanner(addr, 5*time.Second)
	require.NoError(t, err)

	_, err = sc.Scan(context.Background(), writeTempFile(t, "content"))
	assert.Error(t, err)
}

func TestClamAVScanner_ConnectionRefused(t *testing.T) {
	// Port 1 on loopback is not listening — Dial should fail.
	sc, err := scanner.NewClamAVScanner("tcp:127.0.0.1:1", 1*time.Second)
	require.NoError(t, err)

	_, err = sc.Scan(context.Background(), writeTempFile(t, "content"))
	assert.Error(t, err)
}
