package scanner_test

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockICAP starts a TCP server that consumes a RESPMOD request and replies
// with the given canned ICAP response. Returns a "tcp:host:port" address.
func newMockICAP(t *testing.T, response string) string {
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
				consumeICAP(c)
				c.Write([]byte(response))
			}(conn)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// consumeICAP reads an ICAP request: header block (until blank line) then the
// encapsulated res-hdr + chunked body until the final "0" chunk.
func consumeICAP(c net.Conn) {
	r := bufio.NewReader(c)
	for { // ICAP headers
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	for { // encapsulated body, line-oriented (test payloads are text)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimRight(line, "\r\n") == "0" {
			r.ReadString('\n') // trailing CRLF
			return
		}
	}
}

func writeEICAR(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "artifact.bin")
	const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	require.NoError(t, os.WriteFile(p, []byte(eicar), 0644))
	return p
}

func TestICAPScanner_Clean(t *testing.T) {
	addr := newMockICAP(t, "ICAP/1.0 204 No Content\r\n\r\n")
	s, err := scanner.NewICAPScanner(addr, "avscan", 2*time.Second)
	require.NoError(t, err)

	res, err := s.Scan(context.Background(), writeEICAR(t))
	require.NoError(t, err)
	assert.True(t, res.Clean)
	assert.Equal(t, "icap", res.Engine)
}

func TestICAPScanner_KasperskyInfected(t *testing.T) {
	addr := newMockICAP(t, "ICAP/1.0 200 OK\r\nX-Virus-ID: EICAR-Test-File\r\n\r\n")
	s, err := scanner.NewICAPScanner(addr, "avscan", 2*time.Second)
	require.NoError(t, err)

	res, err := s.Scan(context.Background(), writeEICAR(t))
	require.NoError(t, err)
	assert.False(t, res.Clean)
	assert.Equal(t, "EICAR-Test-File", res.Signature)
	assert.Equal(t, "icap", res.Engine)
}

func TestICAPScanner_DrWebInfected(t *testing.T) {
	addr := newMockICAP(t, "ICAP/1.0 200 OK\r\nX-Infection-Found: Type=0; Resolution=2; Threat=EICAR Test File;\r\n\r\n")
	s, err := scanner.NewICAPScanner(addr, "avscan", 2*time.Second)
	require.NoError(t, err)

	res, err := s.Scan(context.Background(), writeEICAR(t))
	require.NoError(t, err)
	assert.False(t, res.Clean)
	assert.Equal(t, "EICAR Test File", res.Signature)
}

func TestICAPScanner_ServerError(t *testing.T) {
	addr := newMockICAP(t, "ICAP/1.0 500 Server Error\r\n\r\n")
	s, err := scanner.NewICAPScanner(addr, "avscan", 2*time.Second)
	require.NoError(t, err)

	_, err = s.Scan(context.Background(), writeEICAR(t))
	assert.Error(t, err)
}

func TestNewICAPScanner_RequiresService(t *testing.T) {
	_, err := scanner.NewICAPScanner("tcp:host:1344", "", time.Second)
	assert.Error(t, err)
}
