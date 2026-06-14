package scanner_test

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/scanner"
)

// newMockClamdPing accepts connections, reads the NUL-terminated command and
// replies with the given response.
func newMockClamdPing(t *testing.T, response string) string {
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
				r := bufio.NewReader(c)
				_, _ = r.ReadBytes(0x00) // zPING\x00
				c.Write([]byte(response))
			}(conn)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// newMockICAPOptions accepts connections, drains the request header block and
// replies with the given canned ICAP response.
func newMockICAPOptions(t *testing.T, response string) string {
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
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				c.Write([]byte(response))
			}(conn)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

func TestClamAVProbe_OK(t *testing.T) {
	addr := newMockClamdPing(t, "PONG\x00")
	sc, err := scanner.NewClamAVScanner(addr, 2*time.Second)
	require.NoError(t, err)
	assert.NoError(t, sc.Probe(context.Background()))
}

func TestClamAVProbe_UnexpectedReply(t *testing.T) {
	addr := newMockClamdPing(t, "ERROR\x00")
	sc, err := scanner.NewClamAVScanner(addr, 2*time.Second)
	require.NoError(t, err)
	assert.Error(t, sc.Probe(context.Background()))
}

func TestClamAVProbe_ConnRefused(t *testing.T) {
	sc, err := scanner.NewClamAVScanner("tcp:127.0.0.1:1", time.Second)
	require.NoError(t, err)
	assert.Error(t, sc.Probe(context.Background()))
}

func TestICAPProbe_OK(t *testing.T) {
	addr := newMockICAPOptions(t, "ICAP/1.0 200 OK\r\nMethods: RESPMOD\r\n\r\n")
	sc, err := scanner.NewICAPScanner(addr, "srv", 2*time.Second)
	require.NoError(t, err)
	assert.NoError(t, sc.Probe(context.Background()))
}

func TestICAPProbe_ServerError(t *testing.T) {
	addr := newMockICAPOptions(t, "ICAP/1.0 500 Server Error\r\n\r\n")
	sc, err := scanner.NewICAPScanner(addr, "srv", 2*time.Second)
	require.NoError(t, err)
	assert.Error(t, sc.Probe(context.Background()))
}

func TestICAPProbe_ConnRefused(t *testing.T) {
	sc, err := scanner.NewICAPScanner("tcp:127.0.0.1:1", "srv", time.Second)
	require.NoError(t, err)
	assert.Error(t, sc.Probe(context.Background()))
}

// Compile-time check that both socket scanners satisfy Prober.
var _ scanner.Prober = (*scanner.ClamAVScanner)(nil)
var _ scanner.Prober = (*scanner.ICAPScanner)(nil)
