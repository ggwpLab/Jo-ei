package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// clamavChunkSize is the size of each INSTREAM data chunk sent to clamd.
const clamavChunkSize = 8192

// ClamAVScanner is a clamd client that scans files via the INSTREAM command.
// It implements proxy.AVScanner.
type ClamAVScanner struct {
	network string // "unix" or "tcp"
	addr    string
	timeout time.Duration
}

// NewClamAVScanner creates a scanner for the given clamd address.
// address is "unix:///var/run/clamav/clamd.sock" or "tcp:host:3310".
func NewClamAVScanner(address string, timeout time.Duration) (*ClamAVScanner, error) {
	network, addr, err := parseScannerAddress(address)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &ClamAVScanner{network: network, addr: addr, timeout: timeout}, nil
}

// parseScannerAddress splits "unix:///path" or "tcp:host:port" into (network, addr).
// Shared by all socket-based scanners (clamav, icap).
func parseScannerAddress(address string) (network, addr string, err error) {
	switch {
	case strings.HasPrefix(address, "unix://"):
		return "unix", strings.TrimPrefix(address, "unix://"), nil
	case strings.HasPrefix(address, "tcp:"):
		return "tcp", strings.TrimPrefix(address, "tcp:"), nil
	default:
		return "", "", fmt.Errorf("unsupported scanner address %q (want unix:// or tcp:)", address)
	}
}

// Scan implements proxy.AVScanner using the clamd INSTREAM protocol.
func (s *ClamAVScanner) Scan(ctx context.Context, filePath string) (*proxy.AVResult, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening artifact for scan: %w", err)
	}
	defer f.Close()

	dialer := net.Dialer{Timeout: s.timeout}
	conn, err := dialer.DialContext(ctx, s.network, s.addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to clamd: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(s.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// "z" prefix = NULL-terminated command.
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return nil, fmt.Errorf("sending INSTREAM command: %w", err)
	}

	// Stream the file as length-prefixed chunks.
	buf := make([]byte, clamavChunkSize)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			var sizeBuf [4]byte
			binary.BigEndian.PutUint32(sizeBuf[:], uint32(n))
			if _, err := conn.Write(sizeBuf[:]); err != nil {
				return nil, fmt.Errorf("sending chunk size: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return nil, fmt.Errorf("sending chunk data: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("reading artifact: %w", readErr)
		}
	}

	// Zero-length chunk terminates the stream.
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return nil, fmt.Errorf("sending stream terminator: %w", err)
	}

	respBytes, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("reading clamd response: %w", err)
	}
	return parseClamAVResponse(string(respBytes))
}

// parseClamAVResponse interprets a clamd INSTREAM reply.
// "stream: OK" → clean; "stream: <sig> FOUND" → infected; anything else → error.
func parseClamAVResponse(resp string) (*proxy.AVResult, error) {
	trimmed := strings.TrimRight(resp, "\x00\n ")
	switch {
	case strings.HasSuffix(trimmed, "OK"):
		return &proxy.AVResult{Clean: true, Engine: "clamav"}, nil
	case strings.HasSuffix(trimmed, "FOUND"):
		sig := strings.TrimSuffix(trimmed, " FOUND")
		if idx := strings.Index(sig, ": "); idx != -1 {
			sig = sig[idx+2:]
		}
		return &proxy.AVResult{Clean: false, Signature: strings.TrimSpace(sig), Engine: "clamav"}, nil
	default:
		return nil, fmt.Errorf("clamd error response: %q", trimmed)
	}
}
