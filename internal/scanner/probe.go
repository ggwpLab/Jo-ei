package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// Prober is an optional scanner capability: a cheap liveness check that does not
// scan a file. ClamAVScanner and ICAPScanner implement it; the health Monitor
// calls Probe on a background timer.
type Prober interface {
	Probe(ctx context.Context) error
}

// dialProbe opens a connection to the scanner with the scanner's timeout, also
// honouring an earlier context deadline. The caller must Close the conn.
func dialProbe(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	return conn, nil
}

// Probe checks clamd liveness with the PING command (expects PONG).
func (s *ClamAVScanner) Probe(ctx context.Context) error {
	conn, err := dialProbe(ctx, s.network, s.addr, s.timeout)
	if err != nil {
		return fmt.Errorf("connecting to clamd: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return fmt.Errorf("sending PING: %w", err)
	}
	r := bufio.NewReader(conn)
	resp, err := r.ReadBytes(0x00) // clamd terminates the reply with NUL
	if err != nil && len(resp) == 0 {
		return fmt.Errorf("reading clamd ping reply: %w", err)
	}
	if !strings.Contains(string(resp), "PONG") {
		return fmt.Errorf("unexpected clamd ping reply: %q", strings.TrimSpace(string(resp)))
	}
	return nil
}

// Probe checks ICAP liveness with the OPTIONS method (expects a 2xx status).
func (s *ICAPScanner) Probe(ctx context.Context) error {
	conn, err := dialProbe(ctx, s.network, s.addr, s.timeout)
	if err != nil {
		return fmt.Errorf("connecting to icap server: %w", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("OPTIONS icap://%s/%s ICAP/1.0\r\nHost: %s\r\n\r\n", s.addr, s.service, s.addr)
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("sending OPTIONS: %w", err)
	}
	// A fresh connection is opened per probe and closed on return, so reading
	// only the status line (not the OPTIONS response headers) is sufficient.
	tp := textproto.NewReader(bufio.NewReader(conn))
	statusLine, err := tp.ReadLine()
	if err != nil {
		return fmt.Errorf("reading icap options status: %w", err)
	}
	code, err := icapStatusCode(statusLine)
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("icap OPTIONS returned status %d", code)
	}
	return nil
}
