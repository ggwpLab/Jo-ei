package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// icapChunkSize is the size of each chunk streamed in the RESPMOD body.
const icapChunkSize = 8192

// ICAPScanner scans files via the ICAP RESPMOD method. It works with any ICAP
// AV server (Kaspersky, Dr.Web, ClamAV behind c-icap). Implements gate.AVScanner.
type ICAPScanner struct {
	network string
	addr    string
	service string
	timeout time.Duration
}

// NewICAPScanner creates a scanner for an ICAP server at address with the given
// service name. address is "unix:///path" or "tcp:host:port".
func NewICAPScanner(address, service string, timeout time.Duration) (*ICAPScanner, error) {
	network, addr, err := parseScannerAddress(address)
	if err != nil {
		return nil, err
	}
	if service == "" {
		return nil, fmt.Errorf("icap scanner requires a service name")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &ICAPScanner{network: network, addr: addr, service: service, timeout: timeout}, nil
}

// Scan implements gate.AVScanner using ICAP RESPMOD.
func (s *ICAPScanner) Scan(ctx context.Context, filePath string) (*gate.AVResult, error) {
	f, err := os.Open(filePath) // #nosec G304 -- scan target is the proxy's own just-downloaded temp file
	if err != nil {
		return nil, fmt.Errorf("opening artifact for scan: %w", err)
	}
	defer f.Close()

	dialer := net.Dialer{Timeout: s.timeout}
	conn, err := dialer.DialContext(ctx, s.network, s.addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to icap server: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(s.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if err := s.writeRespmod(conn, f); err != nil {
		return nil, err
	}
	return parseICAPResponse(bufio.NewReader(conn))
}

// writeRespmod sends a RESPMOD request encapsulating a minimal HTTP response
// whose chunked body is the artifact streamed from disk.
func (s *ICAPScanner) writeRespmod(conn net.Conn, f *os.File) error {
	const resHdr = "HTTP/1.1 200 OK\r\n\r\n"

	var hdr strings.Builder
	fmt.Fprintf(&hdr, "RESPMOD icap://%s/%s ICAP/1.0\r\n", s.addr, s.service)
	fmt.Fprintf(&hdr, "Host: %s\r\n", s.addr)
	hdr.WriteString("Allow: 204\r\n")
	fmt.Fprintf(&hdr, "Encapsulated: res-hdr=0, res-body=%d\r\n", len(resHdr))
	hdr.WriteString("\r\n")
	hdr.WriteString(resHdr)

	if _, err := conn.Write([]byte(hdr.String())); err != nil {
		return fmt.Errorf("sending icap request: %w", err)
	}

	buf := make([]byte, icapChunkSize)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if _, err := fmt.Fprintf(conn, "%x\r\n", n); err != nil {
				return fmt.Errorf("sending chunk size: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return fmt.Errorf("sending chunk data: %w", err)
			}
			if _, err := conn.Write([]byte("\r\n")); err != nil {
				return fmt.Errorf("sending chunk crlf: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("reading artifact: %w", readErr)
		}
	}
	if _, err := conn.Write([]byte("0\r\n\r\n")); err != nil {
		return fmt.Errorf("sending final chunk: %w", err)
	}
	return nil
}

// parseICAPResponse interprets an ICAP reply. With "Allow: 204" sent, a clean
// object yields 204 No Content; a 200 OK means the server modified/flagged the
// object (treated as infected, signature read from vendor headers).
func parseICAPResponse(r *bufio.Reader) (*gate.AVResult, error) {
	tp := textproto.NewReader(r)
	statusLine, err := tp.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("reading icap status line: %w", err)
	}
	code, err := icapStatusCode(statusLine)
	if err != nil {
		return nil, err
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("reading icap headers: %w", err)
	}

	switch code {
	case 204:
		return &gate.AVResult{Clean: true, Engine: "icap"}, nil
	case 200:
		sig := infectionSignature(hdr)
		if sig == "" {
			sig = "icap.infected"
		}
		return &gate.AVResult{Clean: false, Signature: sig, Engine: "icap"}, nil
	default:
		return nil, fmt.Errorf("icap server returned status %d", code)
	}
}

// icapStatusCode parses the numeric code from "ICAP/1.0 204 No Content".
func icapStatusCode(statusLine string) (int, error) {
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "ICAP/") {
		return 0, fmt.Errorf("malformed icap status line %q", statusLine)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("malformed icap status code in %q", statusLine)
	}
	return code, nil
}

// infectionSignature extracts a threat name from the vendor-specific headers
// used by Kaspersky (X-Virus-ID) and Dr.Web / generic servers (X-Infection-Found,
// X-Violations-Found).
func infectionSignature(hdr textproto.MIMEHeader) string {
	if v := hdr.Get("X-Virus-ID"); v != "" {
		return v
	}
	if v := hdr.Get("X-Infection-Found"); v != "" {
		if t := threatFromInfectionHeader(v); t != "" {
			return t
		}
		return v
	}
	if v := hdr.Get("X-Violations-Found"); v != "" {
		return v
	}
	return ""
}

// threatFromInfectionHeader pulls the "Threat=...;" value out of an
// X-Infection-Found header like "Type=0; Resolution=2; Threat=EICAR Test File;".
func threatFromInfectionHeader(v string) string {
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if rest, ok := strings.CutPrefix(part, "Threat="); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
