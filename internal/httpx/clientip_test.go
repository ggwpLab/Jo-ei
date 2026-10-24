package httpx_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
)

func clientIPReq(remote, header, value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	if header != "" {
		r.Header.Set(header, value)
	}
	return r
}

func newResolver(t *testing.T, trusted []string, header string) *httpx.ClientIPResolver {
	t.Helper()
	c, err := httpx.NewClientIPResolver(trusted, header, zerolog.Nop())
	require.NoError(t, err)
	return c
}

func TestClientIP_UntrustedPeerIgnoresHeaders(t *testing.T) {
	c := newResolver(t, nil, "")
	r := clientIPReq("203.0.113.7:5555", httpx.HeaderXForwardedFor, "1.2.3.4")
	assert.Equal(t, "203.0.113.7", c.ClientIP(r))
}

func TestClientIP_TrustedPeerRightmostUntrusted(t *testing.T) {
	c := newResolver(t, []string{"10.0.0.0/8"}, "")
	r := clientIPReq("10.0.0.2:1", httpx.HeaderXForwardedFor, "6.6.6.6, 198.51.100.9, 10.0.0.5")
	assert.Equal(t, "198.51.100.9", c.ClientIP(r))
}

func TestClientIP_AllHopsTrustedTakesLeftmost(t *testing.T) {
	c := newResolver(t, []string{"10.0.0.0/8"}, "")
	r := clientIPReq("10.0.0.2:1", httpx.HeaderXForwardedFor, "10.0.0.9, 10.0.0.5")
	assert.Equal(t, "10.0.0.9", c.ClientIP(r))
}

func TestClientIP_XRealIP(t *testing.T) {
	c := newResolver(t, []string{"10.0.0.0/8"}, httpx.HeaderXRealIP)
	r := clientIPReq("10.0.0.2:1", httpx.HeaderXRealIP, "198.51.100.9")
	assert.Equal(t, "198.51.100.9", c.ClientIP(r))
}

func TestClientIP_Forwarded(t *testing.T) {
	c := newResolver(t, []string{"10.0.0.0/8"}, httpx.HeaderForwarded)
	r := clientIPReq("10.0.0.2:1", httpx.HeaderForwarded, `for=192.0.2.60;proto=https, for="[2001:db8::1]:4711"`)
	assert.Equal(t, "2001:db8::1", c.ClientIP(r))
}

func TestClientIP_MalformedFallsBackToPeer(t *testing.T) {
	c := newResolver(t, []string{"10.0.0.0/8"}, "")
	r := clientIPReq("10.0.0.2:1", httpx.HeaderXForwardedFor, "garbage")
	assert.Equal(t, "10.0.0.2", c.ClientIP(r))
}

func TestClientIP_WarnsOncePerProcess(t *testing.T) {
	var buf bytes.Buffer
	c, err := httpx.NewClientIPResolver(nil, "", zerolog.New(&buf))
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		c.ClientIP(clientIPReq("203.0.113.7:5555", httpx.HeaderXForwardedFor, "1.2.3.4"))
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], `"level":"warn"`)
	assert.Contains(t, lines[0], "server.trusted_proxies")
	assert.Contains(t, lines[0], `"peer":"203.0.113.7"`)
}

func TestNewClientIPResolver_Errors(t *testing.T) {
	_, err := httpx.NewClientIPResolver([]string{"not-an-ip"}, "", zerolog.Nop())
	assert.Error(t, err)
	_, err = httpx.NewClientIPResolver(nil, "X-Foo", zerolog.Nop())
	assert.Error(t, err)
}
