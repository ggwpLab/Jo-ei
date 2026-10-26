package httpx_test

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
)

func TestPublicBaseResolver_Base(t *testing.T) {
	const proxy = "172.18.0.1:40000"
	const client = "10.0.0.5:1234"
	trusted := []string{"172.18.0.1"}

	tests := []struct {
		name      string
		publicURL string
		trusted   []string
		remote    string
		tls       bool
		host      string
		headers   map[string]string
		want      string
		wantErr   bool
	}{
		{name: "direct", remote: client, host: "joei:8080", want: "http://joei:8080"},
		{name: "direct TLS", remote: client, tls: true, host: "joei:8080", want: "https://joei:8080"},
		{name: "direct IPv6 host", remote: client, host: "[::1]:8080", want: "http://[::1]:8080"},
		{
			name: "untrusted peer headers ignored", trusted: trusted, remote: client, host: "joei:8080",
			headers: map[string]string{"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "https"},
			want:    "http://joei:8080",
		},
		{
			name: "trusted proto and host", trusted: trusted, remote: proxy, host: "joei:8080",
			headers: map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "registry.example.com"},
			want:    "https://registry.example.com",
		},
		{
			name: "trusted port added to bare host", trusted: trusted, remote: proxy, host: "joei:8080",
			headers: map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "registry.example.com", "X-Forwarded-Port": "8443"},
			want:    "https://registry.example.com:8443",
		},
		{
			name: "trusted port ignored when host has one", trusted: trusted, remote: proxy, host: "joei:8080",
			headers: map[string]string{"X-Forwarded-Host": "registry.example.com:9000", "X-Forwarded-Port": "8443"},
			want:    "http://registry.example.com:9000",
		},
		{
			name: "trusted prefix", trusted: trusted, remote: proxy, host: "joei:8080",
			headers: map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "registry.example.com", "X-Forwarded-Prefix": "/joei/"},
			want:    "https://registry.example.com/joei",
		},
		{
			name: "trusted host list takes the first entry", trusted: trusted, remote: proxy, host: "joei:8080",
			headers: map[string]string{"X-Forwarded-Host": "a.example, b.internal"},
			want:    "http://a.example",
		},
		{
			name: "trusted Forwarded header", trusted: trusted, remote: proxy, host: "joei:8080",
			headers: map[string]string{"Forwarded": `for=1.2.3.4;proto=https;host="reg.example"`},
			want:    "https://reg.example",
		},
		{
			name: "trusted proto only keeps Host", trusted: trusted, remote: proxy, host: "joei:8080",
			headers: map[string]string{"X-Forwarded-Proto": "https"},
			want:    "https://joei:8080",
		},
		{
			name: "public_url overrides headers", publicURL: "https://reg.example.com/joei/", trusted: trusted, remote: proxy, host: "joei:8080",
			headers: map[string]string{"X-Forwarded-Proto": "http", "X-Forwarded-Host": "other.example"},
			want:    "https://reg.example.com/joei",
		},
		{
			name: "bad proto", trusted: trusted, remote: proxy, host: "joei:8080",
			headers: map[string]string{"X-Forwarded-Proto": "gopher"},
			wantErr: true,
		},
		{
			name: "host with path", trusted: trusted, remote: proxy, host: "joei:8080",
			headers: map[string]string{"X-Forwarded-Host": "a.example/evil"},
			wantErr: true,
		},
		{
			name: "prefix without leading slash", trusted: trusted, remote: proxy, host: "joei:8080",
			headers: map[string]string{"X-Forwarded-Prefix": "joei"},
			wantErr: true,
		},
		{name: "bad direct Host", remote: client, host: "bad host", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peers, err := httpx.ParseTrustedPeers(tc.trusted)
			if err != nil {
				t.Fatal(err)
			}
			res, err := httpx.NewPublicBaseResolver(tc.publicURL, peers)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/npm/lodash", nil)
			r.RemoteAddr = tc.remote
			r.Host = tc.host
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			got, err := res.Base(r)
			if tc.wantErr {
				if !errors.Is(err, httpx.ErrBadForwardedHeader) {
					t.Fatalf("err = %v, want ErrBadForwardedHeader", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want {
				t.Fatalf("Base = %q, want %q", got.String(), tc.want)
			}
		})
	}
}

func TestPublicBaseResolver_NilActsDirect(t *testing.T) {
	var res *httpx.PublicBaseResolver
	r := httptest.NewRequest(http.MethodGet, "/npm/lodash", nil)
	r.Host = "joei:8080"
	r.Header.Set("X-Forwarded-Host", "evil.example")
	got, err := res.Base(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "http://joei:8080" {
		t.Fatalf("Base = %q", got.String())
	}
}

func TestNewPublicBaseResolver_RejectsBadURL(t *testing.T) {
	for _, u := range []string{"ftp://x", "not a url", "/relative", "https://x?q=1"} {
		if _, err := httpx.NewPublicBaseResolver(u, nil); err == nil {
			t.Errorf("NewPublicBaseResolver(%q) = nil error", u)
		}
	}
}

func TestParseTrustedPeers_RejectsJunk(t *testing.T) {
	if _, err := httpx.ParseTrustedPeers([]string{"10.0.0.0/8", "not-an-ip"}); err == nil {
		t.Fatal("want error")
	}
}
