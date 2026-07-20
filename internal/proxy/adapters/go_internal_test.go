package adapters

import "testing"

func TestDecodeGoPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"github.com/stretchr/testify", "github.com/stretchr/testify", true},
		{"github.com/!azure/azure-sdk-for-go", "github.com/Azure/azure-sdk-for-go", true},
		{"!cover", "Cover", true},
		{"v2.0.0+incompatible", "v2.0.0+incompatible", true},
		{"v0.0.0-20200101000000-abcdef123456", "v0.0.0-20200101000000-abcdef123456", true},
		{"bad!", "", false},  // trailing '!'
		{"bad!A", "", false}, // '!' + non-lowercase
		{"bad!1", "", false}, // '!' + digit
	}
	for _, c := range cases {
		got, ok := decodeGoPath(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("decodeGoPath(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestEncodeGoPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"github.com/stretchr/testify", "github.com/stretchr/testify"},
		{"github.com/Azure/azure-sdk-for-go", "github.com/!azure/azure-sdk-for-go"},
		{"Cover", "!cover"},
	}
	for _, c := range cases {
		if got := encodeGoPath(c.in); got != c.want {
			t.Errorf("encodeGoPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGoPathRoundTrip(t *testing.T) {
	for _, s := range []string{"github.com/Azure/Go-Foo", "example.com/ABC/def", "plain/path"} {
		enc := encodeGoPath(s)
		dec, ok := decodeGoPath(enc)
		if !ok || dec != s {
			t.Errorf("round-trip %q -> %q -> (%q, %v)", s, enc, dec, ok)
		}
	}
}
