package adapters

import "strings"

// decodeGoPath reverses Go module case-encoding: a '!' followed by a lowercase
// ASCII letter becomes that letter uppercased (e.g. "!azure" -> "Azure"). Input
// without '!' is returned unchanged. A '!' that is trailing, or followed by any
// byte other than [a-z], is invalid and yields ("", false) — reject, never guess.
func decodeGoPath(s string) (string, bool) {
	if !strings.Contains(s, "!") {
		return s, true
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '!' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			return "", false
		}
		n := s[i+1]
		if n < 'a' || n > 'z' {
			return "", false
		}
		b.WriteByte(n - ('a' - 'A'))
		i++
	}
	return b.String(), true
}

// encodeGoPath applies Go module case-encoding: each uppercase ASCII letter
// becomes '!' followed by its lowercase form. It is the inverse of decodeGoPath.
func encodeGoPath(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteByte(c + ('a' - 'A'))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
