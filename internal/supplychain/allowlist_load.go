package supplychain

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadAllowlist reads an allowlist file and returns an *Allowlist.
// Each non-blank, non-comment line is one entry: "ecosystem/name" or
// "ecosystem/name@version". Lines beginning with '#' and blank lines are
// ignored; entries are whitespace-trimmed.
func LoadAllowlist(path string) (*Allowlist, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from operator config, not request input
	if err != nil {
		return nil, fmt.Errorf("opening allowlist %q: %w", path, err)
	}
	defer f.Close()

	var entries []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading allowlist %q: %w", path, err)
	}
	return NewAllowlist(entries), nil
}
