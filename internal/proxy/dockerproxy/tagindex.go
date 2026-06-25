package dockerproxy

import (
	"encoding/json"
	"strings"
	"sync"
)

// tagIndex maps a resolved platform manifest digest back to the human tag a
// client originally requested. A multi-arch pull asks for repo:tag (an index,
// served un-gated and not recorded) and then fetches the platform child
// manifest by digest (gated and recorded). Without this map the recorded feed
// entry would show the opaque child digest instead of the tag.
//
// The map is a best-effort display hint: it is in-memory, bounded, and lost on
// restart. When an entry is missing (overflow eviction, restart, or a direct
// by-digest pull), callers fall back to the digest. It is safe for concurrent
// use.
type tagIndex struct {
	mu      sync.Mutex
	max     int
	entries map[string]string // "repo@digest" → tag
	order   []string          // insertion order, for FIFO eviction
}

// defaultTagIndexMax bounds the number of remembered digest→tag entries.
const defaultTagIndexMax = 4096

func newTagIndex(max int) *tagIndex {
	if max <= 0 {
		max = defaultTagIndexMax
	}
	return &tagIndex{max: max, entries: make(map[string]string)}
}

func tagIndexKey(repo, digest string) string { return repo + "@" + digest }

// isDigestRef reports whether ref is a content digest ("algo:hex") rather than a
// tag. Registry tags cannot contain ":", so its presence marks a digest.
func isDigestRef(ref string) bool { return strings.Contains(ref, ":") }

// rememberChildren parses a multi-arch index body and maps every child manifest
// digest to tag (scoped by repo), so a later by-digest pull of any platform
// child can recover the originating tag.
func (ti *tagIndex) rememberChildren(repo, tag string, indexBody []byte) {
	var idx struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexBody, &idx); err != nil {
		return
	}
	ti.mu.Lock()
	defer ti.mu.Unlock()
	for _, m := range idx.Manifests {
		if m.Digest != "" {
			ti.put(tagIndexKey(repo, m.Digest), tag)
		}
	}
}

// put inserts or refreshes key→tag, evicting the oldest entry on overflow.
func (ti *tagIndex) put(key, tag string) {
	if _, ok := ti.entries[key]; !ok {
		if ti.max > 0 && len(ti.order) >= ti.max {
			oldest := ti.order[0]
			ti.order = ti.order[1:]
			delete(ti.entries, oldest)
		}
		ti.order = append(ti.order, key)
	}
	ti.entries[key] = tag
}

// tag returns the remembered tag for repo@digest, if any.
func (ti *tagIndex) tag(repo, digest string) (string, bool) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	t, ok := ti.entries[tagIndexKey(repo, digest)]
	return t, ok
}
