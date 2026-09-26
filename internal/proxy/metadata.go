package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// syntheticETagPrefix marks an ETag this proxy minted for a rewritten metadata
// document. A client revalidating with such a tag must be served from a freshly
// filtered document: forwarding its If-None-Match upstream would earn a 304 with
// no body to filter, pinning the client to a stale rewrite forever.
const syntheticETagPrefix = `"joei.`

// syntheticETag mints a strong validator for a rewritten document. The value
// hashes the rewritten body, so a client whose filtering has not changed
// revalidates as 304 and the slow path still costs the client hop nothing.
func syntheticETag(body []byte) string {
	sum := sha256.Sum256(body)
	return syntheticETagPrefix + hex.EncodeToString(sum[:8]) + `"`
}

// holdsSyntheticETag reports whether an If-None-Match header carries a tag this
// proxy minted. The header is a list, and one of ours anywhere in it means the
// client is holding a rewritten document. "*" is not ours: it asks about any
// representation at all, which upstream can answer.
func holdsSyntheticETag(ifNoneMatch string) bool {
	for _, tag := range strings.Split(ifNoneMatch, ",") {
		if strings.HasPrefix(strings.TrimSpace(tag), syntheticETagPrefix) {
			return true
		}
	}
	return false
}
