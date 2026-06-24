package dockerproxy

import "strings"

// RequestKind classifies a Docker Registry V2 request.
type RequestKind int

const (
	KindUnknown  RequestKind = iota
	KindPing                 // GET /v2/
	KindManifest             // GET|HEAD /v2/<repo>/manifests/<ref>
	KindBlob                 // GET /v2/<repo>/blobs/<digest>
	KindTagList              // GET /v2/<repo>/tags/list
)

// ParsedPath is the result of classifying a V2 path (with the /v2 mux prefix
// already stripped). Repo may contain slashes; Reference is a tag or digest.
type ParsedPath struct {
	Kind      RequestKind
	Repo      string
	Reference string
}

// ParsePath classifies a Docker Registry V2 path. The input is the path after
// the mux has stripped the "/v2" prefix (e.g. "/library/nginx/manifests/latest"
// or "/" for the ping endpoint).
func ParsePath(p string) ParsedPath {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return ParsedPath{Kind: KindPing}
	}
	// Split off the trailing "<verb>/<ref>" (manifests/blobs) or "tags/list".
	if repo, ref, ok := splitRepoVerb(trimmed, "manifests"); ok {
		return ParsedPath{Kind: KindManifest, Repo: repo, Reference: ref}
	}
	if repo, ref, ok := splitRepoVerb(trimmed, "blobs"); ok {
		return ParsedPath{Kind: KindBlob, Repo: repo, Reference: ref}
	}
	if strings.HasSuffix(trimmed, "/tags/list") {
		repo := strings.TrimSuffix(trimmed, "/tags/list")
		return ParsedPath{Kind: KindTagList, Repo: repo}
	}
	return ParsedPath{Kind: KindUnknown}
}

// splitRepoVerb finds the LAST "/<verb>/" separator so multi-segment repos
// (e.g. "a/b/c") are preserved. Returns (repo, reference, true) on match.
func splitRepoVerb(path, verb string) (string, string, bool) {
	sep := "/" + verb + "/"
	idx := strings.LastIndex(path, sep)
	if idx < 0 {
		return "", "", false
	}
	repo := path[:idx]
	ref := path[idx+len(sep):]
	if repo == "" || ref == "" || strings.Contains(ref, "/") {
		return "", "", false
	}
	return repo, ref, true
}
