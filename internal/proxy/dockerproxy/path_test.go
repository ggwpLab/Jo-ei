package dockerproxy

import "testing"

func TestParsePath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want ParsedPath
	}{
		{"ping root", "/", ParsedPath{Kind: KindPing}},
		{"ping empty", "", ParsedPath{Kind: KindPing}},
		{"manifest by tag", "/library/nginx/manifests/latest",
			ParsedPath{Kind: KindManifest, Repo: "library/nginx", Reference: "latest"}},
		{"manifest by digest", "/library/nginx/manifests/sha256:abc",
			ParsedPath{Kind: KindManifest, Repo: "library/nginx", Reference: "sha256:abc"}},
		{"nested repo manifest", "/a/b/c/manifests/v1",
			ParsedPath{Kind: KindManifest, Repo: "a/b/c", Reference: "v1"}},
		{"blob", "/library/nginx/blobs/sha256:def",
			ParsedPath{Kind: KindBlob, Repo: "library/nginx", Reference: "sha256:def"}},
		{"tag list", "/library/nginx/tags/list",
			ParsedPath{Kind: KindTagList, Repo: "library/nginx"}},
		{"unknown", "/library/nginx/whatever", ParsedPath{Kind: KindUnknown}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParsePath(tt.in)
			if got != tt.want {
				t.Errorf("ParsePath(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}
