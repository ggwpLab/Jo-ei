package adapters

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// pypiJSONAPIRe matches the legacy JSON API: /pypi/<project>/json and
// /pypi/<project>/<version>/json.
var pypiJSONAPIRe = regexp.MustCompile(`^/pypi/[^/]+(/[^/]+)?/json$`)

// IsIndexRequest implements gate.IndexRewriter: simple-index pages (PEP 503
// HTML or PEP 691 JSON) and the JSON API.
func (a *PyPIAdapter) IsIndexRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/simple/") || pypiJSONAPIRe.MatchString(r.URL.Path)
}

// RewriteIndex implements gate.IndexRewriter. Every absolute link to a
// /packages/ path becomes a relative link to the proxy's own /packages/ route,
// so the download goes through the gates; any other absolute link is removed,
// since following it would bypass them. Relative links already resolve
// against the proxy and are left alone.
func (a *PyPIAdapter) RewriteIndex(doc []byte, contentType, requestPath string) (gate.IndexRewrite, error) {
	rw := &linkRewriter{prefix: strings.Repeat("../", dirDepth(requestPath))}
	var (
		body []byte
		err  error
	)
	switch {
	case pypiJSONAPIRe.MatchString(requestPath):
		body, err = rw.jsonAPI(doc)
	case strings.Contains(contentType, "vnd.pypi.simple") && strings.Contains(contentType, "json"):
		body, err = rw.jsonSimple(doc)
	default:
		body = rw.html(doc)
	}
	if err != nil {
		return gate.IndexRewrite{}, err
	}
	return gate.IndexRewrite{Body: body, Rewritten: rw.rewritten, Dropped: rw.dropped}, nil
}

// dirDepth counts the path segments of requestPath's directory: the number of
// "../" steps from the document back to the registry root.
func dirDepth(requestPath string) int {
	dir := requestPath
	if !strings.HasSuffix(dir, "/") {
		dir = dir[:strings.LastIndex(dir, "/")+1]
	}
	trimmed := strings.Trim(dir, "/")
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "/") + 1
}

// linkRewriter maps links for one document and tallies the outcome.
type linkRewriter struct {
	prefix    string // "../" steps back to the registry root
	rewritten int
	dropped   []string
}

// mapLink returns the link to serve and whether to keep it. raw is the link as
// it appears in the document (unescaped).
func (l *linkRewriter) mapLink(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, true // relative (or not a URL at all): resolves against the proxy
	}
	if !strings.HasPrefix(u.Path, "/packages/") {
		l.dropped = append(l.dropped, raw)
		return "", false
	}
	// Keep everything from /packages/ on verbatim — query and the #sha256=
	// fragment pip verifies included.
	rest := raw[strings.Index(raw, "/packages/")+1:]
	l.rewritten++
	return l.prefix + rest, true
}

var (
	anchorRe = regexp.MustCompile(`(?is)<a\b[^>]*>.*?</a>`)
	hrefRe   = regexp.MustCompile(`(?is)(\bhref\s*=\s*)("([^"]*)"|'([^']*)')`)
	baseRe   = regexp.MustCompile(`(?is)<base\b[^>]*>`)
)

// html rewrites a PEP 503 page. A <base> element would re-root every relative
// link, so it is removed.
func (l *linkRewriter) html(doc []byte) []byte {
	doc = baseRe.ReplaceAll(doc, nil)
	return anchorRe.ReplaceAllFunc(doc, func(anchor []byte) []byte {
		m := hrefRe.FindSubmatchIndex(anchor)
		if m == nil {
			return anchor
		}
		quoted := string(anchor[m[4]:m[5]])
		raw := quoted[1 : len(quoted)-1]
		mapped, keep := l.mapLink(html.UnescapeString(raw))
		if !keep {
			return nil
		}
		if mapped == html.UnescapeString(raw) {
			return anchor
		}
		var b strings.Builder
		b.Write(anchor[:m[2]])
		b.Write(anchor[m[2]:m[3]]) // "href="
		b.WriteString(`"` + html.EscapeString(mapped) + `"`)
		b.Write(anchor[m[5]:])
		return []byte(b.String())
	})
}

// jsonSimple rewrites a PEP 691 project page: files[].url.
func (l *linkRewriter) jsonSimple(doc []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return nil, fmt.Errorf("decoding simple index: %w", err)
	}
	if raw, ok := top["files"]; ok {
		files, err := l.fileList(raw)
		if err != nil {
			return nil, fmt.Errorf("decoding simple index files: %w", err)
		}
		top["files"] = files
	}
	return json.Marshal(top)
}

// jsonAPI rewrites a JSON API document: urls[].url and releases[*][].url.
func (l *linkRewriter) jsonAPI(doc []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return nil, fmt.Errorf("decoding json api document: %w", err)
	}
	if raw, ok := top["urls"]; ok {
		urls, err := l.fileList(raw)
		if err != nil {
			return nil, fmt.Errorf("decoding json api urls: %w", err)
		}
		top["urls"] = urls
	}
	if raw, ok := top["releases"]; ok {
		var releases map[string]json.RawMessage
		if err := json.Unmarshal(raw, &releases); err != nil {
			return nil, fmt.Errorf("decoding json api releases: %w", err)
		}
		for v, files := range releases {
			out, err := l.fileList(files)
			if err != nil {
				return nil, fmt.Errorf("decoding json api release %q: %w", v, err)
			}
			releases[v] = out
		}
		b, err := json.Marshal(releases)
		if err != nil {
			return nil, err
		}
		top["releases"] = b
	}
	return json.Marshal(top)
}

// fileList rewrites the "url" of every object in a JSON array of file
// entries, dropping the entries whose link cannot be pointed at the proxy.
func (l *linkRewriter) fileList(raw json.RawMessage) (json.RawMessage, error) {
	var files []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, err
	}
	kept := files[:0]
	for _, f := range files {
		rawURL, ok := f["url"]
		if !ok {
			kept = append(kept, f)
			continue
		}
		var link string
		if err := json.Unmarshal(rawURL, &link); err != nil {
			return nil, fmt.Errorf("file url: %w", err)
		}
		mapped, keep := l.mapLink(link)
		if !keep {
			continue
		}
		if mapped != link {
			b, err := json.Marshal(mapped)
			if err != nil {
				return nil, err
			}
			f["url"] = b
		}
		kept = append(kept, f)
	}
	return json.Marshal(kept)
}
