package adapters

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// pypiJSONAPIRe matches the legacy JSON API: /pypi/<project>/json and
// /pypi/<project>/<version>/json, with or without a trailing slash.
var pypiJSONAPIRe = regexp.MustCompile(`^/pypi/[^/]+(/[^/]+)?/json/?$`)

// IsIndexRequest implements gate.IndexRewriter: simple-index pages (PEP 503
// HTML or PEP 691 JSON) and the JSON API.
func (a *PyPIAdapter) IsIndexRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/simple/") || pypiJSONAPIRe.MatchString(r.URL.Path)
}

// RewriteIndex implements gate.IndexRewriter. A link survives only if it
// positively resolves to a /packages/ path, and is then served as a relative
// link to the proxy's own /packages/ route, so the download goes through the
// gates. Every other link — another host, another path, or anything this
// proxy might parse differently from pip or uv — is removed: the safe failure
// is a file the client cannot see, never one it fetches around the proxy.
func (a *PyPIAdapter) RewriteIndex(doc []byte, contentType, requestPath string) (gate.IndexRewrite, error) {
	rw := &linkRewriter{
		prefix: strings.Repeat("../", dirDepth(requestPath)),
		base:   &url.URL{Scheme: "http", Host: proxyHost, Path: requestPath},
	}
	var (
		body []byte
		err  error
	)
	switch kind, kerr := indexKind(contentType, requestPath); {
	case kerr != nil:
		return gate.IndexRewrite{}, kerr
	case kind == kindJSONAPI:
		body, err = rw.jsonAPI(doc)
	case kind == kindJSONSimple:
		body, err = rw.jsonSimple(doc)
	default:
		body, err = rw.html(doc)
	}
	if err != nil {
		return gate.IndexRewrite{}, err
	}
	return gate.IndexRewrite{Body: body, Rewritten: rw.rewritten, Dropped: rw.dropped}, nil
}

type docKind int

const (
	kindHTML docKind = iota
	kindJSONSimple
	kindJSONAPI
)

// indexKind picks the parser. The media type is compared case-insensitively,
// as pip does; a type that is neither HTML nor JSON cannot be rewritten with
// confidence, so it is an error rather than a guess.
func indexKind(contentType, requestPath string) (docKind, error) {
	if pypiJSONAPIRe.MatchString(requestPath) {
		return kindJSONAPI, nil
	}
	mt := ""
	if contentType != "" {
		parsed, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return 0, fmt.Errorf("parsing index content type %q: %w", contentType, err)
		}
		mt = strings.ToLower(parsed)
	}
	switch {
	case mt == "" || mt == "text/html" || mt == "application/vnd.pypi.simple.v1+html":
		return kindHTML, nil
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		return kindJSONSimple, nil
	default:
		return 0, fmt.Errorf("unexpected index content type %q", contentType)
	}
}

// proxyHost is the placeholder origin relative links are resolved against;
// a link that resolves to it was relative in the document.
const proxyHost = "proxy.joei.invalid"

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
	prefix    string   // "../" steps back to the registry root
	base      *url.URL // the document's own URL, for resolving relative links
	rewritten int
	dropped   []string
}

// normalizeLink applies the clean-up URL parsers do before parsing (urllib and
// WHATWG alike): leading/trailing C0 controls and spaces are trimmed, tab/CR/LF
// are deleted anywhere, and a backslash counts as a slash. Mapping the
// normalised form means the proxy sees the same URL the client will.
func normalizeLink(raw string) string {
	s := strings.TrimFunc(raw, func(r rune) bool { return r <= ' ' })
	s = strings.NewReplacer("\t", "", "\r", "", "\n", "", `\`, "/").Replace(s)
	return s
}

// mapLink returns the link to serve and whether to keep it.
func (l *linkRewriter) mapLink(raw string) (string, bool) {
	mapped, ok := l.resolve(raw)
	if !ok {
		l.dropped = append(l.dropped, raw)
		return "", false
	}
	if mapped != raw {
		l.rewritten++
	}
	return mapped, true
}

// resolve maps one link to its proxy-relative form, or reports false.
func (l *linkRewriter) resolve(raw string) (string, bool) {
	norm := normalizeLink(raw)
	u, err := url.Parse(norm)
	if err != nil || u.Opaque != "" || u.User != nil {
		return "", false
	}
	if u.Scheme != "" {
		// An absolute link must spell out "scheme://host": "https:/x" and
		// "https:x" have no host to Go but do to a WHATWG parser.
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
			!strings.HasPrefix(strings.ToLower(norm), u.Scheme+"://") {
			return "", false
		}
	}
	abs := l.base.ResolveReference(u)
	clean := path.Clean(abs.Path)
	if !strings.HasPrefix(clean, "/packages/") {
		return "", false
	}
	out := l.prefix + strings.TrimPrefix((&url.URL{Path: clean}).EscapedPath(), "/")
	if abs.RawQuery != "" {
		out += "?" + abs.RawQuery
	}
	if abs.Fragment != "" {
		out += "#" + abs.EscapedFragment()
	}
	return out, true
}

// html rewrites a PEP 503 page token by token. Every href on an <a> start tag
// is mapped (pip honours the last of duplicates, so all of them must pass);
// an anchor with any unmappable href is dropped, and <base> — which would
// re-root relative links — is removed. Everything else is copied byte for
// byte.
func (l *linkRewriter) html(doc []byte) ([]byte, error) {
	z := html.NewTokenizer(bytes.NewReader(doc))
	var out bytes.Buffer
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if errors.Is(z.Err(), io.EOF) {
				return out.Bytes(), nil
			}
			return nil, fmt.Errorf("tokenizing index: %w", z.Err())
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			out.Write(z.Raw())
			continue
		}
		raw := append([]byte(nil), z.Raw()...)
		tok := z.Token()
		switch tok.Data {
		case "base":
			continue
		case "a":
			keep := true
			for i, attr := range tok.Attr {
				if attr.Namespace != "" || attr.Key != "href" {
					continue
				}
				mapped, ok := l.mapLink(attr.Val)
				if !ok {
					keep = false
					continue
				}
				tok.Attr[i].Val = mapped
			}
			// Always re-rendered, never copied raw: the tokenizer keeps the
			// first of duplicate attributes (as browsers do) while pip keeps
			// the last, so only a re-rendered tag is guaranteed to carry the
			// one href that was checked. A dropped anchor's text and </a>
			// stay; without an href they link nowhere.
			if keep {
				out.WriteString(tok.String())
			}
		default:
			out.Write(raw)
		}
	}
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
