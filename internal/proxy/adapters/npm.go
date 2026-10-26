package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

// npmLicense decodes npm's polymorphic "license" field. Modern packages use a
// string (an SPDX expression, e.g. "ISC"); legacy/historical versions use an
// object {"type":"MIT","url":"..."} or other shapes. The value is purely
// informational (no policy decision reads it), and FetchMetadata decodes every
// version in the document, so decoding must never fail the whole response — an
// unrecognized shape yields an empty license.
type npmLicense string

func (l *npmLicense) UnmarshalJSON(data []byte) error {
	// Modern form: a plain string (also handles JSON null → "").
	var s string
	if json.Unmarshal(data, &s) == nil {
		*l = npmLicense(s)
		return nil
	}
	// Legacy object form: {"type":"MIT","url":"..."}.
	var obj struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &obj) == nil {
		*l = npmLicense(obj.Type)
		return nil
	}
	// Anything else (e.g. an array of license objects): drop it, do not error.
	*l = ""
	return nil
}

// npmMetadata is the subset of the npm registry document we consume.
type npmMetadata struct {
	Time     map[string]string `json:"time"`
	Versions map[string]struct {
		License npmLicense `json:"license"`
	} `json:"versions"`
}

// NPMAdapter implements gate.RegistryAdapter for the npm registry.
type NPMAdapter struct {
	upstreams  []string
	httpClient *http.Client
}

// Compile-time proof that npm supports metadata filtering; the handler
// type-asserts this capability rather than requiring it of every adapter.
var _ gate.MetadataFilterer = (*NPMAdapter)(nil)

// NewNPMAdapter creates an npm adapter over the given ordered upstream URLs.
func NewNPMAdapter(upstreams []string, opts ...Option) *NPMAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &NPMAdapter{
		upstreams:  trimmed,
		httpClient: resolveClient(opts),
	}
}

func (a *NPMAdapter) Name() string { return "npm" }

// NormalizeRequest intercepts tarball downloads (path contains "/-/" and ends ".tgz").
// Metadata documents (e.g. "/lodash") are proxied transparently.
func (a *NPMAdapter) NormalizeRequest(r *http.Request) (*gate.PackageRef, bool) {
	path := r.URL.Path
	if !strings.HasSuffix(path, ".tgz") {
		return nil, false
	}
	idx := strings.Index(path, "/-/")
	if idx == -1 {
		return nil, false
	}
	name := strings.TrimPrefix(path[:idx], "/")
	filename := path[idx+len("/-/"):]
	version, ok := parseNPMVersion(name, filename)
	if !ok {
		return nil, false
	}
	return &gate.PackageRef{Ecosystem: "npm", Name: name, Version: version}, true
}

// IsArtifactPath implements gate.ArtifactPathMatcher: a tarball is any ".tgz"
// under a "/-/" segment, whether or not NormalizeRequest can read the version
// out of its file name.
func (a *NPMAdapter) IsArtifactPath(r *http.Request) bool {
	return strings.HasSuffix(r.URL.Path, ".tgz") && strings.Contains(r.URL.Path, "/-/")
}

// parseNPMVersion extracts the version from a tarball filename "<unscoped>-<version>.tgz".
func parseNPMVersion(name, filename string) (string, bool) {
	base := strings.TrimSuffix(filename, ".tgz")
	unscoped := name
	if idx := strings.LastIndex(name, "/"); idx != -1 {
		unscoped = name[idx+1:]
	}
	prefix := unscoped + "-"
	if !strings.HasPrefix(base, prefix) {
		return "", false
	}
	version := strings.TrimPrefix(base, prefix)
	if version == "" {
		return "", false
	}
	return version, true
}

// FetchMetadata walks the configured upstreams in order, returning the first
// success. When every upstream fails, the returned error is an
// upstream.Attempts carrying each mirror's own outcome.
func (a *NPMAdapter) FetchMetadata(ctx context.Context, ref *gate.PackageRef) (*gate.PackageMetadata, error) {
	if len(a.upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured for npm")
	}
	var atts upstream.Attempts
	for _, base := range a.upstreams {
		start := time.Now()
		meta, url, status, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		atts.Add(url, status, err, time.Since(start))
	}
	return nil, atts
}

func (a *NPMAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *gate.PackageRef) (*gate.PackageMetadata, string, int, error) {
	apiURL := base + "/" + ref.Name

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, apiURL, 0, fmt.Errorf("building npm metadata request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, apiURL, 0, fmt.Errorf("fetching npm metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiURL, resp.StatusCode, fmt.Errorf("npm returned HTTP %d for %s", resp.StatusCode, ref.Name)
	}

	var doc npmMetadata
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, apiURL, resp.StatusCode, fmt.Errorf("decoding npm response: %w", err)
	}
	publishedStr, ok := doc.Time[ref.Version]
	if !ok {
		return nil, apiURL, resp.StatusCode, fmt.Errorf("version %s not found in npm metadata for %s", ref.Version, ref.Name)
	}
	publishedAt, err := time.Parse(time.RFC3339, publishedStr)
	if err != nil {
		return nil, apiURL, resp.StatusCode, fmt.Errorf("parsing npm publish time %q: %w", publishedStr, err)
	}
	versionInfo, ok := doc.Versions[ref.Version]
	if !ok {
		return nil, apiURL, resp.StatusCode, fmt.Errorf("version %s missing from npm versions map for %s", ref.Version, ref.Name)
	}
	return &gate.PackageMetadata{
		PublishedAt: publishedAt.UTC(),
		License:     string(versionInfo.License),
	}, apiURL, resp.StatusCode, nil
}

// UpstreamURLs returns one candidate URL per configured upstream, in order.
func (a *NPMAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}

// NormalizeMetadataRequest reports whether r asks for an npm metadata document:
// a packument ("/left-pad", "/@types/node"), the per-package document npm
// resolves version ranges from, or a single-version manifest
// ("/left-pad/1.3.0", "/left-pad/latest"). Both link tarballs by absolute URL,
// so both are rewritten. Registry service endpoints live under "/-/" and are
// proxied untouched.
func (a *NPMAdapter) NormalizeMetadataRequest(r *http.Request) (*gate.MetadataRef, bool) {
	if r.Method != http.MethodGet {
		return nil, false
	}
	// "?write=true" marks the read half of npm's read-modify-write cycle
	// (`npm deprecate`, `npm owner`), whose PUT sends the whole document back.
	// Rewriting this GET would carry hidden versions and proxy links into that
	// PUT, so it passes through untouched. Any other query is an ordinary read
	// and is rewritten like one.
	if r.URL.Query().Has("write") {
		return nil, false
	}
	// URL.Path arrives percent-decoded, so npm's two spellings of a scoped name
	// — "/@types%2fnode" and "/@types/node" — are the same string here. A
	// trailing slash names the same document.
	path := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/")
	name, version, ok := splitNPMMetadataPath(path)
	if !ok {
		return nil, false
	}
	return &gate.MetadataRef{Ecosystem: "npm", Name: name, Version: version}, true
}

// splitNPMMetadataPath splits "left-pad", "left-pad/1.3.0", "@types/node" or
// "@types/node/20.0.0" into a package name and an optional version or tag. A
// leading "-" segment is a registry service endpoint, and anything deeper is a
// tarball or an unknown route.
func splitNPMMetadataPath(s string) (name, version string, ok bool) {
	if s == "" {
		return "", "", false
	}
	parts := strings.Split(s, "/")
	if parts[0] == "-" {
		return "", "", false
	}
	nameParts := 1
	if strings.HasPrefix(s, "@") {
		if len(parts) < 2 || len(parts[0]) < 2 || parts[1] == "" {
			return "", "", false
		}
		nameParts = 2
	}
	switch len(parts) - nameParts {
	case 0:
		return s, "", true
	case 1:
		if parts[nameParts] == "" || parts[nameParts] == "-" {
			return "", "", false
		}
		return strings.Join(parts[:nameParts], "/"), parts[nameParts], true
	default:
		return "", "", false
	}
}

// npmVersionRe bounds the characters a version may carry into a tarball path:
// semver's alphabet, nothing that could add a path segment or a query.
var npmVersionRe = regexp.MustCompile(`^[0-9A-Za-z.+_-]+$`)

// npmTarballURL builds the canonical tarball link for one version under
// linkBase. ok is false when the version cannot form a path NormalizeRequest
// resolves back to the same package and version.
func npmTarballURL(linkBase, name, version string) (string, bool) {
	if !npmVersionRe.MatchString(version) {
		return "", false
	}
	unscoped := name
	if idx := strings.LastIndex(name, "/"); idx != -1 {
		unscoped = name[idx+1:]
	}
	filename := unscoped + "-" + version + ".tgz"
	if v, ok := parseNPMVersion(name, filename); !ok || v != version {
		return "", false
	}
	return linkBase + "/" + name + "/-/" + filename, true
}

// errNoTarballLink reports that a version object has no dist.tarball, so there
// is nothing to rewrite in it.
var errNoTarballLink = errors.New("no dist.tarball")

// rewriteNPMTarball points one version object's dist.tarball at linkBase. A
// version without a dist.tarball is returned unchanged with errNoTarballLink;
// any other error means the link cannot be routed through the proxy.
func rewriteNPMTarball(raw json.RawMessage, linkBase, name, version string) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("decoding version %s: %w", version, err)
	}
	var dist map[string]json.RawMessage
	if rawDist, ok := obj["dist"]; ok {
		if err := json.Unmarshal(rawDist, &dist); err != nil {
			return nil, fmt.Errorf("decoding dist of version %s: %w", version, err)
		}
	}
	if _, ok := dist["tarball"]; !ok {
		return raw, errNoTarballLink
	}
	link, ok := npmTarballURL(linkBase, name, version)
	if !ok {
		return nil, fmt.Errorf("version %q cannot form a tarball path", version)
	}
	encodedLink, err := json.Marshal(link)
	if err != nil {
		return nil, err
	}
	dist["tarball"] = encodedLink
	if obj["dist"], err = json.Marshal(dist); err != nil {
		return nil, err
	}
	return json.Marshal(obj)
}

// FilterVersions implements gate.MetadataFilterer. For a packument it drops
// every version decide rejects, along with that version's "time" entry, and
// points every remaining dist.tarball at linkBase in the canonical
// "<name>/-/<unscoped>-<version>.tgz" shape, whatever shape the upstream used.
// A version whose link cannot take that shape is dropped too: a version the
// client cannot see is the safe failure, one it downloads around the proxy is
// not. Unknown fields survive because the document is decoded one level deep,
// as raw JSON. dist-tags are deliberately left alone: npm tolerates a tag
// naming a version that is no longer listed and falls back to the highest one
// that is, which spares this project a semver comparator.
//
// A single-version manifest (ref.Version set) only has its link rewritten; the
// artifact gate rules on the download.
func (a *NPMAdapter) FilterVersions(doc []byte, ref *gate.MetadataRef, decide gate.VersionDecider, linkBase string) (gate.FilteredDocument, error) {
	if ref.Version != "" {
		return rewriteNPMManifest(doc, ref.Name, linkBase)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("decoding npm packument: %w", err)
	}
	rawVersions, ok := top["versions"]
	if !ok {
		return gate.FilteredDocument{Body: doc}, nil
	}
	var versions map[string]json.RawMessage
	if err := json.Unmarshal(rawVersions, &versions); err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("decoding npm packument versions: %w", err)
	}
	total := len(versions)

	var unmappable []string
	for version, raw := range versions {
		rewritten, err := rewriteNPMTarball(raw, linkBase, ref.Name, version)
		switch {
		case errors.Is(err, errNoTarballLink):
		case err != nil:
			unmappable = append(unmappable, version)
			delete(versions, version)
		default:
			versions[version] = rewritten
		}
	}
	if total > 0 && len(versions) == 0 {
		return gate.FilteredDocument{}, gate.ErrNoServableVersions
	}
	sort.Strings(unmappable)

	published := npmPublishDates(top["time"])
	var removed []string
	for version := range versions {
		if !decide(version, published[version]) {
			removed = append(removed, version)
		}
	}
	sort.Strings(removed)
	allRejected := len(removed) > 0 && len(removed) == len(versions)
	if !allRejected {
		// Serving an empty version list would turn every install of this
		// package into a resolution error, so when policy rejects everything
		// the versions stay and the artifact gate states the real reason at
		// download time.
		for _, v := range removed {
			delete(versions, v)
		}
	}

	encodedVersions, err := json.Marshal(versions)
	if err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("encoding npm packument versions: %w", err)
	}
	top["versions"] = encodedVersions

	if raw, ok := top["time"]; ok {
		var times map[string]json.RawMessage
		if err := json.Unmarshal(raw, &times); err == nil {
			for _, v := range unmappable {
				delete(times, v)
			}
			if !allRejected {
				for _, v := range removed {
					delete(times, v)
				}
			}
			if encoded, err := json.Marshal(times); err == nil {
				top["time"] = encoded
			}
		}
	}

	body, err := json.Marshal(top)
	if err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("encoding npm packument: %w", err)
	}
	return gate.FilteredDocument{Body: body, Removed: removed, Unmappable: unmappable, AllRejected: allRejected}, nil
}

// rewriteNPMManifest points a single-version manifest's dist.tarball at
// linkBase. The version comes from the manifest itself, since the request may
// have named a dist-tag.
func rewriteNPMManifest(doc []byte, name, linkBase string) (gate.FilteredDocument, error) {
	var head struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(doc, &head); err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("decoding npm manifest: %w", err)
	}
	body, err := rewriteNPMTarball(doc, linkBase, name, head.Version)
	switch {
	case errors.Is(err, errNoTarballLink):
		return gate.FilteredDocument{Body: doc}, nil
	case err != nil:
		return gate.FilteredDocument{}, fmt.Errorf("%w: %w", gate.ErrNoServableVersions, err)
	}
	return gate.FilteredDocument{Body: body}, nil
}

// npmPublishDates decodes a packument's "time" map. It is absent from the
// abbreviated document, and a version missing from it yields the zero time,
// which mutes any age-based rule for that version. The map also holds the
// non-version keys "created" and "modified"; they are harmless here because
// only version names are ever looked up.
func npmPublishDates(raw json.RawMessage) map[string]time.Time {
	if len(raw) == 0 {
		return nil
	}
	var times map[string]string
	if err := json.Unmarshal(raw, &times); err != nil {
		return nil
	}
	out := make(map[string]time.Time, len(times))
	for version, s := range times {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			out[version] = t.UTC()
		}
	}
	return out
}
