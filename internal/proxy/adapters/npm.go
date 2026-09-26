package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
		Dist    struct {
			Shasum string `json:"shasum"`
		} `json:"dist"`
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
		Checksum:    versionInfo.Dist.Shasum,
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

// NormalizeMetadataRequest reports whether r asks for an npm packument — the
// per-package document npm resolves version ranges from. Only a bare package
// name qualifies: registry service endpoints live under "/-/", and a
// single-version manifest ("/left-pad/1.3.0") carries no version list to
// rewrite, so both are proxied untouched and blocked at download time instead.
func (a *NPMAdapter) NormalizeMetadataRequest(r *http.Request) (*gate.MetadataRef, bool) {
	if r.Method != http.MethodGet {
		return nil, false
	}
	// URL.Path arrives percent-decoded, so npm's two spellings of a scoped name
	// — "/@types%2fnode" and "/@types/node" — are the same string here.
	name := strings.TrimPrefix(r.URL.Path, "/")
	if !isNPMPackageName(name) {
		return nil, false
	}
	return &gate.MetadataRef{Ecosystem: "npm", Name: name}, true
}

// isNPMPackageName reports whether s is a bare package name: "left-pad" or
// "@types/node". A leading "-" segment is a registry service endpoint, and any
// extra segment means a tarball or a single-version manifest.
func isNPMPackageName(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.Split(s, "/")
	if parts[0] == "-" {
		return false
	}
	if strings.HasPrefix(s, "@") {
		return len(parts) == 2 && len(parts[0]) > 1 && parts[1] != ""
	}
	return len(parts) == 1
}

// FilterVersions implements gate.MetadataFilterer. It rewrites an npm packument,
// dropping every version decide rejects along with that version's "time" entry.
// Unknown fields survive because the document is decoded one level deep, as raw
// JSON. dist-tags are deliberately left alone: npm tolerates a tag naming a
// version that is no longer listed and falls back to the highest one that is,
// which spares this project a semver comparator.
func (a *NPMAdapter) FilterVersions(doc []byte, decide gate.VersionDecider) (gate.FilteredDocument, error) {
	unchanged := gate.FilteredDocument{Body: doc}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("decoding npm packument: %w", err)
	}
	rawVersions, ok := top["versions"]
	if !ok {
		return unchanged, nil
	}
	var versions map[string]json.RawMessage
	if err := json.Unmarshal(rawVersions, &versions); err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("decoding npm packument versions: %w", err)
	}

	published := npmPublishDates(top["time"])

	var removed []string
	for version := range versions {
		if !decide(version, published[version]) {
			removed = append(removed, version)
		}
	}
	if len(removed) == 0 {
		return unchanged, nil
	}
	sort.Strings(removed)
	if len(removed) == len(versions) {
		// Serving an empty version list would turn every install of this
		// package into a resolution error. Hand back the original and let the
		// artifact gate state the real reason at download time.
		return gate.FilteredDocument{Body: doc, Removed: removed, AllRejected: true}, nil
	}

	for _, v := range removed {
		delete(versions, v)
	}
	encodedVersions, err := json.Marshal(versions)
	if err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("encoding npm packument versions: %w", err)
	}
	top["versions"] = encodedVersions

	if raw, ok := top["time"]; ok {
		var times map[string]json.RawMessage
		if err := json.Unmarshal(raw, &times); err == nil {
			for _, v := range removed {
				delete(times, v)
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
	return gate.FilteredDocument{Body: body, Removed: removed}, nil
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
