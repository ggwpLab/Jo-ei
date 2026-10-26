package adapters_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

func TestNPMAdapter_NormalizeRequest_Tarball(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	r := httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-4.17.21.tgz", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "npm", ref.Ecosystem)
	assert.Equal(t, "lodash", ref.Name)
	assert.Equal(t, "4.17.21", ref.Version)
}

func TestNPMAdapter_NormalizeRequest_ScopedTarball(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	r := httptest.NewRequest(http.MethodGet, "/@babel/core/-/core-7.24.0.tgz", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "@babel/core", ref.Name)
	assert.Equal(t, "7.24.0", ref.Version)
}

func TestNPMAdapter_NormalizeRequest_MetadataNotIntercepted(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	r := httptest.NewRequest(http.MethodGet, "/lodash", nil)
	_, ok := a.NormalizeRequest(r)
	assert.False(t, ok)
}

func TestNPMAdapter_FetchMetadata(t *testing.T) {
	publishedAt := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/lodash", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"time": map[string]any{
				"4.17.21": publishedAt.Format(time.RFC3339),
			},
			"versions": map[string]any{
				"4.17.21": map[string]any{
					"license": "MIT",
					"dist":    map[string]any{"shasum": "abc123sha1"},
				},
			},
		})
	}))
	defer srv.Close()

	a := adapters.NewNPMAdapter([]string{srv.URL})
	ref := &gate.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)

	assert.WithinDuration(t, publishedAt, meta.PublishedAt, time.Second)
	assert.Equal(t, "MIT", meta.License)
}

func TestNPMAdapter_FetchMetadata_VersionMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"time": map[string]any{}, "versions": map[string]any{}})
	}))
	defer srv.Close()

	a := adapters.NewNPMAdapter([]string{srv.URL})
	ref := &gate.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "9.9.9"}
	_, err := a.FetchMetadata(context.Background(), ref)
	assert.Error(t, err)
}

func TestNPMAdapter_NormalizeRequest_EmptyVersionRejected(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})
	r := httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-.tgz", nil)
	_, ok := a.NormalizeRequest(r)
	assert.False(t, ok)
}

func TestNPMAdapter_FetchMetadata_VersionInTimeButNotVersions(t *testing.T) {
	publishedAt := time.Now().UTC().Add(-48 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"time":     map[string]any{"1.0.0": publishedAt.Format(time.RFC3339)},
			"versions": map[string]any{}, // version absent from versions map
		})
	}))
	defer srv.Close()

	a := adapters.NewNPMAdapter([]string{srv.URL})
	ref := &gate.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"}
	_, err := a.FetchMetadata(context.Background(), ref)
	assert.Error(t, err)
}

func TestNPMAdapter_FetchMetadata_FallsBackToSecondUpstream(t *testing.T) {
	published := time.Now().UTC().Add(-72 * time.Hour)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"time": map[string]string{"1.0.0": published.Format(time.RFC3339)},
			"versions": map[string]any{
				"1.0.0": map[string]any{"license": "MIT", "dist": map[string]any{"shasum": "abc"}},
			},
		})
	}))
	defer up.Close()

	a := adapters.NewNPMAdapter([]string{down.URL, up.URL})
	ref := &gate.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, published, meta.PublishedAt, time.Second)
}

// Regression: npm's "license" field is polymorphic. Modern versions use a
// string, but legacy/historical versions in the SAME document use an object
// {"type","url"}. FetchMetadata decodes the whole versions map, so an older,
// unrequested version carrying the legacy object form must not fail the fetch
// (the trigger for "decoding npm response: json: cannot unmarshal object into
// Go struct field .versions.license of type string").
func TestNPMAdapter_FetchMetadata_LegacyObjectLicenseInOtherVersion(t *testing.T) {
	publishedAt := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"time": map[string]any{
				"5.1.9": publishedAt.Format(time.RFC3339),
			},
			"versions": map[string]any{
				// Requested version: modern string license.
				"5.1.9": map[string]any{
					"license": "ISC",
					"dist":    map[string]any{"shasum": "deadbeef"},
				},
				// Historical version: legacy object license — must not break decode.
				"0.2.0": map[string]any{
					"license": map[string]any{"type": "MIT", "url": "https://example.com/LICENSE"},
					"dist":    map[string]any{"shasum": "0ldsha"},
				},
			},
		})
	}))
	defer srv.Close()

	a := adapters.NewNPMAdapter([]string{srv.URL})
	ref := &gate.PackageRef{Ecosystem: "npm", Name: "minimatch", Version: "5.1.9"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "ISC", meta.License)
}

// The requested version itself may carry the legacy object license; extract the
// "type" so the (informational) license is still populated.
func TestNPMAdapter_FetchMetadata_ObjectLicenseOnRequestedVersion(t *testing.T) {
	publishedAt := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"time": map[string]any{"1.0.0": publishedAt.Format(time.RFC3339)},
			"versions": map[string]any{
				"1.0.0": map[string]any{
					"license": map[string]any{"type": "MIT", "url": "https://example.com"},
					"dist":    map[string]any{"shasum": "abc"},
				},
			},
		})
	}))
	defer srv.Close()

	a := adapters.NewNPMAdapter([]string{srv.URL})
	ref := &gate.PackageRef{Ecosystem: "npm", Name: "old-pkg", Version: "1.0.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "MIT", meta.License)
}

// An unrecognized license shape (e.g. the legacy "licenses" array form embedded
// under "license") must degrade to an empty license, never fail the decode.
func TestNPMAdapter_FetchMetadata_UnknownLicenseShapeDegrades(t *testing.T) {
	publishedAt := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"time": map[string]any{"1.0.0": publishedAt.Format(time.RFC3339)},
			"versions": map[string]any{
				"1.0.0": map[string]any{
					"license": []any{map[string]any{"type": "MIT"}, map[string]any{"type": "Apache-2.0"}},
					"dist":    map[string]any{"shasum": "abc"},
				},
			},
		})
	}))
	defer srv.Close()

	a := adapters.NewNPMAdapter([]string{srv.URL})
	ref := &gate.PackageRef{Ecosystem: "npm", Name: "old-pkg", Version: "1.0.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "", meta.License)
}

// FetchMetadata must surface every mirror it tried, not just the last.
func TestNPMAdapter_FetchMetadataReportsEveryMirror(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer missing.Close()

	a := adapters.NewNPMAdapter([]string{deadURL, missing.URL})
	_, err := a.FetchMetadata(context.Background(), &gate.PackageRef{
		Ecosystem: "npm", Name: "left-pad", Version: "1.3.0",
	})
	if err == nil {
		t.Fatal("expected an error when every mirror fails")
	}

	atts, ok := upstream.AttemptsFrom(err)
	if !ok {
		t.Fatalf("error does not carry upstream attempts: %v", err)
	}
	if len(atts) != 2 {
		t.Fatalf("recorded %d attempts, want 2: %+v", len(atts), atts)
	}
	if atts[0].Status != 0 {
		t.Fatalf("first attempt status = %d, want 0 (unreachable mirror)", atts[0].Status)
	}
	if atts[1].Status != http.StatusNotFound {
		t.Fatalf("second attempt status = %d, want 404", atts[1].Status)
	}
}

func TestNPMAdapter_FetchMetadataWithNoUpstreams(t *testing.T) {
	a := adapters.NewNPMAdapter(nil)
	_, err := a.FetchMetadata(context.Background(), &gate.PackageRef{
		Ecosystem: "npm", Name: "left-pad", Version: "1.3.0",
	})
	if err == nil || !strings.Contains(err.Error(), "no upstreams configured for npm") {
		t.Fatalf("err = %v, want the no-upstreams message preserved", err)
	}
}

func TestNPMAdapter_UpstreamURLs_OnePerUpstream(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org/", "https://mirror.example.org"})
	r := httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-1.0.0.tgz", nil)
	urls := a.UpstreamURLs(r)
	assert.Equal(t, []string{
		"https://registry.npmjs.org/lodash/-/lodash-1.0.0.tgz",
		"https://mirror.example.org/lodash/-/lodash-1.0.0.tgz",
	}, urls)
}

func TestNPMAdapter_NormalizeMetadataRequest(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	tests := []struct {
		name        string
		method      string
		path        string
		wantOK      bool
		wantName    string
		wantVersion string
	}{
		{name: "bare package", method: http.MethodGet, path: "/left-pad", wantOK: true, wantName: "left-pad"},
		{name: "scoped encoded", method: http.MethodGet, path: "/@types%2fnode", wantOK: true, wantName: "@types/node"},
		{name: "scoped plain", method: http.MethodGet, path: "/@types/node", wantOK: true, wantName: "@types/node"},

		// A single-version manifest carries a tarball link too.
		{name: "version manifest", method: http.MethodGet, path: "/left-pad/1.3.0", wantOK: true, wantName: "left-pad", wantVersion: "1.3.0"},
		{name: "dist-tag manifest", method: http.MethodGet, path: "/left-pad/latest", wantOK: true, wantName: "left-pad", wantVersion: "latest"},
		{name: "scoped version manifest", method: http.MethodGet, path: "/@types/node/20.0.0", wantOK: true, wantName: "@types/node", wantVersion: "20.0.0"},
		{name: "scoped encoded version manifest", method: http.MethodGet, path: "/@types%2fnode/20.0.0", wantOK: true, wantName: "@types/node", wantVersion: "20.0.0"},
		{name: "extra segment", method: http.MethodGet, path: "/left-pad/1.3.0/extra"},
		{name: "scoped extra segment", method: http.MethodGet, path: "/@types/node/20.0.0/extra"},

		// Tarballs belong to NormalizeRequest, service endpoints to nobody.
		{name: "tarball", method: http.MethodGet, path: "/left-pad/-/left-pad-1.3.0.tgz"},
		{name: "search", method: http.MethodGet, path: "/-/v1/search"},
		{name: "npm api", method: http.MethodGet, path: "/-/npm/v1/user"},
		{name: "whoami", method: http.MethodGet, path: "/-/whoami"},

		// Publishes must never be rewritten.
		{name: "publish put", method: http.MethodPut, path: "/left-pad"},
		{name: "publish post", method: http.MethodPost, path: "/left-pad"},

		// The GET half of npm's read-modify-write cycle (`npm deprecate`, `npm
		// owner add/rm`) carries "?write=true" and PUTs the whole document back;
		// a rewritten GET here would carry hidden versions into that PUT.
		{name: "write query", method: http.MethodGet, path: "/left-pad?write=true"},
		{name: "write among other params", method: http.MethodGet, path: "/left-pad?a=1&write=true"},

		// Any other GET of a document is rewritten: passing it through would
		// hand the client links around the proxy.
		{name: "other query", method: http.MethodGet, path: "/left-pad?a=1", wantOK: true, wantName: "left-pad"},
		{name: "trailing slash", method: http.MethodGet, path: "/left-pad/", wantOK: true, wantName: "left-pad"},
		{name: "scoped trailing slash", method: http.MethodGet, path: "/@types/node/", wantOK: true, wantName: "@types/node"},
		{name: "manifest trailing slash", method: http.MethodGet, path: "/left-pad/1.3.0/", wantOK: true, wantName: "left-pad", wantVersion: "1.3.0"},

		{name: "root", method: http.MethodGet, path: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.path, nil)
			ref, ok := a.NormalizeMetadataRequest(r)
			require.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				assert.Nil(t, ref)
				return
			}
			require.NotNil(t, ref)
			assert.Equal(t, "npm", ref.Ecosystem)
			assert.Equal(t, tt.wantName, ref.Name)
			assert.Equal(t, tt.wantVersion, ref.Version)
		})
	}
}

// fullPackument is a miniature of the real thing: unknown top-level fields that
// must survive, a time map that includes the non-version "created"/"modified"
// keys, and a dist-tags entry pointing at the newest version.
const fullPackument = `{
  "_id": "left-pad",
  "name": "left-pad",
  "readme": "# left-pad",
  "dist-tags": {"latest": "1.3.0"},
  "time": {
    "created": "2014-01-01T00:00:00.000Z",
    "modified": "2018-01-01T00:00:00.000Z",
    "1.2.0": "2017-01-01T00:00:00.000Z",
    "1.3.0": "2018-01-01T00:00:00.000Z"
  },
  "versions": {
    "1.2.0": {"name": "left-pad", "version": "1.2.0", "dist": {"shasum": "aaa", "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz"}},
    "1.3.0": {"name": "left-pad", "version": "1.3.0", "dist": {"shasum": "bbb", "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}
  }
}`

// abbreviatedPackument is what Accept: application/vnd.npm.install-v1+json
// returns: no "time" map anywhere, so no age rule can speak.
const abbreviatedPackument = `{
  "name": "left-pad",
  "dist-tags": {"latest": "1.3.0"},
  "modified": "2018-01-01T00:00:00.000Z",
  "versions": {
    "1.2.0": {"name": "left-pad", "version": "1.2.0", "dist": {"shasum": "aaa", "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz"}},
    "1.3.0": {"name": "left-pad", "version": "1.3.0", "dist": {"shasum": "bbb", "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}
  }
}`

// linkBase is where every rewritten tarball link must point.
const linkBase = "https://reg.example/npm"

var packumentRef = &gate.MetadataRef{Ecosystem: "npm", Name: "left-pad"}

// tarballs decodes a packument and returns each version's dist.tarball.
func tarballs(t *testing.T, body []byte) map[string]string {
	t.Helper()
	var doc struct {
		Versions map[string]struct {
			Dist struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		} `json:"versions"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	out := make(map[string]string, len(doc.Versions))
	for v, m := range doc.Versions {
		out[v] = m.Dist.Tarball
	}
	return out
}

// rejectVersions builds a decider that hides exactly the named versions.
func rejectVersions(names ...string) gate.VersionDecider {
	bad := make(map[string]bool, len(names))
	for _, n := range names {
		bad[n] = true
	}
	return func(version string, _ time.Time) bool { return !bad[version] }
}

func TestNPMAdapter_FilterVersions_RemovesVersionAndItsTimeEntry(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	got, err := a.FilterVersions([]byte(fullPackument), packumentRef, rejectVersions("1.3.0"), linkBase)
	require.NoError(t, err)
	assert.Equal(t, []string{"1.3.0"}, got.Removed)
	assert.False(t, got.AllRejected)

	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
		Time     map[string]string          `json:"time"`
		DistTags map[string]string          `json:"dist-tags"`
		Readme   string                     `json:"readme"`
	}
	require.NoError(t, json.Unmarshal(got.Body, &doc))

	assert.NotContains(t, doc.Versions, "1.3.0")
	assert.Contains(t, doc.Versions, "1.2.0")
	assert.NotContains(t, doc.Time, "1.3.0", "the removed version's publish date must go with it")
	assert.Contains(t, doc.Time, "created", "non-version time keys must survive")
	assert.Equal(t, "# left-pad", doc.Readme, "unknown top-level fields must survive")

	// npm tolerates a tag naming a version that is no longer listed and falls
	// back to the highest one that is. Leaving tags alone is what spares this
	// project a semver comparator; do not "fix" this assertion.
	assert.Equal(t, "1.3.0", doc.DistTags["latest"])
}

func TestNPMAdapter_FilterVersions_RewritesEveryTarball(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	got, err := a.FilterVersions([]byte(fullPackument), packumentRef, rejectVersions(), linkBase)
	require.NoError(t, err)
	assert.Empty(t, got.Removed)
	assert.Empty(t, got.Unmappable)
	assert.Equal(t, map[string]string{
		"1.2.0": "https://reg.example/npm/left-pad/-/left-pad-1.2.0.tgz",
		"1.3.0": "https://reg.example/npm/left-pad/-/left-pad-1.3.0.tgz",
	}, tarballs(t, got.Body))

	var doc struct {
		Readme   string `json:"readme"`
		Versions map[string]struct {
			Dist map[string]string `json:"dist"`
		} `json:"versions"`
	}
	require.NoError(t, json.Unmarshal(got.Body, &doc))
	assert.Equal(t, "# left-pad", doc.Readme, "unknown top-level fields must survive")
	assert.Equal(t, "bbb", doc.Versions["1.3.0"].Dist["shasum"], "other dist fields must survive")
}

func TestNPMAdapter_FilterVersions_AllRejectedStillRewritten(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	got, err := a.FilterVersions([]byte(fullPackument), packumentRef, rejectVersions("1.2.0", "1.3.0"), linkBase)
	require.NoError(t, err)
	assert.True(t, got.AllRejected)
	assert.Equal(t, []string{"1.2.0", "1.3.0"}, got.Removed)
	// An empty version list would break every install of this package, so
	// every version stays — but none may link around the proxy.
	assert.Equal(t, map[string]string{
		"1.2.0": "https://reg.example/npm/left-pad/-/left-pad-1.2.0.tgz",
		"1.3.0": "https://reg.example/npm/left-pad/-/left-pad-1.3.0.tgz",
	}, tarballs(t, got.Body))
}

func TestNPMAdapter_FilterVersions_ScopedName(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://nexus.example/repository/npm-proxy"})
	doc := `{"name":"@babel/core","versions":{"7.26.0":{"dist":{"tarball":"https://nexus.example/repository/npm-proxy/@babel/core/-/core-7.26.0.tgz"}}}}`

	got, err := a.FilterVersions([]byte(doc), &gate.MetadataRef{Ecosystem: "npm", Name: "@babel/core"}, rejectVersions(), linkBase)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"7.26.0": "https://reg.example/npm/@babel/core/-/core-7.26.0.tgz"}, tarballs(t, got.Body))
}

func TestNPMAdapter_FilterVersions_ArtifactoryStyleFilenameIgnored(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://art.example/api/npm/npm"})
	doc := `{"name":"@scope/name","versions":{"1.0.0":{"dist":{"tarball":"https://art.example/api/npm/npm/@scope/name/-/@scope/name-1.0.0.tgz"}}}}`

	got, err := a.FilterVersions([]byte(doc), &gate.MetadataRef{Ecosystem: "npm", Name: "@scope/name"}, rejectVersions(), linkBase)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"1.0.0": "https://reg.example/npm/@scope/name/-/name-1.0.0.tgz"}, tarballs(t, got.Body))
}

func TestNPMAdapter_FilterVersions_UnmappableVersionDropped(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})
	doc := `{"name":"left-pad","time":{"1.0.0/../x":"2017-01-01T00:00:00.000Z","1.3.0":"2018-01-01T00:00:00.000Z"},` +
		`"versions":{"1.0.0/../x":{"dist":{"tarball":"https://registry.npmjs.org/x.tgz"}},"1.3.0":{"dist":{"tarball":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}}`

	got, err := a.FilterVersions([]byte(doc), packumentRef, rejectVersions(), linkBase)
	require.NoError(t, err)
	assert.Equal(t, []string{"1.0.0/../x"}, got.Unmappable)
	assert.Empty(t, got.Removed)
	assert.Equal(t, map[string]string{"1.3.0": "https://reg.example/npm/left-pad/-/left-pad-1.3.0.tgz"}, tarballs(t, got.Body))
	assert.NotContains(t, string(got.Body), "1.0.0/../x", "its time entry must go too")
}

func TestNPMAdapter_FilterVersions_AllUnmappable(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})
	doc := `{"name":"left-pad","versions":{"bad version":{"dist":{"tarball":"https://registry.npmjs.org/x.tgz"}}}}`

	_, err := a.FilterVersions([]byte(doc), packumentRef, rejectVersions(), linkBase)
	require.ErrorIs(t, err, gate.ErrNoServableVersions)
}

func TestNPMAdapter_FilterVersions_VersionWithoutDistLeftAlone(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})
	doc := `{"name":"left-pad","versions":{"1.0.0":{"name":"left-pad"},"1.3.0":{"dist":{"tarball":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}}`

	got, err := a.FilterVersions([]byte(doc), packumentRef, rejectVersions(), linkBase)
	require.NoError(t, err)
	assert.Empty(t, got.Unmappable)
	assert.Equal(t, map[string]string{"1.0.0": "", "1.3.0": "https://reg.example/npm/left-pad/-/left-pad-1.3.0.tgz"}, tarballs(t, got.Body))
}

func TestNPMAdapter_FilterVersions_EmptyVersions(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	got, err := a.FilterVersions([]byte(`{"name":"left-pad","versions":{}}`), packumentRef, rejectVersions(), linkBase)
	require.NoError(t, err)
	assert.Empty(t, tarballs(t, got.Body))
}

func TestNPMAdapter_FilterVersions_AbbreviatedRewritten(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	got, err := a.FilterVersions([]byte(abbreviatedPackument), packumentRef, rejectVersions(), linkBase)
	require.NoError(t, err)
	assert.Equal(t, "https://reg.example/npm/left-pad/-/left-pad-1.3.0.tgz", tarballs(t, got.Body)["1.3.0"])
}

func TestNPMAdapter_FilterVersions_SingleVersionManifest(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})
	doc := `{"name":"left-pad","version":"1.3.0","readme":"x","dist":{"shasum":"bbb","tarball":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}`
	never := func(string, time.Time) bool { t.Fatal("a manifest is not filtered"); return false }

	got, err := a.FilterVersions([]byte(doc), &gate.MetadataRef{Ecosystem: "npm", Name: "left-pad", Version: "latest"}, never, linkBase)
	require.NoError(t, err)
	var m struct {
		Readme string            `json:"readme"`
		Dist   map[string]string `json:"dist"`
	}
	require.NoError(t, json.Unmarshal(got.Body, &m))
	assert.Equal(t, "https://reg.example/npm/left-pad/-/left-pad-1.3.0.tgz", m.Dist["tarball"])
	assert.Equal(t, "bbb", m.Dist["shasum"])
	assert.Equal(t, "x", m.Readme)
}

func TestNPMAdapter_FilterVersions_SingleVersionManifestUnmappable(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})
	doc := `{"name":"left-pad","version":"bad/v","dist":{"tarball":"https://registry.npmjs.org/x.tgz"}}`

	_, err := a.FilterVersions([]byte(doc), &gate.MetadataRef{Ecosystem: "npm", Name: "left-pad", Version: "latest"}, rejectVersions(), linkBase)
	require.ErrorIs(t, err, gate.ErrNoServableVersions)
}

func TestNPMAdapter_FilterVersions_AbbreviatedHasNoDates(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	var seen map[string]time.Time
	decide := func(version string, publishedAt time.Time) bool {
		if seen == nil {
			seen = map[string]time.Time{}
		}
		seen[version] = publishedAt
		return true
	}

	got, err := a.FilterVersions([]byte(abbreviatedPackument), packumentRef, decide, linkBase)
	require.NoError(t, err)
	assert.Empty(t, got.Removed)
	assert.True(t, seen["1.2.0"].IsZero(), "no time map means no publish date to judge")
	assert.True(t, seen["1.3.0"].IsZero())
}

func TestNPMAdapter_FilterVersions_PassesPublishDates(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	seen := map[string]time.Time{}
	decide := func(version string, publishedAt time.Time) bool {
		seen[version] = publishedAt
		return true
	}

	_, err := a.FilterVersions([]byte(fullPackument), packumentRef, decide, linkBase)
	require.NoError(t, err)
	assert.Equal(t, "2018-01-01T00:00:00Z", seen["1.3.0"].Format(time.RFC3339))
	assert.Equal(t, "2017-01-01T00:00:00Z", seen["1.2.0"].Format(time.RFC3339))
}

func TestNPMAdapter_FilterVersions_MalformedDocument(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	_, err := a.FilterVersions([]byte(`{"versions": [`), packumentRef, rejectVersions("1.0.0"), linkBase)
	require.Error(t, err)
}

func TestNPMAdapter_FilterVersions_DocumentWithoutVersions(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})
	doc := []byte(`{"name": "left-pad"}`)

	got, err := a.FilterVersions(doc, packumentRef, rejectVersions("1.3.0"), linkBase)
	require.NoError(t, err)
	assert.JSONEq(t, string(doc), string(got.Body))
	assert.Empty(t, got.Removed)
}
