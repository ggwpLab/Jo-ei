package console_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// ---------------------------------------------------------------------------
// fakeRegStore — in-memory RegistryStore for registry API tests.
// ---------------------------------------------------------------------------

type fakeRegStore struct {
	regs []console.RegistryInfo
	ok   bool
}

func (f *fakeRegStore) LoadRegistries() ([]console.RegistryInfo, bool, error) {
	return f.regs, f.ok, nil
}
func (f *fakeRegStore) SaveRegistries(in []console.RegistryInfo) error {
	f.regs = in
	f.ok = true
	return nil
}

// allSix returns a canonical six-ecosystem payload.
func allSix(dockerEnabled bool) []console.RegistryInfo {
	return []console.RegistryInfo{
		{Ecosystem: "pypi", Enabled: true, Upstreams: []string{"https://pypi.org/simple"}},
		{Ecosystem: "npm", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "maven", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "rubygems", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "go", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "docker", Enabled: dockerEnabled, Upstreams: func() []string {
			if dockerEnabled {
				return []string{"https://registry-1.docker.io"}
			}
			return []string{}
		}()},
	}
}

func regHandler(t *testing.T, store console.RegistryStore, running []console.RegistryInfo, imageScan bool) *httptest.Server {
	t.Helper()
	h := newHandler(console.Config{
		Store:             newTelemetryStore(t),
		Broadcaster:       telemetry.NewBroadcaster(),
		RegistryStore:     store,
		RunningRegistries: running,
		ImageScanEnabled:  imageScan,
		Logger:            zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func putRegistries(t *testing.T, url string, regs []console.RegistryInfo) (*http.Response, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"registries": regs})
	req, err := http.NewRequest(http.MethodPut, url+"/api/registries", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	out := new(bytes.Buffer)
	_, _ = out.ReadFrom(resp.Body)
	_ = resp.Body.Close()
	return resp, out.Bytes()
}

// ---------------------------------------------------------------------------
// Registry API tests
// ---------------------------------------------------------------------------

func TestPutRegistries_PersistsAndFlagsPending(t *testing.T) {
	running := allSix(false)
	fs := &fakeRegStore{regs: running, ok: true}
	srv := regHandler(t, fs, running, false)

	edited := allSix(false)
	edited[1].Enabled = true
	edited[1].Upstreams = []string{"https://registry.npmjs.org"}

	resp, body := putRegistries(t, srv.URL, edited)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out struct {
		Registries     []console.RegistryInfo `json:"registries"`
		PendingRestart bool                   `json:"pending_restart"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	assert.True(t, out.PendingRestart, "edit differs from running set")
	assert.True(t, fs.regs[1].Enabled, "npm persisted as enabled")
}

func TestGetRegistries_NoPendingWhenUnchanged(t *testing.T) {
	running := allSix(false)
	fs := &fakeRegStore{regs: running, ok: true}
	srv := regHandler(t, fs, running, false)

	var out struct {
		Registries     []console.RegistryInfo `json:"registries"`
		PendingRestart bool                   `json:"pending_restart"`
	}
	code := getJSON(t, srv.URL+"/api/registries", &out)
	require.Equal(t, http.StatusOK, code)
	assert.False(t, out.PendingRestart)
	assert.Len(t, out.Registries, 6)
}

func TestPutRegistries_EnabledNeedsUpstream(t *testing.T) {
	running := allSix(false)
	srv := regHandler(t, &fakeRegStore{regs: running, ok: true}, running, false)

	bad := allSix(false)
	bad[1].Enabled = true // npm enabled with no upstreams
	resp, body := putRegistries(t, srv.URL, bad)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var e struct{ Error, Field string }
	require.NoError(t, json.Unmarshal(body, &e))
	assert.Equal(t, "invalid_registries", e.Error)
	assert.Equal(t, "npm", e.Field)
}

func TestPutRegistries_UnknownEcoRejected(t *testing.T) {
	running := allSix(false)
	srv := regHandler(t, &fakeRegStore{regs: running, ok: true}, running, false)

	bad := append(allSix(false), console.RegistryInfo{Ecosystem: "cargo", Enabled: false, Upstreams: []string{}})
	resp, body := putRegistries(t, srv.URL, bad)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var e struct{ Error, Field string }
	require.NoError(t, json.Unmarshal(body, &e))
	assert.Equal(t, "invalid_registries", e.Error)
	assert.Equal(t, "registries", e.Field)
}

func TestPutRegistries_DockerWithoutImageScanWarns(t *testing.T) {
	running := allSix(false)
	fs := &fakeRegStore{regs: running, ok: true}
	srv := regHandler(t, fs, running, false) // image_scan OFF

	edited := allSix(true) // docker enabled
	resp, body := putRegistries(t, srv.URL, edited)
	require.Equal(t, http.StatusOK, resp.StatusCode) // warning, not rejection
	var out struct {
		Warnings []string `json:"warnings"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	require.NotEmpty(t, out.Warnings)
	assert.Contains(t, out.Warnings[0], "image_scan")
	assert.True(t, fs.regs[5].Enabled, "docker still persisted despite warning")
}

// ---------------------------------------------------------------------------
// Defensive-copy test: writeRegistries must not mutate the store's backing slice.
// ---------------------------------------------------------------------------

func TestGetRegistries_DefensiveCopy(t *testing.T) {
	// Store returns an entry with nil Upstreams each call; writeRegistries must
	// make a copy and not write through to the store's internal slice.
	fs := &fakeRegStore{
		regs: []console.RegistryInfo{{Ecosystem: "pypi", Enabled: false, Upstreams: nil}},
		ok:   true,
	}
	srv := regHandler(t, fs, nil, false)

	doGet := func(label string) {
		t.Helper()
		resp, err := http.Get(srv.URL + "/api/registries")
		require.NoError(t, err, label)
		var rawBuf bytes.Buffer
		_, _ = rawBuf.ReadFrom(resp.Body)
		_ = resp.Body.Close()
		body := rawBuf.String()
		assert.Contains(t, body, `"upstreams":[]`, "%s: upstreams must be [] not null", label)
		assert.NotContains(t, body, `"upstreams":null`, "%s: must not encode null", label)
	}

	doGet("first GET")
	// Store's internal slice must not have been mutated.
	assert.Nil(t, fs.regs[0].Upstreams, "writeRegistries must not mutate store's backing slice")
	doGet("second GET")
	assert.Nil(t, fs.regs[0].Upstreams, "still not mutated after second GET")
}

// ---------------------------------------------------------------------------
// Validation-rule tests.
// ---------------------------------------------------------------------------

func TestPutRegistries_DuplicateEco(t *testing.T) {
	running := allSix(false)
	srv := regHandler(t, &fakeRegStore{regs: running, ok: true}, running, false)

	// Two "pypi" entries; all ecosystems are known, so the unknown-eco branch
	// does not pre-empt the duplicate-eco branch.
	bad := []console.RegistryInfo{
		{Ecosystem: "pypi", Enabled: true, Upstreams: []string{"https://pypi.org/simple"}},
		{Ecosystem: "pypi", Enabled: false, Upstreams: []string{}}, // duplicate — no unknown eco here
		{Ecosystem: "maven", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "rubygems", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "docker", Enabled: false, Upstreams: []string{}},
	}
	resp, body := putRegistries(t, srv.URL, bad)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var e struct{ Error, Field string }
	require.NoError(t, json.Unmarshal(body, &e))
	assert.Equal(t, "invalid_registries", e.Error)
	assert.Equal(t, "registries", e.Field)
}

func TestPutRegistries_MissingEco(t *testing.T) {
	running := allSix(false)
	srv := regHandler(t, &fakeRegStore{regs: running, ok: true}, running, false)

	// Only 4 ecosystems — "docker" is absent.
	bad := []console.RegistryInfo{
		{Ecosystem: "pypi", Enabled: true, Upstreams: []string{"https://pypi.org/simple"}},
		{Ecosystem: "npm", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "maven", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "rubygems", Enabled: false, Upstreams: []string{}},
	}
	resp, body := putRegistries(t, srv.URL, bad)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var e struct{ Error, Field string }
	require.NoError(t, json.Unmarshal(body, &e))
	assert.Equal(t, "invalid_registries", e.Error)
	assert.Equal(t, "registries", e.Field)
}

func TestPutRegistries_InvalidUpstreamURL(t *testing.T) {
	running := allSix(false)
	srv := regHandler(t, &fakeRegStore{regs: running, ok: true}, running, false)

	// pypi is enabled but its upstream uses ftp:// — not http(s).
	bad := allSix(false)
	bad[0].Upstreams = []string{"ftp://bad.example.com"}
	resp, body := putRegistries(t, srv.URL, bad)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var e struct{ Error, Field string }
	require.NoError(t, json.Unmarshal(body, &e))
	assert.Equal(t, "invalid_registries", e.Error)
	assert.Equal(t, "pypi", e.Field)
}

// ---------------------------------------------------------------------------
// fakePolicyStore — in-memory policy.SettingsStore for persist_failed test.
// ---------------------------------------------------------------------------

type fakePolicyStore struct {
	params  policy.RuntimeParams
	loaded  bool
	saveErr error
}

func (f *fakePolicyStore) LoadPolicy() (policy.RuntimeParams, bool, error) {
	return f.params, f.loaded, nil
}

func (f *fakePolicyStore) SavePolicy(p policy.RuntimeParams) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.params = p
	f.loaded = true
	return nil
}

// ---------------------------------------------------------------------------
// persist_failed branch in putPolicy
// ---------------------------------------------------------------------------

func TestGetPolicy_ReportsDatabasePersistence(t *testing.T) {
	rt, err := policy.NewRuntimeWithStore(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{},
		config.PolicyProfile{},
		nil,
		&fakePolicyStore{},
	)
	require.NoError(t, err)

	h := newHandler(console.Config{
		Store:       newTelemetryStore(t),
		Broadcaster: telemetry.NewBroadcaster(),
		Policy:      rt,
		Logger:      zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/policy")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out struct {
		Persistence string `json:"persistence"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "database", out.Persistence, "store-backed runtime must report database persistence")
}

func TestPutPolicy_PersistFailed(t *testing.T) {
	fps := &fakePolicyStore{}
	rt, err := policy.NewRuntimeWithStore(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{},
		config.PolicyProfile{},
		nil,
		fps,
	)
	require.NoError(t, err)
	// Make all subsequent saves fail — triggers PersistError in Apply.
	fps.saveErr = errors.New("disk full")

	h := newHandler(console.Config{
		Store:       newTelemetryStore(t),
		Broadcaster: telemetry.NewBroadcaster(),
		Policy:      rt,
		Logger:      zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/policy",
		strings.NewReader(`{"mode":"dry_run","min_age_hours":24,"cve_block_on":"HIGH","allowlist_supply":[],"allowlist_cve":[],"denylist":[]}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	var out struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "persist_failed", out.Error)
}

// Upstream URLs may carry credentials ("https://user:pass@host/..."). The
// registries screen is open to operators, so the API must never return them.
func credentialedSix() []console.RegistryInfo {
	regs := allSix(false)
	regs[0].Upstreams = []string{
		"https://ci:s3cret@nexus.example.org/repository/pypi",
		"https://tok123@mirror.example.org/simple",
		"https://pypi.org/simple",
	}
	return regs
}

func getRegistries(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url + "/api/registries")
	require.NoError(t, err)
	out := new(bytes.Buffer)
	_, _ = out.ReadFrom(resp.Body)
	_ = resp.Body.Close()
	return resp, out.Bytes()
}

func decodeRegistries(t *testing.T, body []byte) []console.RegistryInfo {
	t.Helper()
	var got struct {
		Registries []console.RegistryInfo `json:"registries"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	return got.Registries
}

func TestGetRegistries_MasksUpstreamCredentials(t *testing.T) {
	store := &fakeRegStore{regs: credentialedSix(), ok: true}
	srv := regHandler(t, store, credentialedSix(), false)

	resp, body := getRegistries(t, srv.URL)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotContains(t, string(body), "s3cret")
	assert.NotContains(t, string(body), "tok123")

	regs := decodeRegistries(t, body)
	assert.Equal(t, []string{
		"https://ci:***@nexus.example.org/repository/pypi",
		"https://***@mirror.example.org/simple",
		"https://pypi.org/simple",
	}, regs[0].Upstreams)

	var flags struct {
		Pending bool `json:"pending_restart"`
	}
	require.NoError(t, json.Unmarshal(body, &flags))
	assert.False(t, flags.Pending, "masking must not make the running set look changed")
}

func TestPutRegistries_MaskedUpstreamKeepsStoredCredentials(t *testing.T) {
	store := &fakeRegStore{regs: credentialedSix(), ok: true}
	srv := regHandler(t, store, credentialedSix(), false)

	_, body := getRegistries(t, srv.URL)
	regs := decodeRegistries(t, body)
	// Reorder the masked entries, as the screen's up/down buttons do.
	regs[0].Upstreams[0], regs[0].Upstreams[1] = regs[0].Upstreams[1], regs[0].Upstreams[0]

	resp, out := putRegistries(t, srv.URL, regs)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(out))
	assert.NotContains(t, string(out), "s3cret")
	assert.Equal(t, []string{
		"https://tok123@mirror.example.org/simple",
		"https://ci:s3cret@nexus.example.org/repository/pypi",
		"https://pypi.org/simple",
	}, store.regs[0].Upstreams)
}

func TestPutRegistries_UnknownMaskedUpstreamRejected(t *testing.T) {
	store := &fakeRegStore{regs: credentialedSix(), ok: true}
	srv := regHandler(t, store, credentialedSix(), false)

	regs := credentialedSix()
	regs[0].Upstreams = []string{"https://ci:***@other.example.org/pypi"}
	resp, _ := putRegistries(t, srv.URL, regs)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "https://ci:s3cret@nexus.example.org/repository/pypi", store.regs[0].Upstreams[0], "store untouched")
}

func TestPutRegistries_NewCredentialsStoredVerbatim(t *testing.T) {
	store := &fakeRegStore{regs: allSix(false), ok: true}
	srv := regHandler(t, store, allSix(false), false)

	regs := allSix(false)
	regs[0].Upstreams = []string{"https://ci:n3w@nexus.example.org/pypi"}
	resp, out := putRegistries(t, srv.URL, regs)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "https://ci:n3w@nexus.example.org/pypi", store.regs[0].Upstreams[0])
	assert.NotContains(t, string(out), "n3w")
}
