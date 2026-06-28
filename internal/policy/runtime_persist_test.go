package policy_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/policy"
)

// fakeStore is an in-memory policy.SettingsStore.
type fakeStore struct {
	saved   *policy.RuntimeParams
	loadOK  bool
	loadVal policy.RuntimeParams
	saveErr error
	saves   int
}

func (f *fakeStore) LoadPolicy() (policy.RuntimeParams, bool, error) {
	return f.loadVal, f.loadOK, nil
}
func (f *fakeStore) SavePolicy(p policy.RuntimeParams) error {
	f.saves++
	if f.saveErr != nil {
		return f.saveErr
	}
	cp := p
	f.saved = &cp
	return nil
}

func sc() config.SupplyChainConfig { return config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24} }
func cve() config.CVEConfig        { return config.CVEConfig{Enabled: true, BlockOn: "CRITICAL"} }
func prof() config.PolicyProfile   { return config.PolicyProfile{CVEBlock: true} }

func TestNewRuntimeWithStore_SeedsEmptyStore(t *testing.T) {
	fs := &fakeStore{loadOK: false}
	r, err := policy.NewRuntimeWithStore(sc(), cve(), prof(), nil, fs)
	require.NoError(t, err)
	// Seeded from YAML params and persisted.
	require.NotNil(t, fs.saved)
	assert.Equal(t, "enforce", fs.saved.Mode)
	assert.Equal(t, "CRITICAL", fs.saved.CVEBlockOn)
	assert.Equal(t, "enforce", r.Current().Mode)
}

func TestNewRuntimeWithStore_LoadsExisting(t *testing.T) {
	fs := &fakeStore{loadOK: true, loadVal: policy.RuntimeParams{
		Mode: "dry_run", MinAgeHours: 5, CVEBlockOn: "HIGH",
		Allowlist: []string{}, Denylist: []string{},
	}}
	r, err := policy.NewRuntimeWithStore(sc(), cve(), prof(), nil, fs)
	require.NoError(t, err)
	// DB wins over the YAML seed; no re-seed write happens.
	assert.Equal(t, "dry_run", r.Current().Mode)
	assert.Equal(t, 5, r.Current().MinAgeHours)
	assert.Equal(t, 0, fs.saves, "loading an existing row must not re-seed")
}

func TestApply_PersistsThenInstalls(t *testing.T) {
	fs := &fakeStore{loadOK: false}
	r, err := policy.NewRuntimeWithStore(sc(), cve(), prof(), nil, fs)
	require.NoError(t, err)
	fs.saved = nil // ignore the seed write

	p := r.Current()
	p.Mode = "off"
	require.NoError(t, r.Apply(p))
	require.NotNil(t, fs.saved)
	assert.Equal(t, "off", fs.saved.Mode)
	assert.Equal(t, "off", r.Current().Mode)
}

func TestApply_SaveFailure_DoesNotInstall(t *testing.T) {
	fs := &fakeStore{loadOK: false}
	r, err := policy.NewRuntimeWithStore(sc(), cve(), prof(), nil, fs)
	require.NoError(t, err)
	before := r.Current()

	fs.saveErr = errors.New("disk full")
	p := r.Current()
	p.Mode = "off"
	gotErr := r.Apply(p)

	var perr *policy.PersistError
	require.ErrorAs(t, gotErr, &perr, "save failure must surface as PersistError")
	assert.Equal(t, before, r.Current(), "live policy unchanged when persist fails")
}

func TestApply_ValidationBeatsPersist(t *testing.T) {
	fs := &fakeStore{loadOK: false}
	r, err := policy.NewRuntimeWithStore(sc(), cve(), prof(), nil, fs)
	require.NoError(t, err)
	savesAfterSeed := fs.saves

	p := r.Current()
	p.Mode = "yolo" // invalid
	gotErr := r.Apply(p)
	var verr *policy.ValidationError
	require.ErrorAs(t, gotErr, &verr)
	assert.Equal(t, savesAfterSeed, fs.saves, "invalid Apply must not reach the store")
}
