package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/policy"
)

func TestDecodeStored_MigratesLegacyAllowlistIntoBothLists(t *testing.T) {
	legacy := []byte(`{"mode":"enforce","min_age_hours":24,"cve_block_on":"HIGH",` +
		`"allowlist":["pypi/requests@2.31.0","npm/left-pad@1.3.0"],"denylist":[]}`)
	p, err := policy.DecodeStored(legacy)
	require.NoError(t, err)
	assert.Equal(t, []string{"pypi/requests@2.31.0", "npm/left-pad@1.3.0"}, p.AllowlistSupply)
	assert.Equal(t, []string{"pypi/requests@2.31.0", "npm/left-pad@1.3.0"}, p.AllowlistCVE)
	assert.Equal(t, "enforce", p.Mode)
}

func TestDecodeStored_NewFormatRoundTrip(t *testing.T) {
	in := policy.RuntimeParams{
		Mode: "dry_run", MinAgeHours: 5, CVEBlockOn: "LOW",
		AllowlistSupply: []string{"pypi/a@1"}, AllowlistCVE: []string{"npm/b@2"},
		Denylist: []string{"pypi/evil"},
	}
	b, err := policy.EncodeStored(in)
	require.NoError(t, err)
	out, err := policy.DecodeStored(b)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestDecodeStored_LegacyEntriesDeduplicated(t *testing.T) {
	mixed := []byte(`{"mode":"enforce","min_age_hours":24,"cve_block_on":"HIGH",` +
		`"allowlist":["pypi/a@1"],"allowlist_supply":["pypi/a@1"],"allowlist_cve":[],"denylist":[]}`)
	p, err := policy.DecodeStored(mixed)
	require.NoError(t, err)
	assert.Equal(t, []string{"pypi/a@1"}, p.AllowlistSupply, "no duplicate from legacy merge")
	assert.Equal(t, []string{"pypi/a@1"}, p.AllowlistCVE)
}

func TestDecodeStored_InvalidJSON(t *testing.T) {
	_, err := policy.DecodeStored([]byte("{nope"))
	require.Error(t, err)
}
