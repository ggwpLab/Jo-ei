package policy

import "encoding/json"

// storedParams is the persisted JSON shape of the runtime policy.
// LegacyAllowlist accepts rows written before the per-gate split, when a
// single "allowlist" bypassed all gates; DecodeStored migrates those entries
// into both per-gate lists so behavior does not change silently on upgrade.
type storedParams struct {
	RuntimeParams
	LegacyAllowlist []string `json:"allowlist,omitempty"`
}

// DecodeStored parses a persisted policy row, migrating the legacy single
// allowlist into both per-gate lists (deduplicated, order preserved).
func DecodeStored(b []byte) (RuntimeParams, error) {
	var sp storedParams
	if err := json.Unmarshal(b, &sp); err != nil {
		return RuntimeParams{}, err
	}
	p := sp.RuntimeParams
	for _, e := range sp.LegacyAllowlist {
		p.AllowlistSupply = appendMissing(p.AllowlistSupply, e)
		p.AllowlistCVE = appendMissing(p.AllowlistCVE, e)
	}
	return p, nil
}

// EncodeStored marshals the params in the current (per-gate) format; the
// legacy "allowlist" key is never written back.
func EncodeStored(p RuntimeParams) ([]byte, error) {
	return json.Marshal(p)
}

func appendMissing(list []string, e string) []string {
	for _, x := range list {
		if x == e {
			return list
		}
	}
	return append(list, e)
}
