package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

func TestSyntheticETag_IsStableAndBodyDependent(t *testing.T) {
	a := syntheticETag([]byte(`{"versions":{"1.2.0":{}}}`))
	b := syntheticETag([]byte(`{"versions":{"1.2.0":{}}}`))
	c := syntheticETag([]byte(`{"versions":{"1.2.0":{},"1.3.0":{}}}`))

	assert.Equal(t, a, b, "identical filtering must revalidate as 304")
	assert.NotEqual(t, a, c, "different filtering must not")

	assert.True(t, strings.HasPrefix(a, syntheticETagPrefix), "must be recognisable as ours: %s", a)
	assert.True(t, strings.HasSuffix(a, `"`), "must be a quoted ETag: %s", a)
}

func TestHoldsSyntheticETag(t *testing.T) {
	ours := syntheticETag([]byte(`{}`))

	tests := []struct {
		name string
		inm  string
		want bool
	}{
		{name: "empty", inm: ""},
		{name: "upstream tag", inm: `"e83879f942df342315ccdeff2139a89a"`},
		{name: "ours", inm: ours, want: true},
		{name: "ours second in a list", inm: `"e83879f9", ` + ours, want: true},
		{name: "ours first in a list", inm: ours + `, "e83879f9"`, want: true},
		{name: "wildcard is not ours", inm: "*"},
		{name: "garbage", inm: "not-a-tag"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, holdsSyntheticETag(tt.inm))
		})
	}
}

func TestETagMatches(t *testing.T) {
	ours := syntheticETag([]byte(`{}`))

	assert.True(t, etagMatches(ours, ours))
	assert.True(t, etagMatches(`"other", `+ours, ours))
	assert.False(t, etagMatches(`"other"`, ours))
	assert.False(t, etagMatches("", ours))
	assert.False(t, etagMatches(`W/`+ours, ours), "a weak tag is not a match for a strong one")
}

func TestClientAcceptsGzip(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{name: "empty", header: "", want: false},
		{name: "plain gzip", header: "gzip", want: true},
		{name: "uppercase", header: "GZIP", want: true},
		{name: "other encoding only", header: "deflate", want: false},
		{name: "identity only", header: "identity", want: false},
		{name: "explicit refusal", header: "gzip;q=0", want: false},
		{name: "explicit refusal with decimal", header: "gzip;q=0.0", want: false},
		{name: "explicit refusal with a space before the qvalue", header: "gzip; q=0", want: false},
		{name: "explicit refusal with three decimal places", header: "gzip;q=0.000", want: false},
		{name: "low but nonzero preference is still acceptance", header: "gzip;q=0.5", want: true},
		{name: "gzip listed among several encodings", header: "deflate, gzip", want: true},
		{name: "gzip refused among several encodings", header: "deflate, gzip;q=0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/left-pad", nil)
			r.Header.Set("Accept-Encoding", tt.header)
			assert.Equal(t, tt.want, clientAcceptsGzip(r))
		})
	}
}

// denylistPolicy denies the named versions the way the real policy engine does.
type denylistPolicy struct{ denied map[string]bool }

func (p denylistPolicy) Evaluate(ref *gate.PackageRef, _ *gate.ScanResult) gate.PolicyDecision {
	if p.denied[ref.Version] {
		return gate.PolicyDecision{Allowed: false, Reason: gate.ReasonDenylisted}
	}
	return gate.PolicyDecision{Allowed: true, Reason: "ok"}
}

// cvePolicy rejects everything for a non-denylist reason. The decider must
// ignore it: it passes an empty ScanResult, which means "not scanned", not
// "dirty", so a CVE verdict here would be an invention.
type cvePolicy struct{}

func (cvePolicy) Evaluate(*gate.PackageRef, *gate.ScanResult) gate.PolicyDecision {
	return gate.PolicyDecision{Allowed: false, Reason: "cve_found"}
}

func newDeciderHandler(t *testing.T, mode string, policy gate.PolicyDecider) *Handler {
	t.Helper()
	return NewHandler(HandlerConfig{
		Adapter: adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"}),
		Filter: supplychain.NewFilter(config.SupplyChainConfig{
			MinAgeHours: 24,
			Mode:        mode,
		}, nil),
		Logger:              zerolog.Nop(),
		Policy:              policy,
		MetadataFilterMaxMB: 32,
	})
}

func TestHandler_VersionDecider(t *testing.T) {
	mref := &gate.MetadataRef{Ecosystem: "npm", Name: "left-pad"}
	old := time.Now().Add(-240 * time.Hour)
	fresh := time.Now().Add(-1 * time.Hour)

	tests := []struct {
		name        string
		mode        string
		policy      gate.PolicyDecider
		version     string
		publishedAt time.Time
		want        bool
	}{
		{name: "old version allowed", mode: "enforce", version: "1.2.0", publishedAt: old, want: true},
		{name: "fresh version hidden", mode: "enforce", version: "1.3.0", publishedAt: fresh},
		{name: "dry_run hides nothing", mode: "dry_run", version: "1.3.0", publishedAt: fresh, want: true},
		{name: "off hides nothing", mode: "off", version: "1.3.0", publishedAt: fresh, want: true},
		{
			name: "denylisted version hidden", mode: "enforce", version: "1.2.0", publishedAt: old,
			policy: denylistPolicy{denied: map[string]bool{"1.2.0": true}},
		},
		{
			name: "other denylist entries do not spread", mode: "enforce", version: "1.2.0", publishedAt: old,
			policy: denylistPolicy{denied: map[string]bool{"9.9.9": true}}, want: true,
		},
		{
			name: "a CVE verdict on an unscanned package is ignored", mode: "enforce",
			version: "1.2.0", publishedAt: old, policy: cvePolicy{}, want: true,
		},
		{name: "no publish date leaves the age rule mute", mode: "enforce", version: "1.3.0", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newDeciderHandler(t, tt.mode, tt.policy)
			var undated int
			decide := h.versionDecider(context.Background(), mref, &undated)
			assert.Equal(t, tt.want, decide(tt.version, tt.publishedAt))
			if tt.publishedAt.IsZero() {
				assert.Equal(t, 1, undated, "an undated version must be counted so it can be logged")
			} else {
				assert.Zero(t, undated)
			}
		})
	}
}
