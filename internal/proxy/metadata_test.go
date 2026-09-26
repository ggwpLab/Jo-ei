package proxy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
