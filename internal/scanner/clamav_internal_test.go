package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseClamAVAddress(t *testing.T) {
	cases := []struct {
		in          string
		wantNetwork string
		wantAddr    string
		wantErr     bool
	}{
		{"unix:///var/run/clamav/clamd.sock", "unix", "/var/run/clamav/clamd.sock", false},
		{"tcp:127.0.0.1:3310", "tcp", "127.0.0.1:3310", false},
		{"http://nope", "", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		network, addr, err := parseClamAVAddress(c.in)
		if c.wantErr {
			assert.Error(t, err, "address %q", c.in)
			continue
		}
		require.NoError(t, err, "address %q", c.in)
		assert.Equal(t, c.wantNetwork, network, "network for %q", c.in)
		assert.Equal(t, c.wantAddr, addr, "addr for %q", c.in)
	}
}

func TestParseClamAVResponse(t *testing.T) {
	clean, err := parseClamAVResponse("stream: OK\x00")
	require.NoError(t, err)
	assert.True(t, clean.Clean)
	assert.Equal(t, "", clean.Signature)

	found, err := parseClamAVResponse("stream: Eicar-Test-Signature FOUND\x00")
	require.NoError(t, err)
	assert.False(t, found.Clean)
	assert.Equal(t, "Eicar-Test-Signature", found.Signature)

	_, err = parseClamAVResponse("INSTREAM size limit exceeded. ERROR\x00")
	assert.Error(t, err)
}
