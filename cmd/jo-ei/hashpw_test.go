package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHashpwProducesVerifiableHash(t *testing.T) {
	cmd := newHashpwCmd()
	cmd.SetIn(strings.NewReader("mypassword\n"))
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())

	got := strings.TrimSpace(out.String())
	require.NotEmpty(t, got)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(got), []byte("mypassword")),
		"printed hash must verify against the original password")
}

func TestHashpwEmptyPasswordErrors(t *testing.T) {
	cmd := newHashpwCmd()
	cmd.SetIn(strings.NewReader("\n"))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	assert.Error(t, cmd.Execute())
}
