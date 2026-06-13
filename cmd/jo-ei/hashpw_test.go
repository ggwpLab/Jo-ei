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

	err := cmd.Execute()
	require.Error(t, err)
	assert.ErrorContains(t, err, "empty password")
}

func TestHashpwNoTrailingNewline(t *testing.T) {
	cmd := newHashpwCmd()
	cmd.SetIn(strings.NewReader("mypassword")) // no newline
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())
	assert.NoError(t, bcrypt.CompareHashAndPassword(
		[]byte(strings.TrimSpace(out.String())), []byte("mypassword")))
}
