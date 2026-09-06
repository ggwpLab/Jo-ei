package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	return s
}

func TestNewSignerRejectsShortSecret(t *testing.T) {
	_, err := NewSigner([]byte("too-short"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 32 bytes")
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	s := testSigner(t)

	tok, err := s.Issue("ops", TypeAccess, 15*time.Minute)
	require.NoError(t, err)

	claims, err := s.Verify(tok, TypeAccess)
	require.NoError(t, err)
	assert.Equal(t, "ops", claims.Sub)
	assert.Equal(t, TypeAccess, claims.Typ)
	assert.NotEmpty(t, claims.JTI)
	assert.Equal(t, claims.IAT+int64((15*time.Minute).Seconds()), claims.Exp)
}

func TestIssueGivesEachTokenItsOwnID(t *testing.T) {
	s := testSigner(t)
	a, err := s.Issue("ops", TypeAccess, time.Minute)
	require.NoError(t, err)
	b, err := s.Issue("ops", TypeAccess, time.Minute)
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "two tokens issued in the same second must still differ")
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Issue("ops", TypeAccess, time.Minute)
	require.NoError(t, err)

	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	_, err = s.Verify(tok, TypeAccess)
	assert.ErrorIs(t, err, ErrExpiredToken)
}

func TestVerifyRejectsWrongType(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Issue("ops", TypeRefresh, time.Hour)
	require.NoError(t, err)

	_, err = s.Verify(tok, TypeAccess)
	assert.ErrorIs(t, err, ErrWrongTokenType)
}

func TestVerifyRejectsAnotherSecret(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Issue("ops", TypeAccess, time.Minute)
	require.NoError(t, err)

	other, err := NewSigner([]byte("ffffffffffffffffffffffffffffffff"))
	require.NoError(t, err)
	_, err = other.Verify(tok, TypeAccess)
	assert.ErrorIs(t, err, ErrBadSignature)
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Issue("ops", TypeAccess, time.Minute)
	require.NoError(t, err)

	parts := strings.Split(tok, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var c Claims
	require.NoError(t, json.Unmarshal(payload, &c))
	c.Sub = "root" // privilege escalation attempt
	forged, err := json.Marshal(c)
	require.NoError(t, err)
	parts[1] = base64.RawURLEncoding.EncodeToString(forged)

	_, err = s.Verify(strings.Join(parts, "."), TypeAccess)
	assert.ErrorIs(t, err, ErrBadSignature)
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	s := testSigner(t)
	// A token whose header says the signature is unnecessary. Signed with the
	// real secret so only the alg check can reject it.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"sub":"root","typ":"access","iat":1,"exp":9999999999,"jti":"x"}`))
	signing := header + "." + payload
	tok := signing + "." + base64.RawURLEncoding.EncodeToString(s.sign(signing))

	_, err := s.Verify(tok, TypeAccess)
	require.Error(t, err)
	assert.NotErrorIs(t, err, nil)
}

func TestVerifyRejectsMalformedTokens(t *testing.T) {
	s := testSigner(t)
	for name, tok := range map[string]string{
		"empty":         "",
		"one segment":   "abc",
		"two segments":  "abc.def",
		"four segments": "a.b.c.d",
		"not base64":    "!!!.???.###",
		"not json":      base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".x.y",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.Verify(tok, TypeAccess)
			require.Error(t, err)
		})
	}
}

func TestVerifyRejectsEmptySubject(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Issue("", TypeAccess, time.Minute)
	require.NoError(t, err)
	_, err = s.Verify(tok, TypeAccess)
	assert.ErrorIs(t, err, ErrMalformedToken)
}
