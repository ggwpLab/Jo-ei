package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Token types. A refresh token is never accepted where an access token is
// expected, and vice versa: the type is part of what Verify checks.
const (
	TypeAccess  = "access"
	TypeRefresh = "refresh"
)

// MinSecretLen is the shortest signing secret accepted. HMAC-SHA256 keys
// shorter than the hash output add no security and a short secret is almost
// always a placeholder someone forgot to replace.
const MinSecretLen = 32

// Token verification failures. Callers map all of them to the same 401 — the
// distinction exists for logs and tests, never for the response body.
var (
	ErrMalformedToken = errors.New("auth: malformed token")
	ErrBadSignature   = errors.New("auth: bad token signature")
	ErrExpiredToken   = errors.New("auth: token expired")
	ErrWrongTokenType = errors.New("auth: wrong token type")
)

// Claims is the JWT payload. Issuer and audience are omitted: single issuer,
// single audience, and every claim we do not need is one more thing to check.
type Claims struct {
	Sub string `json:"sub"` // username
	Typ string `json:"typ"` // TypeAccess or TypeRefresh
	IAT int64  `json:"iat"` // issued at, Unix seconds
	Exp int64  `json:"exp"` // expires at, Unix seconds
	JTI string `json:"jti"` // random id, so two tokens issued in the same second differ
}

// jwtHeader is the only header this package emits, and the only one it accepts.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

const algHS256 = "HS256"

// Signer issues and verifies HS256 tokens against one secret.
type Signer struct {
	secret []byte
	now    func() time.Time // seam for tests
}

// NewSigner returns a Signer over secret, which must be at least MinSecretLen
// bytes. The secret is copied, so the caller may reuse its buffer.
func NewSigner(secret []byte) (*Signer, error) {
	if len(secret) < MinSecretLen {
		return nil, fmt.Errorf("auth: signing secret must be at least %d bytes, got %d", MinSecretLen, len(secret))
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return &Signer{secret: cp, now: time.Now}, nil
}

// Issue returns a signed token for username with the given type and lifetime.
func (s *Signer) Issue(username, typ string, ttl time.Duration) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: generating token id: %w", err)
	}
	now := s.now()
	header, err := json.Marshal(jwtHeader{Alg: algHS256, Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("auth: encoding token header: %w", err)
	}
	payload, err := json.Marshal(Claims{
		Sub: username,
		Typ: typ,
		IAT: now.Unix(),
		Exp: now.Add(ttl).Unix(),
		JTI: hex.EncodeToString(raw),
	})
	if err != nil {
		return "", fmt.Errorf("auth: encoding token claims: %w", err)
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signing + "." + base64.RawURLEncoding.EncodeToString(s.sign(signing)), nil
}

// Verify checks a token's signature, algorithm, type and expiry, and returns
// its claims. wantType is TypeAccess or TypeRefresh.
func (s *Signer) Verify(token, wantType string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformedToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	// Signature first: nothing else in the token is trustworthy until it holds.
	if !hmac.Equal(sig, s.sign(parts[0]+"."+parts[1])) {
		return Claims{}, ErrBadSignature
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	var h jwtHeader
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return Claims{}, ErrMalformedToken
	}
	// HS256 is the only algorithm issued and the only one accepted. Dispatching
	// on the header's choice is where "alg: none" and algorithm-confusion bugs
	// come from, so this compares rather than switches.
	if h.Alg != algHS256 {
		return Claims{}, ErrBadSignature
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	var c Claims
	if err := json.Unmarshal(rawPayload, &c); err != nil {
		return Claims{}, ErrMalformedToken
	}
	if c.Sub == "" {
		return Claims{}, ErrMalformedToken
	}
	if c.Typ != wantType {
		return Claims{}, ErrWrongTokenType
	}
	if s.now().Unix() >= c.Exp {
		return Claims{}, ErrExpiredToken
	}
	return c, nil
}

func (s *Signer) sign(signingInput string) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(signingInput))
	return m.Sum(nil)
}
