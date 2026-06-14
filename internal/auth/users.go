// Package auth provides HTTP Basic authentication for the admin console and
// API. Credentials are a set of username + bcrypt password-hash pairs loaded
// from config and the JOEI_CONSOLE_AUTH_USERS environment variable. With no
// users configured the set is "locked" (fail-closed): the middleware serves
// 503 and never reaches the wrapped handler.
package auth

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// User is one credential: a username and its bcrypt password hash.
type User struct {
	Username     string
	PasswordHash string
}

// Users is a validated set of credentials. An empty set is the locked state.
type Users struct {
	byName map[string]string // username -> bcrypt hash
}

// dummyHash is compared against when an unknown username is supplied so that
// response timing does not reveal whether a username exists. Generated once at
// package load at the default cost.
var dummyHash []byte

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("joei-timing-dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		panic("auth: generating dummy hash: " + err.Error())
	}
	dummyHash = h
}

// NewUsers builds the credential set from config-file users and the
// semicolon-separated JOEI_CONSOLE_AUTH_USERS env value
// ("username:hash;username:hash"). Whitespace around entries is trimmed. Env
// entries override file entries with the same username. Every username must be
// non-empty and every hash must be a valid bcrypt hash, else an error is
// returned. An empty result is valid and yields the locked state.
func NewUsers(fileUsers []User, envValue string) (*Users, error) {
	byName := map[string]string{}

	add := func(username, passwordHash, src string) error {
		name := strings.TrimSpace(username)
		if name == "" {
			return fmt.Errorf("auth: %s: empty username", src)
		}
		h := strings.TrimSpace(passwordHash)
		if _, err := bcrypt.Cost([]byte(h)); err != nil {
			return fmt.Errorf("auth: %s: user %q: password_hash is not a valid bcrypt hash: %w", src, name, err)
		}
		byName[name] = h
		return nil
	}

	for _, u := range fileUsers {
		if err := add(u.Username, u.PasswordHash, "config"); err != nil {
			return nil, err
		}
	}
	for _, entry := range strings.Split(envValue, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// bcrypt hashes contain no ':' and usernames may not, so split on the
		// first ':' — everything after it is the hash.
		name, h, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("auth: JOEI_CONSOLE_AUTH_USERS entry %q must be username:hash", entry)
		}
		if err := add(name, h, "JOEI_CONSOLE_AUTH_USERS"); err != nil {
			return nil, err
		}
	}

	return &Users{byName: byName}, nil
}

// Locked reports whether no users are configured (fail-closed state).
func (u *Users) Locked() bool { return len(u.byName) == 0 }

// Verify reports whether username/password match a configured user. For an
// unknown username it still performs a bcrypt comparison against a dummy hash
// so timing does not reveal which usernames exist. It is safe to call on a
// locked (empty) set — it simply returns false.
func (u *Users) Verify(username, password string) bool {
	h, ok := u.byName[username]
	if !ok {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) == nil
}
