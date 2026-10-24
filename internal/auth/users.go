// Package auth provides JWT session authentication for the admin console and
// API. Console accounts (username, bcrypt hash, role, disabled flag, token
// version) live in the users store (internal/users); config.yaml and the
// JOEI_CONSOLE_AUTH_USERS environment variable only bootstrap that store (see
// ParseBootstrapUsers). A successful POST /api/auth/login exchanges a
// username and password for an HS256-signed session: HttpOnly access/refresh
// cookies for the browser console, and a bearer access token in the response
// body for scripts and CI. Every request re-reads its user from the store, so
// disabling, deleting or bumping a user's token version revokes their
// sessions at once. The /api/auth/* endpoints (login, refresh, logout, me,
// password) and the session-verifying middleware live in this package. With
// no enabled users the console is "locked" (fail-closed): the middleware
// serves 503 on /api/ and never reaches the wrapped handler — the console
// shell itself stays public so its login screen can still render.
package auth

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// User is one bootstrap credential from config or the environment: a username
// and its bcrypt password hash.
type User struct {
	Username     string
	PasswordHash string
}

// ParseBootstrapUsers validates config-file users and the semicolon-separated
// JOEI_CONSOLE_AUTH_USERS env value ("username:hash;username:hash") and
// returns the merged list. Whitespace around entries is trimmed. An env entry
// overrides a file entry with the same username (compared case-insensitively,
// as usernames are), keeping the file entry's position. Every username must
// be non-empty and every hash a valid bcrypt hash, else an error is returned.
// An empty result is valid.
func ParseBootstrapUsers(fileUsers []User, envValue string) ([]User, error) {
	var out []User
	index := map[string]int{} // lower-cased username -> position in out

	add := func(username, passwordHash, src string) error {
		name := strings.TrimSpace(username)
		if name == "" {
			return fmt.Errorf("auth: %s: empty username", src)
		}
		h := strings.TrimSpace(passwordHash)
		if _, err := bcrypt.Cost([]byte(h)); err != nil {
			return fmt.Errorf("auth: %s: user %q: password_hash is not a valid bcrypt hash: %w", src, name, err)
		}
		u := User{Username: name, PasswordHash: h}
		key := strings.ToLower(name)
		if i, ok := index[key]; ok {
			out[i] = u
			return nil
		}
		index[key] = len(out)
		out = append(out, u)
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
	return out, nil
}
