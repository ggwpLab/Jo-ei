// Package users stores console users (username, bcrypt hash, role) in the
// shared SQLite database and validates the credentials that go into it.
package users

import (
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// Role is a console permission level.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
)

// Valid reports whether r is one of the known roles.
func (r Role) Valid() bool { return r == RoleAdmin || r == RoleOperator }

// User is a console account. Username keeps the case it was created with;
// lookups are case-insensitive.
type User struct {
	Username           string
	PasswordHash       string
	Role               Role
	Disabled           bool
	MustChangePassword bool
	TokenVersion       int64
	CreatedAt          time.Time
	LastLoginAt        *time.Time
}

var (
	ErrNotFound  = errors.New("user not found")
	ErrExists    = errors.New("user already exists")
	ErrLastAdmin = errors.New("operation would leave no enabled admin")
)

// ValidationError describes an invalid user field.
type ValidationError struct{ Field, Message string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Message }

const (
	minPasswordRunes = 12
	maxPasswordBytes = 72 // bcrypt silently truncates beyond this; reject instead
)

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// ValidateUsername accepts 1-64 characters of [A-Za-z0-9._@-].
func ValidateUsername(name string) error {
	if !usernameRe.MatchString(name) {
		return &ValidationError{Field: "username", Message: "must be 1-64 characters of letters, digits, '.', '_', '@' or '-'"}
	}
	return nil
}

// ValidatePassword requires at least 12 characters, at most 72 bytes, and a
// password different from the username (case-insensitive).
func ValidatePassword(username, password string) error {
	if utf8.RuneCountInString(password) < minPasswordRunes {
		return &ValidationError{Field: "password", Message: "must be at least 12 characters"}
	}
	if len(password) > maxPasswordBytes {
		return &ValidationError{Field: "password", Message: "must be at most 72 bytes"}
	}
	if strings.EqualFold(password, username) {
		return &ValidationError{Field: "password", Message: "must not equal the username"}
	}
	return nil
}

// HashPassword returns a bcrypt hash of password at the default cost.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// CheckPassword reports whether password matches hash. A malformed hash
// never matches.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
