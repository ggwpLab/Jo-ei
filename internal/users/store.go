package users

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/storage"
)

// Store persists users in SQLite.
type Store struct {
	db *storage.DB
}

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS users (
		username             TEXT PRIMARY KEY COLLATE NOCASE,
		password_hash        TEXT NOT NULL,
		role                 TEXT NOT NULL CHECK(role IN ('admin','operator')),
		disabled             INTEGER NOT NULL DEFAULT 0,
		must_change_password INTEGER NOT NULL DEFAULT 0,
		token_version        INTEGER NOT NULL DEFAULT 0,
		created_at           INTEGER NOT NULL,
		last_login_at        INTEGER
	)`,
}

// New runs the users migration on db and returns a Store.
func New(db *storage.DB) (*Store, error) {
	if err := db.ApplyMigrations("users", migrations); err != nil {
		return nil, fmt.Errorf("users migrations: %w", err)
	}
	return &Store{db: db}, nil
}

const selectCols = `username, password_hash, role, disabled, must_change_password, token_version, created_at, last_login_at`

type scanner interface{ Scan(dest ...any) error }

func scanUser(sc scanner) (User, error) {
	var (
		u                    User
		role                 string
		disabled, mustChange int
		created              int64
		lastLogin            sql.NullInt64
	)
	if err := sc.Scan(&u.Username, &u.PasswordHash, &role, &disabled, &mustChange, &u.TokenVersion, &created, &lastLogin); err != nil {
		return User{}, err
	}
	u.Role = Role(role)
	u.Disabled = disabled != 0
	u.MustChangePassword = mustChange != 0
	u.CreatedAt = time.Unix(created, 0)
	if lastLogin.Valid {
		t := time.Unix(lastLogin.Int64, 0)
		u.LastLoginAt = &t
	}
	return u, nil
}

// Get returns the user with the given (case-insensitive) name.
func (s *Store) Get(username string) (User, error) {
	u, err := scanUser(s.db.SQL().QueryRow(`SELECT `+selectCols+` FROM users WHERE username=?`, username))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("reading user: %w", err)
	}
	return u, nil
}

// List returns all users ordered by username, case-insensitively.
func (s *Store) List() ([]User, error) {
	rows, err := s.db.SQL().Query(`SELECT ` + selectCols + ` FROM users ORDER BY username COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// HasEnabledUsers reports whether at least one non-disabled user exists.
func (s *Store) HasEnabledUsers() (bool, error) {
	var n int
	if err := s.db.SQL().QueryRow(`SELECT COUNT(*) FROM users WHERE disabled=0`).Scan(&n); err != nil {
		return false, fmt.Errorf("counting users: %w", err)
	}
	return n > 0, nil
}

// HasAnyUsers reports whether the table holds at least one user, enabled or
// not. An empty table is what EnsureInitialAdmin fills.
func (s *Store) HasAnyUsers() (bool, error) {
	var n int
	if err := s.db.SQL().QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false, fmt.Errorf("counting users: %w", err)
	}
	return n > 0, nil
}

func validateNew(u User) error {
	if err := ValidateUsername(u.Username); err != nil {
		return err
	}
	if !u.Role.Valid() {
		return &ValidationError{Field: "role", Message: "must be admin or operator"}
	}
	return nil
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// insert adds u. A new row's token_version starts at the current Unix time in
// nanoseconds rather than 0: a deleted-and-recreated user must never reach a
// version the old row held, or the old account's unexpired tokens would verify
// again. Revocations still increment by one, and nobody bumps a row a billion
// times a second.
func insert(ex execer, u User) error {
	now := time.Now()
	_, err := ex.Exec(
		`INSERT INTO users (username, password_hash, role, disabled, must_change_password, token_version, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.Username, u.PasswordHash, string(u.Role), b2i(u.Disabled), b2i(u.MustChangePassword), now.UnixNano(), now.Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrExists
		}
		return fmt.Errorf("creating user: %w", err)
	}
	return nil
}

// Create validates and inserts u. ErrExists on a duplicate name in any case.
func (s *Store) Create(u User) error {
	if err := validateNew(u); err != nil {
		return err
	}
	return insert(s.db.SQL(), u)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// mutate runs fn on the current user inside a transaction. fn performs any
// guard checks and returns the SQL update to apply (empty for a no-op).
func (s *Store) mutate(username string, fn func(tx *sql.Tx, cur User) (query string, args []any, err error)) error {
	tx, err := s.db.SQL().Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	cur, err := scanUser(tx.QueryRow(`SELECT `+selectCols+` FROM users WHERE username=?`, username))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("reading user: %w", err)
	}
	q, args, err := fn(tx, cur)
	if err != nil {
		return err
	}
	if q != "" {
		if _, err := tx.Exec(q, args...); err != nil {
			return fmt.Errorf("updating user: %w", err)
		}
	}
	return tx.Commit()
}

// guardLastAdmin returns ErrLastAdmin if cur is an enabled admin and no other
// enabled admin exists.
func guardLastAdmin(tx *sql.Tx, cur User) error {
	if cur.Role != RoleAdmin || cur.Disabled {
		return nil
	}
	var n int
	err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0 AND username<>?`, cur.Username).Scan(&n)
	if err != nil {
		return fmt.Errorf("counting admins: %w", err)
	}
	if n == 0 {
		return ErrLastAdmin
	}
	return nil
}

// SetRole changes the user's role and revokes their sessions. Same role is a no-op.
func (s *Store) SetRole(username string, r Role) error {
	if !r.Valid() {
		return &ValidationError{Field: "role", Message: "must be admin or operator"}
	}
	return s.mutate(username, func(tx *sql.Tx, cur User) (string, []any, error) {
		if cur.Role == r {
			return "", nil, nil
		}
		if r != RoleAdmin {
			if err := guardLastAdmin(tx, cur); err != nil {
				return "", nil, err
			}
		}
		return `UPDATE users SET role=?, token_version=token_version+1 WHERE username=?`, []any{string(r), cur.Username}, nil
	})
}

// SetDisabled enables or disables the user and revokes their sessions.
// Setting the current value is a no-op.
func (s *Store) SetDisabled(username string, disabled bool) error {
	return s.mutate(username, func(tx *sql.Tx, cur User) (string, []any, error) {
		if cur.Disabled == disabled {
			return "", nil, nil
		}
		if disabled {
			if err := guardLastAdmin(tx, cur); err != nil {
				return "", nil, err
			}
		}
		return `UPDATE users SET disabled=?, token_version=token_version+1 WHERE username=?`, []any{b2i(disabled), cur.Username}, nil
	})
}

// SetPassword replaces the password hash and revokes the user's sessions.
func (s *Store) SetPassword(username, hash string, mustChange bool) error {
	return s.mutate(username, func(_ *sql.Tx, cur User) (string, []any, error) {
		return `UPDATE users SET password_hash=?, must_change_password=?, token_version=token_version+1 WHERE username=?`,
			[]any{hash, b2i(mustChange), cur.Username}, nil
	})
}

// Delete removes the user, refusing to remove the last enabled admin.
func (s *Store) Delete(username string) error {
	return s.mutate(username, func(tx *sql.Tx, cur User) (string, []any, error) {
		if err := guardLastAdmin(tx, cur); err != nil {
			return "", nil, err
		}
		return `DELETE FROM users WHERE username=?`, []any{cur.Username}, nil
	})
}

// TouchLogin records a successful login time.
func (s *Store) TouchLogin(username string, at time.Time) error {
	res, err := s.db.SQL().Exec(`UPDATE users SET last_login_at=? WHERE username=?`, at.Unix(), username)
	if err != nil {
		return fmt.Errorf("recording login: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// EnsureInitialAdmin creates the initial admin account when the users table
// is completely empty: user InitialAdminUsername, role admin, a generated
// password (returned so the caller can show it once) and
// must_change_password set. The emptiness check and the insert share one
// transaction. A table with any row, even only disabled users, is left alone
// and created is false.
func (s *Store) EnsureInitialAdmin() (password string, created bool, err error) {
	tx, err := s.db.SQL().Begin()
	if err != nil {
		return "", false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return "", false, fmt.Errorf("counting users: %w", err)
	}
	if n > 0 {
		return "", false, nil
	}
	password, err = GeneratePassword()
	if err != nil {
		return "", false, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return "", false, fmt.Errorf("hashing password: %w", err)
	}
	if err := insert(tx, User{
		Username: InitialAdminUsername, PasswordHash: hash, Role: RoleAdmin, MustChangePassword: true,
	}); err != nil {
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("commit: %w", err)
	}
	return password, true, nil
}

// ResetAdmin is the recovery path behind `jo-ei reset-admin-password`. In one
// transaction it either restores the InitialAdminUsername account — new
// password hash, must_change_password set, enabled, role admin, sessions
// revoked by a token_version bump — or, when that account was deleted,
// recreates it with the same properties (created is true). Restoring or
// enabling an admin can only add admins, so the last-admin guard never
// applies.
func (s *Store) ResetAdmin(hash string) (created bool, err error) {
	tx, err := s.db.SQL().Begin()
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(
		`UPDATE users SET password_hash=?, must_change_password=1, disabled=0, role='admin', token_version=token_version+1
		 WHERE username=?`, hash, InitialAdminUsername)
	if err != nil {
		return false, fmt.Errorf("resetting admin: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("resetting admin: %w", err)
	}
	if n == 0 {
		if err := insert(tx, User{
			Username: InitialAdminUsername, PasswordHash: hash, Role: RoleAdmin, MustChangePassword: true,
		}); err != nil {
			return false, err
		}
		created = true
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return created, nil
}
