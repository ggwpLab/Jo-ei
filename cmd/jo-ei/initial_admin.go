package main

import (
	"fmt"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/users"
)

// ensureInitialAdmin creates the initial admin on a completely empty users
// table and logs its temporary password — the only place a password is ever
// logged, and only at creation, so later restarts never repeat it. A table
// with any row (even only disabled users) is left alone.
func ensureInitialAdmin(store *users.Store, log zerolog.Logger) error {
	password, created, err := store.EnsureInitialAdmin()
	if err != nil {
		return fmt.Errorf("creating the initial admin user: %w", err)
	}
	if !created {
		return nil
	}
	log.Warn().
		Str("user", users.InitialAdminUsername).
		Str("password", password).
		Str("hint", "temporary password: change it at first sign-in; lost it? run jo-ei reset-admin-password").
		Msg("created initial admin user")
	return nil
}
