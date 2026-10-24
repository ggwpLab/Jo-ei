package main

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// ignoredUsersWarning is logged when config/env users are set but the users
// table already has users.
const ignoredUsersWarning = "console.auth.users / JOEI_CONSOLE_AUTH_USERS are ignored: users are managed in the database (console Users page or jo-ei user)"

// bootstrapUsers seeds the users table from config/env credentials, once.
// Users live in the database after that: config/env entries seen against a
// non-empty table are ignored with a warning — not even parsed, so a stale or
// malformed entry cannot stop startup or silently change who may sign in.
// Only against an empty table are they parsed and validated, and a failure is
// returned so startup fails.
func bootstrapUsers(store *users.Store, fileUsers []auth.User, envValue string, log zerolog.Logger) error {
	if len(fileUsers) == 0 && strings.Trim(envValue, " \t;") == "" {
		return nil
	}
	exists, err := store.HasAnyUsers()
	if err != nil {
		return fmt.Errorf("checking for console users: %w", err)
	}
	if exists {
		log.Warn().Msg(ignoredUsersWarning)
		return nil
	}
	parsed, err := auth.ParseBootstrapUsers(fileUsers, envValue)
	if err != nil {
		return err
	}
	if len(parsed) == 0 {
		return nil
	}
	seed := make([]users.User, len(parsed))
	for i, u := range parsed {
		seed[i] = users.User{Username: u.Username, PasswordHash: u.PasswordHash, Role: users.RoleAdmin}
	}
	n, err := store.ImportIfEmpty(seed)
	if err != nil {
		return fmt.Errorf("importing console users from config: %w", err)
	}
	if n > 0 {
		log.Info().Msgf("imported %d console users from config", n)
		return nil
	}
	// Someone (jo-ei user create) filled the table between the check and the
	// import.
	log.Warn().Msg(ignoredUsersWarning)
	return nil
}
