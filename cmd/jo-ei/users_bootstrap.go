package main

import (
	"fmt"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// bootstrapUsers seeds the users table from config/env credentials, once.
// Users live in the database after that: config/env entries seen against a
// non-empty table are ignored with a warning, so editing them cannot silently
// change who may sign in. Validation failures are returned so startup fails.
func bootstrapUsers(store *users.Store, fileUsers []auth.User, envValue string, log zerolog.Logger) error {
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
	log.Warn().Msg("console.auth.users / JOEI_CONSOLE_AUTH_USERS are ignored: users are managed in the database (console Users page or jo-ei user)")
	return nil
}
