package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// newResetAdminPasswordCmd builds `jo-ei reset-admin-password`, the recovery
// path for the console: it restores (or recreates) the "admin" account with a
// new temporary password. It is a constructor (not a package var) so tests can
// wire in their own stdout/stderr. It opens the database directly, so it also
// works while the server runs — the server re-reads users on every request.
func newResetAdminPasswordCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset-admin-password",
		Short: "Restore the console admin account with a new temporary password",
		Long: "Sets a new generated password on the console user \"admin\", re-enables it,\n" +
			"restores its admin role, requires a password change at next sign-in and\n" +
			"ends its sessions. If \"admin\" was deleted it is recreated.\n\n" +
			"Only the new password is printed on stdout; messages go to stderr.\n" +
			"Use the same --config as the server so the right database is opened.",
		Args: cobra.NoArgs,
		// A runtime failure (wrong --config) is not a usage error; keep the
		// usage text off stdout, which scripts capture for the password.
		SilenceUsage: true,
		RunE:         runResetAdminPassword,
	}
}

func init() {
	rootCmd.AddCommand(newResetAdminPasswordCmd())
}

func runResetAdminPassword(cmd *cobra.Command, _ []string) error {
	return withExistingUserStore(func(st *users.Store) error {
		password, err := users.GeneratePassword()
		if err != nil {
			return err
		}
		hash, err := users.HashPassword(password)
		if err != nil {
			return fmt.Errorf("hashing password: %w", err)
		}
		created, err := st.ResetAdmin(hash)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), password); err != nil {
			return fmt.Errorf("writing password: %w", err)
		}
		action := "reset"
		if created {
			action = "created"
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
			"user %q %s: role admin, enabled, sessions revoked; sign in with the password above and change it\n",
			users.InitialAdminUsername, action)
		return nil
	})
}

// withExistingUserStore loads the config, opens its database, runs fn and
// closes it. A missing database file almost always means the wrong --config,
// and silently creating an empty database there would hide that, so it is an
// error instead.
func withExistingUserStore(fn func(*users.Store) error) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}
	// Warn, never fail: this is the recovery tool.
	for _, p := range cfg.UnknownEnv {
		_, _ = fmt.Fprintln(os.Stderr, "warning: environment:", p)
	}
	if _, err := os.Stat(cfg.Database.Path); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("database %s does not exist: check --config (currently %q) points at the server's config file", cfg.Database.Path, cfgFile)
	} else if err != nil {
		return fmt.Errorf("checking database: %w", err)
	}
	db, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()
	st, err := users.New(db)
	if err != nil {
		return err
	}
	return fn(st)
}
