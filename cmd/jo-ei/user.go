package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

const (
	generatedPasswordLen      = 20
	generatedPasswordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// newUserCmd builds `jo-ei user`, the offline/recovery path for console users.
// It opens the database directly, so it also works while the server runs.
func newUserCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "user",
		Short: "Create console users, reset passwords and list users",
	}

	var role string
	var generate, noForce bool

	create := &cobra.Command{
		Use:   "create <name> --role admin|operator",
		Short: "Create a console user (password from the first stdin line, or --generate)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := users.Role(role)
			if !r.Valid() {
				return fmt.Errorf("invalid role %q: must be %q or %q", role, users.RoleAdmin, users.RoleOperator)
			}
			name := args[0]
			if err := users.ValidateUsername(name); err != nil {
				return err
			}
			password, err := obtainPassword(cmd, name, generate)
			if err != nil {
				return err
			}
			hash, err := users.HashPassword(password)
			if err != nil {
				return err
			}
			return withUserStore(func(st *users.Store) error {
				err := st.Create(users.User{
					Username: name, PasswordHash: hash, Role: r,
					MustChangePassword: !noForce,
				})
				if errors.Is(err, users.ErrExists) {
					return fmt.Errorf("user %q already exists", name)
				}
				if err != nil {
					return err
				}
				return emitPassword(cmd, password, generate)
			})
		},
	}
	create.Flags().StringVar(&role, "role", "", "role: admin or operator (required)")
	_ = create.MarkFlagRequired("role")
	create.Flags().BoolVar(&generate, "generate", false, "generate a random password and print it on stdout")
	create.Flags().BoolVar(&noForce, "no-force-change", false, "do not require a password change at next sign-in")

	var rGenerate, rNoForce bool
	reset := &cobra.Command{
		Use:   "reset-password <name>",
		Short: "Set a user's password, revoke their sessions and re-enable them",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			password, err := obtainPassword(cmd, name, rGenerate)
			if err != nil {
				return err
			}
			hash, err := users.HashPassword(password)
			if err != nil {
				return err
			}
			return withUserStore(func(st *users.Store) error {
				if err := st.SetPassword(name, hash, !rNoForce); err != nil {
					if errors.Is(err, users.ErrNotFound) {
						return fmt.Errorf("user %q not found", name)
					}
					return err
				}
				if err := st.SetDisabled(name, false); err != nil {
					return err
				}
				return emitPassword(cmd, password, rGenerate)
			})
		},
	}
	reset.Flags().BoolVar(&rGenerate, "generate", false, "generate a random password and print it on stdout")
	reset.Flags().BoolVar(&rNoForce, "no-force-change", false, "do not require a password change at next sign-in")

	list := &cobra.Command{
		Use:   "list",
		Short: "List console users",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withUserStore(func(st *users.Store) error {
				us, err := st.List()
				if err != nil {
					return err
				}
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintln(tw, "USERNAME\tROLE\tSTATUS\tLAST LOGIN")
				for _, u := range us {
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", u.Username, u.Role, userStatus(u), lastLogin(u))
				}
				return tw.Flush()
			})
		},
	}

	root.AddCommand(create, reset, list)
	return root
}

func init() {
	rootCmd.AddCommand(newUserCmd())
}

func userStatus(u users.User) string {
	switch {
	case u.Disabled:
		return "disabled"
	case u.MustChangePassword:
		return "must change password"
	default:
		return "active"
	}
}

func lastLogin(u users.User) string {
	if u.LastLoginAt == nil {
		return "never"
	}
	return u.LastLoginAt.UTC().Format(time.RFC3339)
}

// obtainPassword returns a generated password or the validated first stdin line.
func obtainPassword(cmd *cobra.Command, username string, generate bool) (string, error) {
	var password string
	var err error
	if generate {
		password, err = generatePassword()
	} else {
		password, err = readPasswordLine(cmd.InOrStdin())
	}
	if err != nil {
		return "", err
	}
	if err := users.ValidatePassword(username, password); err != nil {
		return "", err
	}
	return password, nil
}

// emitPassword prints a generated password (only the password, one line) on
// stdout so scripts can capture it; the confirmation goes to stderr.
func emitPassword(cmd *cobra.Command, password string, generated bool) error {
	if generated {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), password); err != nil {
			return fmt.Errorf("writing password: %w", err)
		}
	}
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "ok")
	return nil
}

func generatePassword() (string, error) {
	var b strings.Builder
	limit := big.NewInt(int64(len(generatedPasswordAlphabet)))
	for i := 0; i < generatedPasswordLen; i++ {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("generating password: %w", err)
		}
		b.WriteByte(generatedPasswordAlphabet[n.Int64()])
	}
	return b.String(), nil
}

// withUserStore loads the config, opens the database, runs fn and closes it.
func withUserStore(fn func(*users.Store) error) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
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
