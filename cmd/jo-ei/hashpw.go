package main

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

// newHashpwCmd builds the `jo-ei hashpw` subcommand. It is a constructor (not a
// package var) so tests can wire in their own stdin/stdout.
func newHashpwCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hashpw",
		Short: "Read a password from stdin and print its bcrypt hash",
		Long: "Reads a single line from stdin and prints its bcrypt hash on stdout, " +
			"for use in console.auth.users[].password_hash or the " +
			"JOEI_CONSOLE_AUTH_USERS environment variable.\n\n" +
			"Example: printf '%s' \"$PASSWORD\" | jo-ei hashpw",
		Args: cobra.NoArgs,
		RunE: runHashpw,
	}
}

func init() {
	rootCmd.AddCommand(newHashpwCmd())
}

func runHashpw(cmd *cobra.Command, _ []string) error {
	reader := bufio.NewReader(cmd.InOrStdin())
	line, err := reader.ReadString('\n')
	// A final line with no trailing newline returns io.EOF together with the
	// data, so only treat EOF as fatal when nothing was read.
	if err != nil && line == "" {
		return fmt.Errorf("reading password from stdin: %w", err)
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return fmt.Errorf("empty password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// bcrypt rejects passwords longer than 72 bytes.
		return fmt.Errorf("hashing password: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(hash))
	return nil
}
