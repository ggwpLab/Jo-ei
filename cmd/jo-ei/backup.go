package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

// newBackupCmd builds "jo-ei backup": a consistent online copy of the state
// database (users, signing key, policy, registries, telemetry), safe to run
// while the proxy is serving. The artifact cache and its index are not
// included: they are disposable and rebuilt on demand.
func newBackupCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:          "backup",
		Short:        "Write a consistent copy of the state database to --output",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}
			warnUnknownEnv(cmd, cfg)
			if err := backupDatabase(cfg.Database.Path, output); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), output)
			return err
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "file to write the backup to (must not exist)")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func init() {
	rootCmd.AddCommand(newBackupCmd())
}

// backupDatabase copies the SQLite database at dbPath to out with VACUUM INTO:
// a single read transaction, so the copy is consistent even while the server
// writes (WAL mode), and compacted. An existing out is never overwritten.
func backupDatabase(dbPath, out string) error {
	if _, err := os.Stat(dbPath); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("database %s does not exist: check --config (currently %q) points at the server's config file", dbPath, cfgFile)
	} else if err != nil {
		return fmt.Errorf("checking database: %w", err)
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	// Create the file first, exclusively and owner-only: it will hold the
	// console's password hashes and the session signing key. VACUUM INTO
	// accepts an existing empty file, and O_EXCL makes "never overwrite"
	// atomic.
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- operator-supplied backup path
	switch {
	case errors.Is(err, fs.ErrExist):
		return fmt.Errorf("backup output %s already exists", out)
	case err != nil:
		return fmt.Errorf("creating backup output in %s: %w", filepath.Dir(abs), err)
	}
	_ = f.Close()

	db, err := storage.Open(dbPath)
	if err != nil {
		_ = os.Remove(abs)
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.SQL().Exec("VACUUM INTO ?", abs); err != nil {
		_ = os.Remove(abs)
		return fmt.Errorf("backing up %s to %s: %w", dbPath, out, err)
	}
	return nil
}
