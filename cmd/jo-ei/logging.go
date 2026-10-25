package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/config"
)

// setupLogging sets the global level and builds the base logger every
// subsystem tags with its own component, plus serverLog for startup and wiring
// messages. A log file is registered for closing on a. An unknown level falls
// back to info with a warning.
func setupLogging(a *app, cfg config.LoggingConfig) (base, serverLog zerolog.Logger, err error) {
	level, levelErr := zerolog.ParseLevel(cfg.Level)
	if levelErr != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	logOut, closeLog, err := logWriter(cfg.Output)
	if err != nil {
		return zerolog.Logger{}, zerolog.Logger{}, err
	}
	a.onClose(closeLog)

	if cfg.Format == "text" {
		base = zerolog.New(zerolog.ConsoleWriter{Out: logOut, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger()
	} else {
		base = zerolog.New(logOut).With().Timestamp().Logger()
	}
	serverLog = base.With().Str("component", "server").Logger()
	if levelErr != nil {
		serverLog.Warn().Str("value", cfg.Level).Msg("unknown log level; defaulting to info")
	}
	return base, serverLog, nil
}

// logWriter resolves a logging.output value to a writer and a close function.
// "" or "stderr" → os.Stderr, "stdout" → os.Stdout, anything else → a file
// opened for append. The returned closeFn is a no-op for the standard streams.
func logWriter(output string) (io.Writer, func() error, error) {
	switch output {
	case "", "stderr":
		return os.Stderr, func() error { return nil }, nil
	case "stdout":
		return os.Stdout, func() error { return nil }, nil
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644) // #nosec G302 G304 -- operator-configured log path; log file, not a secret
		if err != nil {
			return nil, nil, fmt.Errorf("opening log output %q: %w", output, err)
		}
		return f, f.Close, nil
	}
}
