package main

import (
	"fmt"
	"io"
	"os"
)

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
