package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/ggwpLab/Jo-ei/internal/config"
)

// healthcheckTimeout bounds one healthcheck probe.
const healthcheckTimeout = 3 * time.Second

// newHealthcheckCmd builds "jo-ei healthcheck": a probe the distroless image
// can run as a container healthcheck (it has no shell or curl). It reads
// server.listen from the config and exits non-zero unless /health — or
// /ready with --ready — answers 200.
func newHealthcheckCmd() *cobra.Command {
	var ready bool
	cmd := &cobra.Command{
		Use:          "healthcheck",
		Short:        "Probe the running proxy's /health (or /ready) endpoint",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}
			url, err := healthcheckURL(cfg.Server.Listen, ready)
			if err != nil {
				return err
			}
			return probe(cmd.Context(), url)
		},
	}
	cmd.Flags().BoolVar(&ready, "ready", false, "probe /ready (database and scanners) instead of /health")
	return cmd
}

func init() {
	rootCmd.AddCommand(newHealthcheckCmd())
}

// healthcheckURL turns server.listen into the URL to probe. A wildcard or
// empty host is probed on loopback; a specific host is probed as configured,
// since the server may not listen on loopback at all.
func healthcheckURL(listen string, ready bool) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("server.listen %q: %w", listen, err)
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	path := "/health"
	if ready {
		path = "/ready"
	}
	return "http://" + net.JoinHostPort(host, port) + path, nil
}

// probe GETs url and fails unless it answers 200.
func probe(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req) // #nosec G107 G704 -- loopback or the configured listen address
	if err != nil {
		return fmt.Errorf("probing %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probing %s: HTTP %d", url, resp.StatusCode)
	}
	return nil
}
