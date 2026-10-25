package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/metrics"
)

// boundServer pairs a server with the listener it was pre-bound to, so a port
// clash surfaces before any server starts accepting traffic.
type boundServer struct {
	srv *http.Server
	ln  net.Listener
	// drain bounds the graceful shutdown before remaining connections are
	// closed.
	drain time.Duration
	log   zerolog.Logger
}

// bindServers binds the metrics listener (when metrics are enabled) and then
// the main one, before any of them serves, so a port clash — notably on
// metrics.listen — stops startup before the proxy accepts traffic. Each bound
// listener is registered for closing on a (a no-op once its server has shut
// down).
func bindServers(a *app, cfg *config.Config, handler http.Handler, mx *metrics.Metrics, log zerolog.Logger) ([]boundServer, error) {
	var servers []boundServer
	if mx != nil {
		mmux := http.NewServeMux()
		mmux.Handle(cfg.Metrics.Path, mx.Handler())
		metricsSrv := &http.Server{
			Handler:           mmux,
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      30 * time.Second,
		}
		ln, err := net.Listen("tcp", cfg.Metrics.Listen)
		if err != nil {
			return nil, fmt.Errorf("metrics.listen %s: %w", cfg.Metrics.Listen, err)
		}
		a.onClose(ln.Close)
		servers = append(servers, boundServer{metricsSrv, ln, metricsDrain, log})
	}
	// No ReadTimeout or WriteTimeout: a gated request downloads and scans
	// before it answers, which can take minutes for a multi-GB artifact or a
	// cold image. WriteTimeout would cut that response, and an expired
	// ReadTimeout cancels the running handler's context through the server's
	// background read. Upstream fetches, request bodies and client writes are
	// bounded by progress instead (httpx.IdleTimeout, httpx.BodyReadDeadline,
	// httpx.CopyWithWriteDeadline).
	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return nil, fmt.Errorf("server.listen %s: %w", cfg.Server.Listen, err)
	}
	a.onClose(ln.Close)
	drain := time.Duration(cfg.Server.ShutdownTimeoutSeconds) * time.Second
	if drain <= 0 {
		drain = defaultDrain
	}
	return append(servers, boundServer{srv, ln, drain, log}), nil
}

// Drain bounds: the main server's default (server.shutdown_timeout_seconds),
// and the metrics server's, whose scrapes are short.
const (
	defaultDrain = 30 * time.Second
	metricsDrain = 5 * time.Second
)

// serveListener runs srv on its pre-bound listener until it errors or ctx is
// cancelled. On cancellation it drains in-flight requests for up to drain,
// then closes whatever is still open: a client that never finishes is not a
// failure of the process, so running out the deadline still returns nil.
func serveListener(ctx context.Context, srv *http.Server, ln net.Listener, drain time.Duration, log zerolog.Logger) error {
	return serveWith(ctx, srv, drain, log, func() error { return srv.Serve(ln) })
}

func serveWith(ctx context.Context, srv *http.Server, drain time.Duration, log zerolog.Logger, run func() error) error {
	errCh := make(chan error, 1)
	go func() {
		err := run()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), drain)
		defer cancel()
		err := srv.Shutdown(shutdownCtx)
		if errors.Is(err, context.DeadlineExceeded) {
			log.Warn().Dur("drain", drain).Msg("shutdown deadline passed; closing remaining connections")
			return srv.Close()
		}
		return err
	}
}

// serveAll runs every server until ctx is cancelled or one of them fails; the
// first failure shuts the others down and is returned.
func serveAll(ctx context.Context, servers ...boundServer) error {
	g, gctx := errgroup.WithContext(ctx)
	for _, s := range servers {
		g.Go(func() error { return serveListener(gctx, s.srv, s.ln, s.drain, s.log) })
	}
	return g.Wait()
}
