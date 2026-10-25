package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/metrics"
)

// boundServer pairs a server with the listener it was pre-bound to, so a port
// clash surfaces before any server starts accepting traffic.
type boundServer struct {
	srv *http.Server
	ln  net.Listener
}

// bindServers binds the metrics listener (when metrics are enabled) and then
// the main one, before any of them serves, so a port clash — notably on
// metrics.listen — stops startup before the proxy accepts traffic. Each bound
// listener is registered for closing on a (a no-op once its server has shut
// down).
func bindServers(a *app, cfg *config.Config, handler http.Handler, mx *metrics.Metrics) ([]boundServer, error) {
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
		servers = append(servers, boundServer{metricsSrv, ln})
	}
	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      handler,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return nil, fmt.Errorf("server.listen %s: %w", cfg.Server.Listen, err)
	}
	a.onClose(ln.Close)
	return append(servers, boundServer{srv, ln}), nil
}

// serveListener runs srv on its pre-bound listener until it errors or ctx is
// cancelled. On cancellation it gracefully drains in-flight requests with a
// bounded timeout. A clean shutdown returns nil.
func serveListener(ctx context.Context, srv *http.Server, ln net.Listener) error {
	return serveWith(ctx, srv, func() error { return srv.Serve(ln) })
}

func serveWith(ctx context.Context, srv *http.Server, run func() error) error {
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// serveAll runs every server until ctx is cancelled or one of them fails; the
// first failure shuts the others down and is returned.
func serveAll(ctx context.Context, servers ...boundServer) error {
	g, gctx := errgroup.WithContext(ctx)
	for _, s := range servers {
		g.Go(func() error { return serveListener(gctx, s.srv, s.ln) })
	}
	return g.Wait()
}
