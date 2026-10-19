package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
)

// boundServer pairs a server with the listener it was pre-bound to, so a port
// clash surfaces before any server starts accepting traffic.
type boundServer struct {
	srv *http.Server
	ln  net.Listener
}

// serve runs srv until it errors or ctx is cancelled. On cancellation it
// gracefully drains in-flight requests with a bounded timeout. A clean
// shutdown returns nil.
func serve(ctx context.Context, srv *http.Server) error {
	return serveWith(ctx, srv, srv.ListenAndServe)
}

// serveListener is serve for a server whose listener is already bound.
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
