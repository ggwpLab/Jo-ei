package main

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// serve runs srv until it errors or ctx is cancelled. On cancellation it
// gracefully drains in-flight requests with a bounded timeout. A clean
// shutdown returns nil.
func serve(ctx context.Context, srv *http.Server) error {
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
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
