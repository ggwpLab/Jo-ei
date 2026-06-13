package auth

import (
	"context"
	"net/http"
)

type ctxKey struct{}

// Middleware wraps h with HTTP Basic authentication.
//
//   - Locked (no users configured): serves 503 and never calls h.
//   - Missing or invalid credentials: serves 401 with a Basic challenge.
//   - Valid credentials: stores the username in the request context (see
//     UserFromContext) and calls h.
func (u *Users) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u.Locked() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"auth_not_configured"}` + "\n"))
			return
		}
		username, password, ok := r.BasicAuth()
		if !ok || !u.Verify(username, password) {
			// Realm is ASCII on purpose: HTTP header values must be ASCII.
			w.Header().Set("WWW-Authenticate", `Basic realm="Joei Console", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, username)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserFromContext returns the authenticated username stored by Middleware, and
// false when the request did not pass through the authenticating middleware.
func UserFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(ctxKey{}).(string)
	return name, ok
}
