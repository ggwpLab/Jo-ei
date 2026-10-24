//go:build integration

package integration_test

import (
	"net/http"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// asAdmin injects an admin identity, standing in for the session middleware
// in tests that mount the console handler directly.
func asAdmin(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := auth.Identity{Username: "admin", Role: users.RoleAdmin}
		h.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
	})
}
