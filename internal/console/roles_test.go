package console_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// newHandler mounts the console handler with an admin identity, standing in
// for the session middleware.
func newHandler(cfg console.Config) http.Handler {
	return withIdentity(console.NewHandler(cfg), &auth.Identity{Username: "admin", Role: users.RoleAdmin})
}

func withIdentity(h http.Handler, id *auth.Identity) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id != nil {
			r = r.WithContext(auth.WithIdentity(r.Context(), *id))
		}
		h.ServeHTTP(w, r)
	})
}

func rolesHandler(t *testing.T, id *auth.Identity) http.Handler {
	t.Helper()
	return withIdentity(console.NewHandler(console.Config{
		Store:       newTelemetryStore(t),
		Broadcaster: telemetry.NewBroadcaster(),
		Policy:      policy.NewRuntime(config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24}, config.CVEConfig{}, config.PolicyProfile{}, nil),
		Cache:       &fakeStats{},
		Purger:      &fakePurger{},
		Logger:      zerolog.Nop(),
	}), id)
}

func doRole(h http.Handler, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var adminRoutes = [][2]string{
	{"PUT", "/api/policy"},
	{"PUT", "/api/registries"},
	{"POST", "/api/cache/cleanup"},
}

func TestRoles_OperatorReadsEverything(t *testing.T) {
	h := rolesHandler(t, &auth.Identity{Username: "op", Role: users.RoleOperator})
	for _, p := range []string{"/api/overview", "/api/requests", "/api/quarantine", "/api/policy", "/api/registries", "/api/metrics/daily"} {
		assert.NotEqual(t, http.StatusForbidden, doRole(h, "GET", p).Code, p)
	}
}

func TestRoles_OperatorForbiddenOnAdminRoutes(t *testing.T) {
	h := rolesHandler(t, &auth.Identity{Username: "op", Role: users.RoleOperator})
	for _, r := range adminRoutes {
		rec := doRole(h, r[0], r[1])
		require.Equal(t, http.StatusForbidden, rec.Code, r[1])
		assert.JSONEq(t, `{"error":"forbidden"}`, rec.Body.String())
	}
}

func TestRoles_AdminAllowed(t *testing.T) {
	h := rolesHandler(t, &auth.Identity{Username: "admin", Role: users.RoleAdmin})
	for _, r := range adminRoutes {
		assert.NotEqual(t, http.StatusForbidden, doRole(h, r[0], r[1]).Code, r[1])
	}
}

func TestRoles_NoIdentityForbidden(t *testing.T) {
	rec := doRole(rolesHandler(t, nil), "GET", "/api/overview")
	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.JSONEq(t, `{"error":"forbidden"}`, rec.Body.String())
}
