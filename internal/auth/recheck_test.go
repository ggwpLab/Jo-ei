package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// recheckThrough runs a request through the middleware and returns the
// request context the handler saw.
func recheckThrough(t *testing.T, s *auth.Sessions, tok string) context.Context {
	t.Helper()
	var got context.Context
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Context() })
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.Middleware(h).ServeHTTP(httptest.NewRecorder(), req)
	require.NotNil(t, got, "the handler must have run")
	return got
}

func TestRecheck_FollowsUserState(t *testing.T) {
	for name, change := range map[string]func(*fakeStore){
		"disabled":         func(f *fakeStore) { _ = f.update("anna", func(u *users.User) { u.Disabled = true }) },
		"deleted":          func(f *fakeStore) { f.remove("anna") },
		"version bumped":   func(f *fakeStore) { _ = f.update("anna", func(u *users.User) { u.TokenVersion++ }) },
		"must change pass": func(f *fakeStore) { _ = f.update("anna", func(u *users.User) { u.MustChangePassword = true }) },
	} {
		t.Run(name, func(t *testing.T) {
			store := newStore(adminUser(t), operator(t, "anna", "secret"))
			s := sessionsWith(t, store)
			ctx := recheckThrough(t, s, loginToken(t, s, "anna", "secret"))
			assert.True(t, auth.Recheck(ctx), "unchanged user is still valid")
			change(store)
			assert.False(t, auth.Recheck(ctx))
		})
	}
}

func TestRecheck_WithoutMiddlewareIsTrue(t *testing.T) {
	assert.True(t, auth.Recheck(context.Background()))
	assert.False(t, auth.Recheck(auth.WithRecheck(context.Background(), func() bool { return false })))
}
