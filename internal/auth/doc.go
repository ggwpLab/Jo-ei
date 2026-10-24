// Package auth provides JWT session authentication for the admin console and
// API. Console accounts (username, bcrypt hash, role, disabled flag, token
// version) live in the users store (internal/users); on first start, with an
// empty store, cmd/jo-ei creates the initial "admin" account. A successful
// POST /api/auth/login exchanges a username and password for an HS256-signed
// session: HttpOnly access/refresh cookies for the browser console, and a
// bearer access token in the response body for scripts and CI. Every request
// re-reads its user from the store, so disabling, deleting or bumping a
// user's token version revokes their sessions at once. The /api/auth/*
// endpoints (login, refresh, logout, me, password) and the session-verifying
// middleware live in this package. With no enabled users the console is
// "locked" (fail-closed): the middleware serves 503 on /api/ and never
// reaches the wrapped handler — the console shell itself stays public so its
// login screen can still render.
package auth
