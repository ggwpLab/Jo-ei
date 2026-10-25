package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/health"
)

// readinessTimeout bounds the database check behind /ready.
const readinessTimeout = 2 * time.Second

// readinessHandler serves /ready: 200 when the database answers and no enabled
// scanner is down, 503 naming what is failing otherwise. /health only says the
// process is up; this says requests can actually be gated. A scanner that is
// merely unknown (osv.dev is tracked passively and has no data before the
// first CVE lookup) does not fail readiness.
func readinessHandler(db *sql.DB, scanners func() []health.ScannerHealth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failing := []string{}
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()
		var one int
		if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
			failing = append(failing, "database")
		}
		for _, sh := range scanners() {
			if sh.Enabled && sh.Status == health.StatusDown {
				failing = append(failing, sh.Name)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		body := map[string]any{"status": "ready"}
		if len(failing) > 0 {
			body = map[string]any{"status": "not_ready", "failing": failing}
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(body)
	})
}
