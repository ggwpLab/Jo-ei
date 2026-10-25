package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/health"
)

// readinessTimeout bounds the database check behind /ready.
const readinessTimeout = 2 * time.Second

// readinessCacheTTL is how long one evaluation answers every probe. /ready is
// public, and each evaluation takes the single SQLite connection the data
// path's telemetry writes also need.
const readinessCacheTTL = 2 * time.Second

// readinessHandler serves /ready: 200 when the database answers and no
// enabled, actively probed scanner is down; 503 naming what is failing
// otherwise. /health only says the process is up; this says requests can
// actually be gated. Unknown does not fail readiness, and neither does a
// passively tracked engine (osv.dev): its status is its last lookup, which on
// an idle instance can stay "down" long after the outage — and a probe that
// takes the instance out of rotation would stop the traffic that clears it.
func readinessHandler(db *sql.DB, scanners func() []health.ScannerHealth) http.Handler {
	var (
		mu      sync.Mutex
		at      time.Time
		code    int
		payload []byte
	)
	evaluate := func(ctx context.Context) (int, []byte) {
		failing := []string{}
		ctx, cancel := context.WithTimeout(ctx, readinessTimeout)
		defer cancel()
		var one int
		if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
			failing = append(failing, "database")
		}
		for _, sh := range scanners() {
			if sh.Enabled && !sh.Passive && sh.Status == health.StatusDown {
				failing = append(failing, sh.Name)
			}
		}
		if len(failing) > 0 {
			b, _ := json.Marshal(map[string]any{"status": "not_ready", "failing": failing})
			return http.StatusServiceUnavailable, b
		}
		b, _ := json.Marshal(map[string]any{"status": "ready"})
		return http.StatusOK, b
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Held across the evaluation, so concurrent probes wait for one
		// result instead of each running their own.
		mu.Lock()
		if time.Since(at) >= readinessCacheTTL {
			code, payload = evaluate(r.Context())
			at = time.Now()
		}
		c, p := code, payload
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(c)
		_, _ = w.Write(p)
	})
}
