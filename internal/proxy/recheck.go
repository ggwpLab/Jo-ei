package proxy

import (
	"context"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

func (h *Handler) serveCached(ctx context.Context, w http.ResponseWriter, requestID string, ref *gate.PackageRef, entry *gate.ArtifactEntry, record recordOutcome, log zerolog.Logger) {
	if !entry.ScanClean {
		record(gate.VerdictBlock, gate.GateCache, "scan_failed", http.StatusForbidden, nil)
		h.writeError(w, requestID, ref, http.StatusForbidden, "scan_failed")
		return
	}
	if out := h.recheckExpired(ctx, ref, entry, log); out != nil {
		log.Warn().Str("gate", out.gate).Msg("cached artifact failed re-check; evicted")
		switch out.gate {
		case gate.GateCVE:
			h.blockCVE(w, requestID, ref, out.decision, record)
		case gate.GateMalware:
			h.blockMalware(w, requestID, ref, out.av, record)
		}
		return
	}
	if err := h.serveFromCache(w, entry, log); err != nil {
		record(gate.VerdictError, gate.GateCache, "cache_read_error", http.StatusInternalServerError, nil)
		return
	}
	record(gate.VerdictCache, gate.GateCache, "cache_hit", http.StatusOK, nil)
}

// recheckOutcome is the shared result of one coalesced re-check flight.
// nil means "serve from cache": every check passed, was skipped, or failed
// against an unreachable scanner (stale serve).
type recheckOutcome struct {
	gate     string              // gate.GateCVE | gate.GateMalware
	decision gate.PolicyDecision // CVE block details
	av       *gate.AVResult      // malware block details
}

// recheckDue reports which configured gates have expired for this entry.
func (h *Handler) recheckDue(entry *gate.ArtifactEntry, now time.Time) (cve, malware bool) {
	cve = h.cfg.CVERecheckTTL > 0 && h.cfg.CVEScanner != nil && h.cfg.Policy != nil &&
		now.Sub(entry.LastCVECheck) > h.cfg.CVERecheckTTL
	malware = h.cfg.MalwareRecheckTTL > 0 && h.cfg.AVScanner != nil &&
		now.Sub(entry.LastMalwareCheck) > h.cfg.MalwareRecheckTTL
	return cve, malware
}

// recheckExpired lazily re-runs each gate whose TTL has lapsed for a cache
// hit. Concurrent requests for the same entry coalesce into one flight: the
// leader scans and evicts on a block. Every waiter receives the same result
// and writes its own response and telemetry event.
func (h *Handler) recheckExpired(ctx context.Context, ref *gate.PackageRef, entry *gate.ArtifactEntry, log zerolog.Logger) *recheckOutcome {
	if cve, malware := h.recheckDue(entry, time.Now()); !cve && !malware {
		return nil
	}
	// WithoutCancel: the flight's scan serves every waiter — a leader whose
	// client disconnects must not cancel it for the others.
	flightCtx := context.WithoutCancel(ctx)
	v, _, _ := h.recheckGroup.Do(ref.Key(), func() (any, error) {
		return h.runRechecks(flightCtx, ref, entry, log), nil
	})
	out, _ := v.(*recheckOutcome)
	return out
}

// runRechecks executes the expired-gate re-checks once per flight: CVE+policy
// against current metadata, then malware against the cached bytes (cheap
// metadata check first). Evicts on a block; bumps a gate's timestamp only on
// a passed check.
func (h *Handler) runRechecks(ctx context.Context, ref *gate.PackageRef, entry *gate.ArtifactEntry, log zerolog.Logger) *recheckOutcome {
	now := time.Now()
	cve, malware := h.recheckDue(entry, now)

	if cve {
		res, err := h.cfg.CVEScanner.Scan(ctx, ref)
		switch {
		case err != nil:
			log.Warn().Err(err).Msg("cve re-check failed; serving cached artifact")
		default:
			if decision := h.cfg.Policy.Evaluate(ref, res); !decision.Allowed {
				h.evictRechecked(ref, log)
				return &recheckOutcome{gate: gate.GateCVE, decision: decision}
			}
			if err := h.cfg.Cache.MarkCVEChecked(ref, now); err != nil {
				log.Warn().Err(err).Msg("marking CVE re-check")
			}
		}
	}

	if malware {
		res, err := h.cfg.AVScanner.Scan(ctx, entry.ArtifactPath)
		switch {
		case err != nil:
			log.Warn().Err(err).Msg("malware re-check failed; serving cached artifact")
		case res.Incomplete:
			// It scanned clean in full before; an engine giving up now (lower
			// limits, a slow moment) is a failed re-check, retried next hit.
			log.Warn().Str("signature", res.Signature).Msg("malware re-check incomplete; serving cached artifact")
		case !res.Clean:
			h.evictRechecked(ref, log)
			return &recheckOutcome{gate: gate.GateMalware, av: res}
		default:
			if err := h.cfg.Cache.MarkMalwareChecked(ref, now); err != nil {
				log.Warn().Err(err).Msg("marking malware re-check")
			}
		}
	}
	return nil
}

// evictRechecked removes a cached entry that failed a lazy re-check. Eviction
// failure is logged but never blocks the block response.
func (h *Handler) evictRechecked(ref *gate.PackageRef, log zerolog.Logger) {
	if err := h.cfg.Cache.Invalidate(ref); err != nil {
		log.Error().Err(err).Msg("evicting re-checked artifact")
	}
}
