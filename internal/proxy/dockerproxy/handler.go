package dockerproxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/logx"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

// Config groups the Docker proxy handler dependencies.
type Config struct {
	Adapter *Adapter
	Gate    *manifestGate
	Store   *verdictStore
	Tags    *tagIndex
	// Attest remembers attestation manifests' blobs so they can be served
	// to clients that fetch them (containerd). Optional.
	Attest   *attestationBlobs
	Recorder gate.Recorder
	Logger   zerolog.Logger
	// Throttles reports upstream hosts in a post-throttle cooldown; optional
	// (see proxy.HandlerConfig.Throttles).
	Throttles upstream.ThrottleLookup
	// ClientWait bounds how long a manifest request waits for the gate
	// (0 = until it answers); see HandlerDeps.ClientWait.
	ClientWait time.Duration
}

// scanInProgressRetryAfter is the Retry-After sent while a first scan runs.
const scanInProgressRetryAfter = 30 * time.Second

// Handler implements the Docker Registry V2 pull-through flow.
type Handler struct {
	cfg Config
	log zerolog.Logger // cfg.Logger tagged component=docker, ecosystem=docker
}

// NewHandler creates a Docker proxy handler.
func NewHandler(cfg Config) *Handler {
	return &Handler{
		cfg: cfg,
		log: cfg.Logger.With().Str("component", "docker").Str("ecosystem", "docker").Logger(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pp := ParsePath(r.URL.Path)
	switch pp.Kind {
	case KindPing:
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
	case KindManifest:
		h.serveManifest(w, r, pp)
	case KindBlob:
		h.serveBlob(w, r, pp)
	default:
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "unsupported registry path")
	}
}

func (h *Handler) serveManifest(w http.ResponseWriter, r *http.Request, pp ParsedPath) {
	r, requestID := logx.Ensure(r)
	start := time.Now()
	log := logx.Logger(r.Context(), h.log).With().Str("package", pp.Repo).Str("version", pp.Reference).Logger()

	res, pending := h.evaluate(r, pp)
	digest, v, err := res.digest, res.v, res.err
	if pending != nil {
		// The scan is still running (it carries on and caches its verdict);
		// answer before the client's own header timeout cuts the connection,
		// and record the scan's real outcome when it lands.
		log.Info().Dur("waited", h.cfg.ClientWait).Msg("image scan still running; asking the client to retry")
		h.record(log, requestID, pp, gate.VerdictError, gate.GateImageScan, "scan_in_progress", http.StatusServiceUnavailable, start, nil)
		go h.recordWhenDone(log, requestID, pp, start, pending)
		httpx.SetRetryAfter(w.Header(), scanInProgressRetryAfter)
		h.writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "image scan in progress; retry shortly")
		return
	}
	if err != nil {
		f := h.gateFailure(log, err)
		h.record(log, requestID, pp, gate.VerdictError, gate.GateImageScan, f.reason, f.status, start, nil)
		if f.retry > 0 {
			httpx.SetRetryAfter(w.Header(), f.retry)
		}
		h.writeError(w, f.status, f.code, f.msg)
		return
	}
	// Feed label: prefer the human tag over the resolved digest. A by-tag pull
	// already carries the tag in pp.Reference; a multi-arch platform child is
	// requested by digest, so recover its tag from the index seen earlier.
	displayVer := h.displayVersion(pp, digest)
	log = log.With().Str("digest", digest).Logger()

	if !v.Allowed {
		h.recordBlock(log, requestID, pp, start, displayVer, v)
		h.writeError(w, http.StatusForbidden, "DENIED", "image blocked by policy: "+v.Reason)
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	if v.ContentType != "" {
		w.Header().Set("Content-Type", v.ContentType)
	}
	// An index or attestation manifest is a transit response, not a gate
	// decision: the real PASS/BLOCK event comes from the concrete platform image
	// manifest the client requests by digest. Serve it but keep it out of the
	// request feed so a pull shows a single, meaningful entry.
	recordPass := !v.Passthrough
	if v.Passthrough {
		log.Debug().Str("reason", v.Reason).Msg("serving manifest passthrough (not gated)")
	}
	// A repeat pull served from the cached gate decision is a CACHE event, not a
	// fresh PASS, so the feed distinguishes re-pulls from first-time evaluations.
	passVerdict, passGate, passReason := gate.VerdictPass, gate.GateImageScan, v.Reason
	if v.FromCache {
		passVerdict, passGate, passReason = gate.VerdictCache, gate.GateCache, "cache_hit"
	}
	if v.Reason == reasonAttestationPassthrough && h.cfg.Attest != nil {
		// Re-read on every serve, cached verdict included, so the blobs stay
		// servable across restarts.
		body, err := os.ReadFile(v.ManifestPath) // #nosec G304 -- path from the verdict store, inside the cache root
		if err != nil {
			log.Debug().Err(err).Msg("reading attestation manifest to remember its blobs")
		} else {
			h.cfg.Attest.remember(pp.Repo, body)
		}
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		if recordPass {
			h.record(log, requestID, pp, passVerdict, passGate, passReason, http.StatusOK, start, func(ev *gate.Event) { ev.Version = displayVer })
		}
		return
	}
	// Open the cached manifest before writing any header so a cache-read
	// failure can still emit the Docker error envelope (and a telemetry event).
	f, err := os.Open(v.ManifestPath)
	if err != nil {
		log.Error().Err(err).Msg("opening cached manifest")
		h.record(log, requestID, pp, gate.VerdictError, gate.GateImageScan, "cache_read_error", http.StatusInternalServerError, start, func(ev *gate.Event) { ev.Version = displayVer })
		h.writeError(w, http.StatusInternalServerError, "UNAVAILABLE", "cache read error")
		return
	}
	defer f.Close()
	w.WriteHeader(http.StatusOK)
	if _, err := httpx.CopyWithWriteDeadline(w, f, httpx.DefaultWriteIdleTimeout); err != nil {
		// Headers are already sent; can only log.
		log.Error().Err(err).Msg("serving cached manifest")
		return
	}
	if recordPass {
		h.record(log, requestID, pp, passVerdict, passGate, passReason, http.StatusOK, start, func(ev *gate.Event) { ev.Version = displayVer })
	}
}

// gateResult is one manifest-gate evaluation.
type gateResult struct {
	digest string
	v      GateVerdict
	err    error
}

// evaluate runs the manifest gate. With ClientWait set it waits at most that
// long; a non-nil pending channel means the gate is still working and will
// deliver its result there. The gate then runs on a context detached from the
// request, so the client hanging up after the 503 does not abort the scan its
// retry will be served from. (A stopping server does not wait for it; the
// temp files it leaves are removed at the next start.)
func (h *Handler) evaluate(r *http.Request, pp ParsedPath) (res gateResult, pending <-chan gateResult) {
	if h.cfg.ClientWait <= 0 {
		d, v, err := h.cfg.Gate.Evaluate(r.Context(), pp.Repo, pp.Reference)
		return gateResult{d, v, err}, nil
	}
	ch := make(chan gateResult, 1)
	ctx := context.WithoutCancel(r.Context())
	go func() {
		d, gv, gerr := h.cfg.Gate.Evaluate(ctx, pp.Repo, pp.Reference)
		ch <- gateResult{d, gv, gerr}
	}()
	timer := time.NewTimer(h.cfg.ClientWait)
	defer timer.Stop()
	select {
	case res := <-ch:
		return res, nil
	case <-timer.C:
		return gateResult{}, ch
	}
}

// recordWhenDone records the real outcome of a scan whose client was already
// answered 503 "scan in progress": the first verdict (with its findings) or the
// failure, which would otherwise surface nowhere while every retry got another
// 503.
func (h *Handler) recordWhenDone(log zerolog.Logger, requestID string, pp ParsedPath, start time.Time, pending <-chan gateResult) {
	res := <-pending
	if res.err != nil {
		f := h.gateFailure(log, res.err)
		h.record(log, requestID, pp, gate.VerdictError, gate.GateImageScan, f.reason, f.status, start, nil)
		return
	}
	displayVer := h.displayVersion(pp, res.digest)
	log = log.With().Str("digest", res.digest).Logger()
	switch {
	case !res.v.Allowed:
		h.recordBlock(log, requestID, pp, start, displayVer, res.v)
	case !res.v.Passthrough:
		h.record(log, requestID, pp, gate.VerdictPass, gate.GateImageScan, res.v.Reason, http.StatusOK, start,
			func(ev *gate.Event) { ev.Version = displayVer })
	}
}

// gateOutcome is how a manifest-gate failure is answered and recorded.
type gateOutcome struct {
	status    int
	reason    string
	code, msg string
	retry     time.Duration
}

// gateFailure classifies and logs an Evaluate error.
func (h *Handler) gateFailure(log zerolog.Logger, err error) gateOutcome {
	atts, hasAtts := upstream.AttemptsFrom(err)
	// Every mirror answered 404/410 for the manifest: it does not exist (a
	// typo'd tag, or a client's OCI referrers tag-schema fallback probe).
	// Answer with the registry's own MANIFEST_UNKNOWN, not a 502 gate failure.
	if errors.Is(err, errManifestNotFound) {
		log.Warn().Array("upstream_attempts", atts).Msg("manifest not found on any upstream")
		return gateOutcome{status: http.StatusNotFound, reason: "manifest_not_found", code: "MANIFEST_UNKNOWN", msg: "manifest unknown"}
	}
	// The rest were throttled: neither proof of absence nor an outage.
	if status, retry, ok := atts.Throttled(h.cfg.Throttles); hasAtts && ok {
		log.Warn().Err(err).Array("upstream_attempts", atts).Msg("upstream throttled")
		code := "UNAVAILABLE"
		if status == http.StatusTooManyRequests {
			code = "TOOMANYREQUESTS"
		}
		return gateOutcome{status: status, reason: "upstream_throttled", code: code, msg: "upstream registry throttled", retry: retry}
	}
	ev := log.Error().Err(err)
	if hasAtts {
		ev = ev.Array("upstream_attempts", atts)
	}
	ev.Msg("gate error")
	return gateOutcome{status: http.StatusBadGateway, reason: "gate_error", code: "UNAVAILABLE", msg: "upstream or scan failure"}
}

// recordBlock records a blocked image with its findings.
func (h *Handler) recordBlock(log zerolog.Logger, requestID string, pp ParsedPath, start time.Time, displayVer string, v GateVerdict) {
	h.record(log, requestID, pp, gate.VerdictBlock, gateForBlockedBy(v.BlockedBy), v.Reason, http.StatusForbidden, start, func(ev *gate.Event) {
		ev.BlockedBy = []string{v.BlockedBy}
		ev.CVEs = v.Findings
		ev.Version = displayVer
		// Supply-chain holds carry these; other block reasons leave them zero
		// (correct — only supply-chain blocks are quarantined).
		ev.PublishedAt = v.PublishedAt
		ev.BlockUntil = v.BlockUntil
	})
}

// displayVersion picks the feed label for a gated manifest: the human tag when
// known (a by-tag pull, or a multi-arch platform child whose tag was recorded
// from the index), otherwise the resolved digest.
func (h *Handler) displayVersion(pp ParsedPath, digest string) string {
	if !isDigestRef(pp.Reference) {
		return pp.Reference
	}
	if h.cfg.Tags != nil {
		if tag, ok := h.cfg.Tags.tag(pp.Repo, digest); ok {
			return tag
		}
	}
	return digest
}

func (h *Handler) serveBlob(w http.ResponseWriter, r *http.Request, pp ParsedPath) {
	log := logx.Logger(r.Context(), h.log).With().Str("package", pp.Repo).Str("digest", pp.Reference).Logger()
	path, clean, found := h.cfg.Store.GetBlob(pp.Reference)
	if !found && h.cfg.Attest != nil && h.cfg.Attest.has(pp.Repo, pp.Reference) {
		h.serveAttestationBlob(w, r, pp, log)
		return
	}
	if !found || !clean {
		h.writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not available")
		return
	}
	// Open before writing any header so a cache-read failure yields the Docker
	// error envelope rather than a half-written 200.
	f, err := os.Open(path) // #nosec G304 -- path comes from the verdict store, always inside the cache root
	if err != nil {
		log.Error().Err(err).Msg("opening cached blob")
		h.writeError(w, http.StatusInternalServerError, "UNAVAILABLE", "cache read error")
		return
	}
	defer f.Close()
	w.Header().Set("Docker-Content-Digest", pp.Reference)
	w.Header().Set("Content-Type", "application/octet-stream")
	// An explicit length lets the client detect a truncated transfer.
	if fi, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	w.WriteHeader(http.StatusOK)
	// Blob serves are deliberately not recorded as telemetry events: a single
	// pull fetches many blobs, and one event per blob would inflate the console
	// request metrics. The manifest gate already records the per-image outcome.
	if _, err := httpx.CopyWithWriteDeadline(w, f, httpx.DefaultWriteIdleTimeout); err != nil {
		log.Error().Err(err).Msg("serving cached blob")
	}
}

// serveAttestationBlob relays one attestation blob from upstream: capped,
// verified against its digest, not cached. Only blobs remembered from an
// attestation manifest's config and non-filesystem layers reach this.
func (h *Handler) serveAttestationBlob(w http.ResponseWriter, r *http.Request, pp ParsedPath, log zerolog.Logger) {
	// Coalesced per blob; the flight is detached from any one client so a
	// disconnecting leader does not fail the others.
	ctx := context.WithoutCancel(r.Context())
	res, err, _ := h.cfg.Attest.fetches.Do(pp.Repo+"@"+pp.Reference, func() (any, error) {
		return fetchAttestationBlob(ctx, h.cfg.Adapter, pp.Repo, pp.Reference)
	})
	var body []byte
	if err == nil {
		body = res.([]byte)
	}
	switch {
	case errors.Is(err, errAttestationBlobRejected):
		log.Warn().Err(err).Msg("refusing attestation blob")
		h.writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not available")
		return
	case err != nil:
		log.Error().Err(err).Msg("fetching attestation blob")
		h.writeError(w, http.StatusBadGateway, "UNAVAILABLE", "upstream failure")
		return
	}
	w.Header().Set("Docker-Content-Digest", pp.Reference)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := w.Write(body); err != nil {
		log.Debug().Err(err).Msg("serving attestation blob")
	}
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{{"code": code, "message": msg}},
	})
}

// record ends a manifest request: one telemetry event and the matching
// outcome log line. A nil Recorder disables only the event.
func (h *Handler) record(log zerolog.Logger, requestID string, pp ParsedPath, verdict, gateName, reason string, status int, start time.Time, mod func(*gate.Event)) {
	ev := gate.Event{
		RequestID: requestID, Time: time.Now(),
		Ecosystem: "docker", Package: pp.Repo, Version: pp.Reference,
		Verdict: verdict, Gate: gateName, Reason: reason,
		HTTPStatus: status, LatencyMS: time.Since(start).Milliseconds(),
	}
	if mod != nil {
		mod(&ev)
	}
	logx.Outcome(log, ev)
	if h.cfg.Recorder != nil {
		h.cfg.Recorder.Record(ev)
	}
}

func gateForBlockedBy(by string) string {
	switch by {
	case "malware", gate.ReasonScanIncomplete:
		return gate.GateMalware
	case "supply_chain":
		return gate.GateSupply
	default:
		return gate.GateImageScan
	}
}

// HandlerDeps is the public assembly input for the Docker proxy handler.
type HandlerDeps struct {
	Upstreams     []string
	Scanner       ImageScanner
	AV            gate.AVScanner
	Filter        gate.SCFilter
	Policy        gate.PolicyDecider
	Cache         cache.Cache
	MaxLayerBytes int64
	Recorder      gate.Recorder
	Logger        zerolog.Logger
	// RecheckTTL: cached image verdicts older than this are re-evaluated by the
	// full gate on the next pull (0 = never expire). Wire min of the enabled
	// per-gate TTLs.
	RecheckTTL time.Duration
	// HTTPClient talks to the upstream registry. Optional; nil uses a private
	// client with a 120s timeout. Pass a client whose transport caps per-host
	// concurrency (shared with the other registries) to avoid 429 throttling.
	HTTPClient *http.Client
	// Throttles reports upstream hosts in a post-throttle cooldown; optional.
	Throttles upstream.ThrottleLookup
	// ClientWait bounds how long a manifest request waits for the image gate
	// before answering 503 + Retry-After while the scan carries on (0 = wait
	// for the verdict). containerd gives up after 30 s without response
	// headers, and a first scan of a large image takes minutes.
	ClientWait time.Duration
	// TempDir holds layers and manifests while they are checked. Empty uses
	// os.TempDir(); point it at the cache volume so multi-GB layers do not
	// land on the container's root filesystem.
	TempDir string
}

// New assembles a ready-to-serve Docker Registry V2 proxy handler.
func New(d HandlerDeps) http.Handler {
	adapter := NewAdapter(d.Upstreams, d.HTTPClient)
	store := newVerdictStore(d.Cache)
	tags := newTagIndex(0)
	mgate := newManifestGate(gateDeps{
		adapter: adapter, scanner: d.Scanner, av: d.AV,
		filter: d.Filter, policy: d.Policy, store: store, tags: tags,
		maxLayerBytes: d.MaxLayerBytes, recheckTTL: d.RecheckTTL, tempDir: d.TempDir, logger: d.Logger,
	})
	return NewHandler(Config{Adapter: adapter, Gate: mgate, Store: store, Tags: tags, Attest: newAttestationBlobs(0), Recorder: d.Recorder, Logger: d.Logger, Throttles: d.Throttles, ClientWait: d.ClientWait})
}
