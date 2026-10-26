package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/logx"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

// syntheticETagPrefix marks an ETag this proxy minted for a rewritten metadata
// document. A client revalidating with such a tag must be served from a freshly
// filtered document: forwarding its If-None-Match upstream would earn a 304 with
// no body to filter, pinning the client to a stale rewrite forever.
const syntheticETagPrefix = `"joei.`

// syntheticETag mints a strong validator for a rewritten document. The value
// hashes the rewritten body, so a client whose filtering has not changed
// revalidates as 304 and the slow path still costs the client hop nothing.
func syntheticETag(body []byte) string {
	sum := sha256.Sum256(body)
	return syntheticETagPrefix + hex.EncodeToString(sum[:8]) + `"`
}

// etagMatches reports whether an If-None-Match list contains tag exactly. The
// tags this proxy mints are strong validators, so a weak comparison would be
// wrong here.
func etagMatches(ifNoneMatch, tag string) bool {
	for _, candidate := range strings.Split(ifNoneMatch, ",") {
		if strings.TrimSpace(candidate) == tag {
			return true
		}
	}
	return false
}

// metadataFilterRef reports the package a metadata request describes. It is
// false unless this registry's adapter can rewrite documents at all, which
// keeps the cost off every other ecosystem.
func (h *Handler) metadataFilterRef(r *http.Request) (*gate.MetadataRef, bool) {
	filterer, ok := h.cfg.Adapter.(gate.MetadataFilterer)
	if !ok {
		return nil, false
	}
	return filterer.NormalizeMetadataRequest(r)
}

// proxyMetadata serves a metadata document only with every download link
// pointed at the proxy, under the address the client used to reach it, and
// with the versions policy would block at download time hidden. Served
// untouched, the document would send the client's downloads around every
// gate, so each path that cannot rewrite — an oversized document, a coding
// this proxy does not decode, a status with no document, an unparseable
// document — fails the request instead.
func (h *Handler) proxyMetadata(w http.ResponseWriter, r *http.Request, mref *gate.MetadataRef) {
	filterer, ok := h.cfg.Adapter.(gate.MetadataFilterer)
	if !ok { // unreachable: metadataFilterRef already asserted the capability
		h.proxyTransparent(w, r)
		return
	}

	log := logx.Logger(r.Context(), h.metaLog).With().
		Str("ecosystem", mref.Ecosystem).
		Str("package", mref.Name).
		Str("path", r.URL.Path).
		Logger()

	base, err := h.cfg.PublicBase.Base(r)
	if err != nil {
		log.Warn().Err(err).Msg("refusing a request whose host or forwarding header cannot form a link")
		writeJSONError(w, http.StatusBadRequest, "bad_forwarded_header")
		return
	}
	linkBase := base.String()
	if prefix := RoutePrefix(r.Context()); prefix != "" {
		linkBase += "/" + prefix
	}

	// Every document this proxy serves is rewritten, so a client's validators
	// name either one of our own tags — which upstream cannot answer — or a
	// copy cached before rewriting, which upstream's 304 would keep alive with
	// its links around the proxy. Neither may reach upstream. gzip is the only
	// coding readMetadataDocument decodes, so ask for exactly that rather than
	// relaying the client's own Accept-Encoding; a partial response is a
	// slice of a document that cannot be rewritten.
	clientTag := strings.Join(r.Header.Values("If-None-Match"), ", ")
	outbound := r.Clone(r.Context())
	outbound.Header.Del("If-None-Match")
	outbound.Header.Del("If-Modified-Since")
	outbound.Header.Del("Range")
	outbound.Header.Del("If-Range")
	outbound.Header.Set("Accept-Encoding", "gzip")

	// The full request URI — not just the path — picks the document, since
	// UpstreamURLs builds the fetch from it; Accept picks its shape. Nothing
	// else the flight forwards varies between callers, and the rewrite below
	// runs per caller, so callers behind different addresses share a flight
	// safely.
	key := r.URL.RequestURI() + "\x00" + r.Header.Get("Accept")

	fetch, atts, err := h.fetchMetadataDocument(outbound, key, h.metadataLimit())
	switch {
	case fetch == nil && (err == nil || errors.Is(err, errNoUpstreams) || errors.Is(err, errUnreadableRequestBody)):
		// forwardUpstream itself never produced a usable response — every
		// mirror failed, or none is configured — and writeForwardError already
		// knows how to report that precisely (404 vs 502 vs 500).
		h.writeForwardError(w, atts, err, log)
		return
	case err != nil:
		// fetchMetadataDocument detaches the flight from any one caller's
		// context, so a cancellation here is defensive only: an aborted install
		// surfaces at the write in writeMetadataDocument instead.
		event := log.Error()
		if errors.Is(err, context.Canceled) {
			event = log.Debug()
		}
		failMetadata(w, event.Err(err))
		return
	}
	if fetch.status == http.StatusNoContent {
		copyProxyHeaders(w.Header(), fetch.header)
		w.WriteHeader(fetch.status)
		return
	}

	var undated int
	filtered, err := filterer.FilterVersions(fetch.doc, mref, h.versionDecider(r.Context(), mref, &undated), linkBase)
	if err != nil {
		failMetadata(w, log.Error().Err(err))
		return
	}
	if undated > 0 {
		// The abbreviated packument has no publish dates at all, so min-age
		// cannot speak for it. Say so once, or "why does pnpm still get 423"
		// has no answer outside the source.
		log.Debug().Int("versions", undated).
			Msg("document carries no publish dates, so the age rule is mute here")
	}
	if n := len(filtered.Unmappable); n > 0 {
		examples := filtered.Unmappable
		if len(examples) > maxLoggedDrops {
			examples = examples[:maxLoggedDrops]
		}
		log.Warn().Int("count", n).Strs("examples", examples).
			Msg("hid versions whose download link cannot route through the proxy")
	}
	switch {
	case filtered.AllRejected:
		log.Info().Strs("versions", filtered.Removed).
			Msg("every version is blocked, serving them all for the artifact gate to refuse")
	case len(filtered.Removed) > 0:
		log.Info().Strs("versions", filtered.Removed).Int("count", len(filtered.Removed)).
			Msg("hid blocked versions")
	}

	tag := syntheticETag(filtered.Body)
	if etagMatches(clientTag, tag) {
		// Same document, same policy, same address: the copy the client
		// already has is current.
		w.Header().Set("ETag", tag)
		if cc := fetch.header.Get("Cache-Control"); cc != "" {
			w.Header().Set("Cache-Control", cc)
		}
		if vary := fetch.header.Get("Vary"); vary != "" {
			w.Header().Set("Vary", vary)
		}
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeMetadataDocument(w, r, fetch.header, fetch.status, filtered.Body, log)
}

// metadataLimit is the byte cap on a decoded metadata document; zero means no
// cap.
func (h *Handler) metadataLimit() int64 {
	if h.cfg.MetadataFilterMaxMB <= 0 {
		return 0
	}
	return int64(h.cfg.MetadataFilterMaxMB) << 20
}

// failMetadata logs why a metadata document cannot be served and answers 502:
// served untouched, it would hand the client links around the proxy.
func failMetadata(w http.ResponseWriter, event *zerolog.Event) {
	event.Msg("upstream metadata document cannot be rewritten")
	writeJSONError(w, http.StatusBadGateway, "metadata_rewrite_failed")
}

// writeJSONError answers status with {"error": code}.
func writeJSONError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}

// metadataFetch is one coalesced upstream document: the bytes, and the
// response header and status they came with. doc is nil for a 204.
type metadataFetch struct {
	doc    []byte
	header http.Header
	status int
}

// Reasons an upstream answer cannot become a rewritten document.
var (
	errMetadataOversized = errors.New("document exceeds server.metadata_filter_max_mb")
	errMetadataEncoding  = errors.New("document in a content-encoding the proxy cannot decode")
	errMetadataStatus    = errors.New("upstream status carries no document to rewrite")
)

// fetchMetadataDocument fetches and decompresses a metadata document, collapsing
// concurrent callers for the same document onto one upstream request — the case
// that matters is a CI fleet resolving the same dependency tree at once, which
// would otherwise cost one upstream fetch per worker instead of one overall.
// limit caps the decoded document (0 = no cap).
//
// The upstream request is detached from the triggering caller's context before
// the fetch runs, the same way recheckExpired detaches its own flight: a leader
// whose client disconnects mid-flight must not cancel the fetch for every other
// waiter sharing it.
func (h *Handler) fetchMetadataDocument(r *http.Request, key string, limit int64) (*metadataFetch, upstream.Attempts, error) {
	type result struct {
		fetch *metadataFetch
		atts  upstream.Attempts
		err   error
	}
	v, _, _ := h.metadataGroup.Do(key, func() (any, error) {
		flightReq := r.Clone(context.WithoutCancel(r.Context()))
		resp, atts, err := h.forwardUpstream(flightReq)
		if resp == nil {
			return result{atts: atts, err: err}, nil
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusNoContent:
			return result{fetch: &metadataFetch{header: resp.Header.Clone(), status: resp.StatusCode}}, nil
		default:
			// The HTTP client follows redirects itself, so a 3xx here is one it
			// gave up on — or a 304 to a request that sent no validator, or a
			// 2xx that is not a whole document. None can be rewritten.
			return result{err: fmt.Errorf("%w: %d", errMetadataStatus, resp.StatusCode)}, nil
		}

		doc, rest, unsupportedEncoding, err := readMetadataDocument(resp, limit)
		switch {
		case err != nil:
			return result{err: err}, nil
		case unsupportedEncoding:
			return result{err: fmt.Errorf("%w: %q", errMetadataEncoding, resp.Header.Get("Content-Encoding"))}, nil
		case rest != nil:
			return result{err: errMetadataOversized}, nil
		}
		return result{fetch: &metadataFetch{doc: doc, header: resp.Header.Clone(), status: resp.StatusCode}}, nil
	})
	res := v.(result)
	return res.fetch, res.atts, res.err
}

// versionDecider builds the per-version predicate the filter asks. It mirrors
// what the artifact gate would decide at download time, limited to the rules
// that need no network call: the denylist and the age check. undated counts the
// versions the document gave no publish date for, so the caller can say once
// that the age rule had nothing to judge.
func (h *Handler) versionDecider(ctx context.Context, mref *gate.MetadataRef, undated *int) gate.VersionDecider {
	return func(version string, publishedAt time.Time) bool {
		ref := &gate.PackageRef{Ecosystem: mref.Ecosystem, Name: mref.Name, Version: version}

		// An empty ScanResult means "not scanned", not "clean": only the
		// denylist verdict is trustworthy here, so no other reason may hide a
		// version.
		if h.cfg.Policy != nil {
			if d := h.cfg.Policy.Evaluate(ref, &gate.ScanResult{}); !d.Allowed && d.Reason == gate.ReasonDenylisted {
				return false
			}
		}
		// Document shapes without per-version publish dates leave the age check
		// mute; the artifact gate still applies it at download time.
		if publishedAt.IsZero() {
			*undated++
			return true
		}
		return h.cfg.Filter.Check(ctx, ref, &gate.PackageMetadata{PublishedAt: publishedAt}).Allowed
	}
}

// readMetadataDocument reads a decompressed metadata document, at most limit
// bytes of it (0 = no cap). A non-nil rest means the document cannot be filtered and must be
// streamed instead: either it is larger than limit, in which case rest is
// positioned at the remainder, or its Content-Encoding is a coding this proxy
// does not decode, in which case rest is resp.Body itself, still untouched.
// unsupportedEncoding distinguishes the two so the caller can log accurately;
// both route to the same verbatim relay.
//
// Only a bare "gzip" is decoded. Anything else this proxy might see —
// "deflate", "br", "zstd", or a coding list such as "gzip, identity" — is left
// alone deliberately: decoding here happens before anything has been read from
// resp.Body, so an unsupported coding can still be relayed byte-for-byte. The
// alternative — reading it as if it were plain JSON — is silent corruption:
// FilterVersions fails to unmarshal the still-compressed bytes, "unfiltered"
// serving then strips the Content-Encoding that described them and ships a
// body the client is told is plain JSON but cannot decode.
func readMetadataDocument(resp *http.Response, limit int64) (doc []byte, rest io.Reader, unsupportedEncoding bool, err error) {
	src := io.Reader(resp.Body)
	switch coding := strings.TrimSpace(resp.Header.Get("Content-Encoding")); {
	case coding == "" || strings.EqualFold(coding, "identity"):
		// Already plain; nothing to decode.
	case strings.EqualFold(coding, "gzip"):
		zr, zerr := gzip.NewReader(resp.Body)
		if zerr != nil {
			return nil, nil, false, fmt.Errorf("decompressing metadata document: %w", zerr)
		}
		src = zr
	default:
		return nil, resp.Body, true, nil
	}
	if limit <= 0 {
		buf, err := io.ReadAll(src)
		if err != nil {
			return nil, nil, false, fmt.Errorf("reading metadata document: %w", err)
		}
		return buf, nil, false, nil
	}
	buf, err := io.ReadAll(io.LimitReader(src, limit+1))
	if err != nil {
		return nil, nil, false, fmt.Errorf("reading metadata document: %w", err)
	}
	if int64(len(buf)) <= limit {
		return buf, nil, false, nil
	}
	return buf, src, false, nil
}

// writeMetadataDocument serves a rewritten document. It gets this proxy's own
// validator and loses upstream's, so no client can revalidate its way back
// into a stale rewrite. The body is re-compressed when the client asked for
// gzip, so rewriting costs the client hop nothing.
func writeMetadataDocument(w http.ResponseWriter, r *http.Request, header http.Header, status int, body []byte, log zerolog.Logger) {
	copyProxyHeaders(w.Header(), header)
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Encoding")
	w.Header().Del("Last-Modified")
	w.Header().Set("ETag", syntheticETag(body))

	payload := body
	if clientAcceptsGzip(r) {
		if gzipped, err := gzipBytes(body); err == nil {
			payload = gzipped
			w.Header().Set("Content-Encoding", "gzip")
		} else {
			// Fall back to identity: a client that asked for gzip can still
			// decode plain bytes, so this must not fail the response. But a
			// silent fallback is undiagnosable, so it gets a log line same as
			// every other write failure in this file.
			log.Error().Err(err).Msg("compressing response, serving identity")
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(status)
	if _, err := httpx.CopyWithWriteDeadline(w, bytes.NewReader(payload), httpx.DefaultWriteIdleTimeout); err != nil {
		// The flight's own fetch context is detached from any one caller's
		// disconnect (see fetchMetadataDocument), so an aborted npm install no
		// longer shows up as a cancelled read — it shows up here instead, as a
		// write against a connection the client already closed. That is the
		// same "client hung up, not a proxy failure" case the read path used to
		// demote, just relocated to where it now actually occurs.
		event := log.Error()
		if r.Context().Err() != nil {
			event = log.Debug()
		}
		event.Err(err).Msg("writing response")
	}
}

// clientAcceptsGzip reports whether the client listed gzip in Accept-Encoding.
// A zero qvalue ("q=0", "q=0.0", "q=0.000", …) is a refusal per RFC 7231 §5.3.4,
// so it is parsed as a float rather than matched against the single literal
// "q=0" — a client sending "q=0.0" refused gzip exactly as much as one sending
// "q=0", and both must not receive a gzipped body they said they cannot decode.
func clientAcceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(fields[0]), "gzip") {
			continue
		}
		for _, param := range fields[1:] {
			name, value, ok := strings.Cut(strings.TrimSpace(param), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			if q, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil && q == 0 {
				return false
			}
		}
		return true
	}
	return false
}

// gzipBytes compresses b at the default level.
func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
