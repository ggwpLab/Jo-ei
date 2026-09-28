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

// holdsSyntheticETag reports whether an If-None-Match header carries a tag this
// proxy minted. The header is a list, and one of ours anywhere in it means the
// client is holding a rewritten document. "*" is not ours: it asks about any
// representation at all, which upstream can answer.
func holdsSyntheticETag(ifNoneMatch string) bool {
	for _, tag := range strings.Split(ifNoneMatch, ",") {
		if strings.HasPrefix(strings.TrimSpace(tag), syntheticETagPrefix) {
			return true
		}
	}
	return false
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

// metadataFilterRef reports the package a filterable metadata request describes.
// It is false unless filtering is enabled and this registry's adapter can
// rewrite documents at all, which keeps the cost off every other ecosystem.
func (h *Handler) metadataFilterRef(r *http.Request) (*gate.MetadataRef, bool) {
	if h.cfg.MetadataFilterMaxMB <= 0 {
		return nil, false
	}
	filterer, ok := h.cfg.Adapter.(gate.MetadataFilterer)
	if !ok {
		return nil, false
	}
	return filterer.NormalizeMetadataRequest(r)
}

// proxyMetadata serves a metadata document with the versions policy would block
// at download time hidden from it, so the client's own resolver never picks one.
// Every path that cannot filter — an oversized document, a coding this proxy
// does not decode, a non-200 response, an unparseable document, a policy that
// rejects everything — serves the document untouched, because the artifact
// gate remains the enforcement boundary.
func (h *Handler) proxyMetadata(w http.ResponseWriter, r *http.Request, mref *gate.MetadataRef) {
	filterer, ok := h.cfg.Adapter.(gate.MetadataFilterer)
	if !ok { // unreachable: metadataFilterRef already asserted the capability
		h.proxyTransparent(w, r)
		return
	}

	log := h.cfg.Logger.With().Str("ecosystem", mref.Ecosystem).Str("package", mref.Name).Logger()

	// The whole cost model rests on this branch, and it is decided from the
	// request alone: a client holding one of our tags needs a fresh body to
	// filter, so its validators must not reach upstream. Everyone else keeps
	// their conditional request, and with it the chance of a cheap 304.
	//
	// Header.Values, not Header.Get: repeated If-None-Match field lines are
	// legal HTTP and mean the same thing as one comma-joined line, so joining
	// them here is what makes detection independent of which shape the client
	// chose to send.
	clientTag := strings.Join(r.Header.Values("If-None-Match"), ", ")
	clientHoldsOurTag := holdsSyntheticETag(clientTag)

	outbound := r
	if clientHoldsOurTag {
		outbound = r.Clone(r.Context())
		outbound.Header.Del("If-None-Match")
		outbound.Header.Del("If-Modified-Since")
	}

	// Requests that would get different answers must not be coalesced: the
	// full request URI — not just the path — picks the document, since
	// UpstreamURLs builds the fetch from it query string included; Accept
	// picks the document's shape; and the validators actually forwarded
	// upstream (after a held synthetic tag is stripped above) decide whether
	// upstream can answer 304 at all. Folding in the forwarded validators
	// themselves, rather than just whether one was held, is what matters: two
	// callers that both forward nothing share a flight safely (neither can
	// get a 304), but a caller forwarding no validator must never share a
	// flight with one forwarding a validator upstream might honour — sharing
	// that flight would hand the first caller a bodyless 304 for a request
	// that has nothing to revalidate.
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%s",
		r.URL.RequestURI(),
		r.Header.Get("Accept"),
		outbound.Header.Get("If-None-Match"),
		outbound.Header.Get("If-Modified-Since"),
	)

	fetch, relay, atts, err := h.fetchMetadataDocument(outbound, key, int64(h.cfg.MetadataFilterMaxMB)<<20)
	switch {
	case relay != "":
		// Not shareable across callers: whatever the flight read (or chose not
		// to read) belongs to that one attempt, so this caller fetches its own
		// copy. outbound's body was already drained and closed by the flight's
		// own attempt — Clone shares the Body field by reference rather than
		// deep-copying it, so fetchMetadataDocument's internal clone consumed
		// the same body this one would reuse — so this retry needs a fresh one.
		// Metadata GETs never carry a request body, so NoBody is exact here,
		// not just a stand-in.
		retry := outbound.Clone(outbound.Context())
		retry.Body = http.NoBody
		h.streamOversizedMetadata(w, r, retry, &log, relay)
		return
	case fetch == nil && (err == nil || errors.Is(err, errNoUpstreams) || errors.Is(err, errUnreadableRequestBody)):
		// forwardUpstream itself never produced a usable response — every
		// mirror failed, or none is configured — and writeForwardError already
		// knows how to report that precisely (404 vs 502 vs 500). A document-read
		// failure never lands here: forwardUpstream returns no error but these
		// two sentinels, so any other non-nil err below is readMetadataDocument's.
		h.writeForwardError(w, r, atts, err)
		return
	case err != nil:
		// A cancelled context would mean the client hung up mid-fetch, not a
		// genuine upstream or read failure — but fetchMetadataDocument detaches
		// the flight's own request context (context.WithoutCancel), precisely so
		// one caller's disconnect cannot cancel the fetch for every other waiter
		// sharing it. That means this specific read can no longer observe THIS
		// caller's cancellation: an aborted npm install now surfaces later, at
		// the write in writeMetadataDocument, which carries the matching
		// demotion. This branch is kept defensive-only, in case a future path
		// ever reaches readMetadataDocument without that detachment.
		event := log.Error()
		if errors.Is(err, context.Canceled) {
			event = log.Debug()
		}
		event.Err(err).Msg("metadata filter: reading upstream document")
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}

	// Upstream answered 304, which it can only do for a validator we
	// forwarded — and every caller sharing this flight forwarded the exact
	// same validator, because the coalescing key folds it in above. A client
	// holding one of our tags never reaches this branch, because its
	// validators were stripped above and upstream never 304s an empty
	// conditional. There is no body to filter and none is needed.
	if fetch.status == http.StatusNotModified {
		copyProxyHeaders(w.Header(), fetch.header)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	var undated int
	filtered, err := filterer.FilterVersions(fetch.doc, h.versionDecider(r.Context(), mref, &undated))
	if err != nil {
		log.Warn().Err(err).Msg("metadata filter: unparseable document, serving unfiltered")
		filtered = gate.FilteredDocument{Body: fetch.doc}
	}
	if undated > 0 {
		// The abbreviated packument has no publish dates at all, so min-age
		// cannot speak for it. Say so once, or "why does pnpm still get 423"
		// has no answer outside the source.
		log.Debug().Int("versions", undated).
			Msg("metadata filter: document carries no publish dates, so the age rule is mute here")
	}

	switch {
	case filtered.AllRejected:
		log.Info().Strs("versions", filtered.Removed).
			Msg("metadata filter: every version is blocked, serving the document unchanged")
	case len(filtered.Removed) > 0:
		log.Info().Strs("versions", filtered.Removed).Int("count", len(filtered.Removed)).
			Msg("metadata filter: hid blocked versions")
	}

	rewritten := len(filtered.Removed) > 0 && !filtered.AllRejected
	if rewritten {
		tag := syntheticETag(filtered.Body)
		if clientHoldsOurTag && etagMatches(clientTag, tag) {
			// Same document, same policy, same rewrite: the copy the client
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
	}
	writeMetadataDocument(w, r, fetch.header, fetch.status, filtered.Body, rewritten, log)
}

// metadataFetch is one coalesced upstream document: the bytes, and the response
// header and status they came with. A document over the cap is not shareable —
// its remainder is a live reader belonging to one request — so oversized
// fetches are reported and the caller retries alone.
type metadataFetch struct {
	doc    []byte
	header http.Header
	status int
}

// relayReason names why a fetched response cannot be filtered and must instead
// be relayed verbatim by streamOversizedMetadata. The empty value means the
// document is filterable.
type relayReason string

const (
	relayOversized   relayReason = "oversized" // exceeded the configured cap
	relayEncoding    relayReason = "encoding"  // a Content-Encoding this proxy does not decode
	relayNonOKStatus relayReason = "status"    // not a 200 document (redirect, 204, ...); 304 is handled separately
)

// fetchMetadataDocument fetches and decompresses a metadata document, collapsing
// concurrent callers for the same package onto one upstream request — the case
// that matters is a CI fleet resolving the same dependency tree at once, which
// would otherwise cost one upstream fetch per worker instead of one overall.
// A non-empty relay reason means the caller must fetch and stream the document
// itself instead of filtering it: an oversized body's remainder is a live
// reader that cannot be handed to more than one waiter, an unsupported coding
// was left untouched precisely so it could still be relayed, and a non-200
// status is not a document to filter at all.
//
// The upstream request is detached from the triggering caller's context before
// the fetch runs, the same way recheckExpired detaches its own flight: a leader
// whose client disconnects mid-flight must not cancel the fetch for every other
// waiter sharing it.
func (h *Handler) fetchMetadataDocument(r *http.Request, key string, limit int64) (f *metadataFetch, relay relayReason, atts upstream.Attempts, err error) {
	type result struct {
		fetch *metadataFetch
		relay relayReason
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

		if resp.StatusCode == http.StatusNotModified {
			return result{fetch: &metadataFetch{header: resp.Header.Clone(), status: resp.StatusCode}}, nil
		}
		if resp.StatusCode != http.StatusOK {
			// A mirror answering with a redirect, 204, or similar sub-400 status
			// (forwardUpstream accepts anything under 400) has no document to
			// filter. Relay it exactly as proxyTransparent would have, rather
			// than buffering it, failing to parse it, and relaying it anyway
			// with a Content-Length that no longer matches nothing consumed.
			return result{relay: relayNonOKStatus}, nil
		}

		doc, rest, unsupportedEncoding, err := readMetadataDocument(resp, limit)
		if err != nil {
			return result{err: err}, nil
		}
		if rest != nil {
			reason := relayOversized
			if unsupportedEncoding {
				reason = relayEncoding
			}
			return result{relay: reason}, nil
		}
		return result{fetch: &metadataFetch{doc: doc, header: resp.Header.Clone(), status: resp.StatusCode}}, nil
	})
	res := v.(result)
	return res.fetch, res.relay, res.atts, res.err
}

// streamOversizedMetadata serves a document this proxy cannot filter: too
// large to buffer, compressed with a coding it does not decode, or not a 200
// document at all. In every case the artifact gate blocks the download
// instead, which is the behaviour that predates metadata filtering. It streams
// the upstream body verbatim, compression (and status) and all, rather than
// resuming a partially-read body from a coalesced attempt — that body's
// remainder belongs to whichever request read it, not to this one, so this
// caller fetches its own copy alone.
func (h *Handler) streamOversizedMetadata(w http.ResponseWriter, r *http.Request, outbound *http.Request, log *zerolog.Logger, relay relayReason) {
	switch relay {
	case relayOversized:
		log.Warn().Int("cap_mb", h.cfg.MetadataFilterMaxMB).
			Msg("metadata filter: document over cap, serving unfiltered")
	case relayEncoding:
		log.Warn().Msg("metadata filter: content-encoding not supported, serving unfiltered")
	default:
		// A non-200 sub-400 status is not a filtering degradation — there was
		// never a document to filter — so it does not earn a Warn.
		log.Debug().Msg("metadata filter: non-200 upstream response, relaying unfiltered")
	}

	resp, atts, err := h.forwardUpstream(outbound)
	if resp == nil {
		h.writeForwardError(w, r, atts, err)
		return
	}
	defer resp.Body.Close()

	copyProxyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Error().Err(err).Msg("metadata filter: streaming oversized document")
	}
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
// bytes of it. A non-nil rest means the document cannot be filtered and must be
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
	buf, err := io.ReadAll(io.LimitReader(src, limit+1))
	if err != nil {
		return nil, nil, false, fmt.Errorf("reading metadata document: %w", err)
	}
	if int64(len(buf)) <= limit {
		return buf, nil, false, nil
	}
	return buf, src, false, nil
}

// writeMetadataDocument serves a buffered document. A rewritten body gets this
// proxy's own validator and loses upstream's, so no client can revalidate its
// way back into a stale rewrite; an untouched body keeps upstream's validators
// and with them the cheap 304 that follows. The body is re-compressed when the
// client asked for gzip, so rewriting costs the client hop nothing.
func writeMetadataDocument(w http.ResponseWriter, r *http.Request, header http.Header, status int, body []byte, rewritten bool, log zerolog.Logger) {
	copyProxyHeaders(w.Header(), header)
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Encoding")
	if rewritten {
		w.Header().Del("Last-Modified")
		w.Header().Set("ETag", syntheticETag(body))
	}

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
			log.Error().Err(err).Msg("metadata filter: compressing response, serving identity")
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(status)
	if _, err := w.Write(payload); err != nil {
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
		event.Err(err).Msg("metadata filter: writing response")
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
