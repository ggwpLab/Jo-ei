package dockerproxy

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// Passthrough reasons: manifests served without gating because they carry no
// scannable image content. A multi-arch index lists per-platform child
// manifests (each gated on its own request); an attestation manifest's "layers"
// are in-toto JSON (SBOM/provenance), not a filesystem.
const (
	reasonIndexPassthrough       = "index_passthrough"
	reasonAttestationPassthrough = "attestation_passthrough"
)

// isPassthroughReason reports whether a cached verdict reason denotes an
// un-gated passthrough (index or attestation) rather than a real gate decision.
func isPassthroughReason(reason string) bool {
	return reason == reasonIndexPassthrough || reason == reasonAttestationPassthrough
}

// GateVerdict is the per-image decision produced by the manifest gate.
type GateVerdict struct {
	Allowed      bool
	Reason       string // "ok" | "index_passthrough" | "attestation_passthrough" | "cve_found" | "denylisted" | "malware_found" | supply-chain reason
	BlockedBy    string // "supply_chain" | "cve" | "denylist" | "malware" (empty when allowed)
	Findings     []gate.CVEFinding
	ManifestPath string // cached manifest body (allowed only)
	ContentType  string
	PublishedAt  time.Time
	BlockUntil   time.Time // non-zero only for supply-chain holds (drives the quarantine view)
	// Passthrough is true when the served manifest was not gated because it has
	// no scannable image content (a multi-arch index, or an attestation
	// manifest). The real image content is gated when the client requests the
	// concrete platform image manifest by digest.
	Passthrough bool
	// FromCache is true when this verdict was served from a previously cached
	// gate decision rather than freshly evaluated. The handler records it as a
	// CACHE event so repeat pulls are distinguishable from first-time passes.
	FromCache bool
}

type gateDeps struct {
	adapter       *Adapter
	scanner       ImageScanner
	av            gate.AVScanner
	filter        gate.SCFilter
	policy        gate.PolicyDecider
	store         *verdictStore
	tags          *tagIndex
	maxLayerBytes int64
	logger        zerolog.Logger
}

type manifestGate struct{ gateDeps }

func newManifestGate(d gateDeps) *manifestGate { return &manifestGate{d} }

// Evaluate runs the full gate for repo:ref. It returns the canonical manifest
// digest and the verdict. A multi-arch index is passed through un-gated (it has
// no image content; the client then requests a concrete child manifest by
// digest, which is gated on its own request). Infrastructure failures (fetch,
// scan errors) return a non-nil error so the handler fails closed.
func (g *manifestGate) Evaluate(ctx context.Context, repo, ref string) (string, GateVerdict, error) {
	// Fetch the raw manifest for ref (tag or digest); indexes are not resolved
	// server-side, so the client's own platform choice drives what gets gated.
	manifestBody, contentType, digest, err := g.adapter.FetchManifest(ctx, repo, ref)
	if err != nil {
		return "", GateVerdict{}, fmt.Errorf("resolving manifest %s:%s: %w", repo, ref, err)
	}

	// When a multi-arch index is requested by tag, remember each child platform
	// digest → tag so the gated by-digest pull that follows can be recorded
	// against the human tag rather than the opaque child digest. Done before the
	// cache check so the (in-memory) map stays warm even when the index verdict
	// is served from the (on-disk) cache or after a restart.
	if g.tags != nil && isIndexMediaType(contentType) && !isDigestRef(ref) {
		g.tags.rememberChildren(repo, ref, manifestBody)
	}

	// Cached verdict? Supply-chain blocks are intentionally never cached (step 1
	// below): they are time-based and must be re-evaluated each pull. Ignore a
	// stale supply-chain block left in the on-disk store by an older build —
	// the store persists only clean+reason, not block_until, so restoring it
	// would block the image with a zero block_until (never shown in the
	// quarantine view) and would keep blocking it even after it matured. Fall
	// through to a fresh evaluation instead.
	if clean, reason, found := g.store.GetImageVerdict(repo, digest); found && !isStaleSupplyBlock(clean, reason) {
		v := GateVerdict{Allowed: clean, Reason: reason, Passthrough: isPassthroughReason(reason), FromCache: true}
		if !clean {
			v.BlockedBy = blockedByForReason(reason)
		} else if path, ok := g.store.GetManifestBody(repo, digest); ok {
			v.ManifestPath, v.ContentType = path, contentType
		}
		return digest, v, nil
	}

	// Multi-arch index: pass through un-gated. It lists per-platform child
	// manifests only; the client selects a platform and requests that child by
	// digest, which reaches Evaluate again as a concrete manifest and is gated.
	if isIndexMediaType(contentType) {
		return g.passthrough(ctx, repo, digest, manifestBody, contentType, reasonIndexPassthrough)
	}

	// Non-image manifest (e.g. a buildx attestation manifest whose layers are
	// in-toto JSON, not a filesystem): pass through un-gated. Trivy/ClamAV cannot
	// and must not scan it, and it carries no executable image content. The real
	// platform image manifests in the same index are gated on their own requests.
	if !isImageManifest(manifestBody) {
		return g.passthrough(ctx, repo, digest, manifestBody, contentType, reasonAttestationPassthrough)
	}

	pkgRef := &gate.PackageRef{Ecosystem: "docker", Name: repo, Version: ref}

	// Parse manifest → config.created + config digest + layer digests.
	created, configDigest, layers, err := g.adapter.ImageConfig(ctx, repo, manifestBody)
	if err != nil {
		return "", GateVerdict{}, err
	}

	// 1. Supply-chain (config.created as the publish proxy).
	fr := g.filter.Check(ctx, pkgRef, &gate.PackageMetadata{PublishedAt: created})
	if !fr.Allowed {
		// A supply-chain hold is time-based: it expires when the image matures.
		// Do NOT cache it — re-evaluate on every pull so the block lifts on its
		// own, and so each pull records a fresh block event with a current
		// block_until for the quarantine view.
		return digest, GateVerdict{
			Allowed:     false,
			Reason:      fr.Reason,
			BlockedBy:   "supply_chain",
			PublishedAt: fr.PublishedAt,
			BlockUntil:  fr.BlockUntil,
		}, nil
	}

	// 2. Trivy → policy (severity threshold + denylist).
	scan, err := g.scanner.ScanImage(ctx, g.imageRef(repo, digest))
	if err != nil {
		return "", GateVerdict{}, err
	}
	if g.policy != nil {
		decision := g.policy.Evaluate(pkgRef, &gate.ScanResult{
			Clean:    len(scan.Findings) == 0,
			Findings: scan.Findings,
		})
		if !decision.Allowed {
			by := "cve"
			if decision.Reason == gate.ReasonDenylisted {
				by = "denylist"
			}
			v := GateVerdict{Allowed: false, Reason: decision.Reason, BlockedBy: by, Findings: decision.Findings}
			_ = g.cacheVerdict(ctx, repo, digest, manifestBody, v)
			return digest, v, nil
		}
	}

	// 3. ClamAV over the config blob and each layer (fail-closed on oversize /
	// infection / error). The config blob is included so that subsequent
	// GET /v2/<repo>/blobs/<configDigest> requests are served from cache;
	// scanLayer is cache-aware, so the small double-fetch of the config is
	// acceptable.
	if g.av != nil {
		blobs := layers
		if configDigest != "" {
			blobs = append([]string{configDigest}, layers...)
		}
		for _, b := range blobs {
			infected, scanErr := g.scanLayer(ctx, repo, b)
			if scanErr != nil {
				return "", GateVerdict{}, scanErr
			}
			if infected {
				v := GateVerdict{Allowed: false, Reason: "malware_found", BlockedBy: "malware"}
				_ = g.cacheVerdict(ctx, repo, digest, manifestBody, v)
				return digest, v, nil
			}
		}
	}

	// Clean.
	v := GateVerdict{Allowed: true, Reason: "ok", PublishedAt: created, ContentType: contentType}
	if err := g.cacheVerdict(ctx, repo, digest, manifestBody, v); err != nil {
		return "", GateVerdict{}, err
	}
	if path, ok := g.store.GetManifestBody(repo, digest); ok {
		v.ManifestPath = path
	}
	return digest, v, nil
}

// passthrough caches and returns an allowed, un-gated verdict for a manifest
// with no scannable image content (a multi-arch index or an attestation
// manifest). The body is cached so the subsequent serve is from cache.
func (g *manifestGate) passthrough(ctx context.Context, repo, digest string, manifestBody []byte, contentType, reason string) (string, GateVerdict, error) {
	v := GateVerdict{Allowed: true, Reason: reason, ContentType: contentType, Passthrough: true}
	if err := g.cacheVerdict(ctx, repo, digest, manifestBody, v); err != nil {
		return "", GateVerdict{}, err
	}
	if path, ok := g.store.GetManifestBody(repo, digest); ok {
		v.ManifestPath = path
	}
	return digest, v, nil
}

// scanLayer downloads a layer (unless cached clean), enforces the size limit,
// runs the AV scanner, and caches the per-blob verdict. Returns infected=true on
// a malware hit or an oversized layer (fail-closed). An error means the layer
// could not be checked (handler fails closed with 5xx).
func (g *manifestGate) scanLayer(ctx context.Context, repo, digest string) (bool, error) {
	if _, clean, found := g.store.GetBlob(digest); found {
		return !clean, nil
	}
	rc, size, err := g.adapter.FetchBlob(ctx, repo, digest)
	if err != nil {
		return false, fmt.Errorf("fetching layer %s: %w", digest, err)
	}
	defer rc.Close()

	if g.maxLayerBytes > 0 && size > g.maxLayerBytes {
		// Oversized: fail-closed, cache as not-clean so repeats stay blocked.
		_ = g.store.PutBlob(digest, os.DevNull, false)
		return true, nil
	}

	tmp, err := os.CreateTemp("", "jo-ei-layer-*")
	if err != nil {
		return false, fmt.Errorf("creating temp layer file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	limit := g.maxLayerBytes
	var written int64
	if limit > 0 {
		written, err = io.Copy(tmp, io.LimitReader(rc, limit+1))
	} else {
		written, err = io.Copy(tmp, rc)
	}
	tmp.Close()
	if err != nil {
		return false, fmt.Errorf("buffering layer %s: %w", digest, err)
	}
	if limit > 0 && written > limit {
		_ = g.store.PutBlob(digest, os.DevNull, false)
		return true, nil
	}

	res, err := g.av.Scan(ctx, tmpPath)
	if err != nil {
		return false, fmt.Errorf("AV scanning layer %s: %w", digest, err)
	}
	if err := g.store.PutBlob(digest, tmpPath, res.Clean); err != nil {
		return false, fmt.Errorf("caching layer %s: %w", digest, err)
	}
	return !res.Clean, nil
}

// cacheVerdict writes the manifest body + verdict to the store under the digest.
func (g *manifestGate) cacheVerdict(_ context.Context, repo, digest string, manifestBody []byte, v GateVerdict) error {
	tmp, err := os.CreateTemp("", "jo-ei-manifest-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(manifestBody); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	tmp.Close()
	defer os.Remove(tmpPath)
	return g.store.PutImageVerdict(repo, digest, tmpPath, v.Allowed, v.Reason)
}

// imageRef builds the "<host>/<repo>@<digest>" string Trivy scans. The host is
// taken from the first upstream (scheme stripped).
func (g *manifestGate) imageRef(repo, digest string) string {
	host := hostFromUpstream(g.adapter.upstreams)
	return host + "/" + repo + "@" + digest
}

// isStaleSupplyBlock reports whether a cached verdict is a supply-chain block.
// The current gate never caches these (a supply-chain hold is time-based; see
// Evaluate step 1), so such an entry can only have been written by an older
// build. The verdict store does not persist the block_until timestamp, so the
// entry must be re-evaluated rather than trusted.
func isStaleSupplyBlock(clean bool, reason string) bool {
	return !clean && blockedByForReason(reason) == "supply_chain"
}

func blockedByForReason(reason string) string {
	switch reason {
	case "malware_found":
		return "malware"
	case gate.ReasonDenylisted:
		return "denylist"
	case "cve_found":
		return "cve"
	default:
		return "supply_chain"
	}
}
