package dockerproxy

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// GateVerdict is the per-image decision produced by the manifest gate.
type GateVerdict struct {
	Allowed      bool
	Reason       string // "ok" | "cve_found" | "denylisted" | "malware_found" | supply-chain reason
	BlockedBy    string // "supply_chain" | "cve" | "denylist" | "malware" (empty when allowed)
	Findings     []proxy.CVEFinding
	ManifestPath string // cached manifest body (allowed only)
	ContentType  string
	PublishedAt  time.Time
}

type gateDeps struct {
	adapter       *Adapter
	scanner       ImageScanner
	av            proxy.AVScanner
	filter        proxy.SCFilter
	policy        proxy.PolicyDecider
	store         *verdictStore
	maxLayerBytes int64
	logger        zerolog.Logger
}

type manifestGate struct{ gateDeps }

func newManifestGate(d gateDeps) *manifestGate { return &manifestGate{d} }

// Evaluate runs the full gate for repo:ref on the given platform. It returns the
// resolved image digest and the verdict. Infrastructure failures (resolve,
// fetch, scan errors) return a non-nil error so the handler fails closed.
func (g *manifestGate) Evaluate(ctx context.Context, repo, ref, platform string) (string, GateVerdict, error) {
	// Resolve the requested ref to a canonical digest for the selected platform
	// by fetching the (possibly index) manifest.
	manifestBody, contentType, digest, err := g.adapter.FetchManifest(ctx, repo, ref, platform)
	if err != nil {
		return "", GateVerdict{}, fmt.Errorf("resolving manifest %s:%s: %w", repo, ref, err)
	}

	// Cached verdict?
	if clean, reason, found := g.store.GetImageVerdict(repo, digest); found {
		v := GateVerdict{Allowed: clean, Reason: reason}
		if !clean {
			v.BlockedBy = blockedByForReason(reason)
		} else if path, ok := g.store.GetManifestBody(repo, digest); ok {
			v.ManifestPath, v.ContentType = path, contentType
		}
		return digest, v, nil
	}

	pkgRef := &proxy.PackageRef{Ecosystem: "docker", Name: repo, Version: ref}

	// Parse manifest → config.created + layer digests.
	created, layers, err := g.adapter.ImageConfig(ctx, repo, manifestBody)
	if err != nil {
		return "", GateVerdict{}, err
	}

	// 1. Supply-chain (config.created as the publish proxy).
	fr := g.filter.Check(ctx, pkgRef, &proxy.PackageMetadata{PublishedAt: created})
	if !fr.Allowed {
		v := GateVerdict{Allowed: false, Reason: fr.Reason, BlockedBy: "supply_chain", PublishedAt: created}
		_ = g.cacheVerdict(ctx, repo, digest, manifestBody, v)
		return digest, v, nil
	}

	// 2. Trivy → policy (severity threshold + denylist).
	scan, err := g.scanner.ScanImage(ctx, g.imageRef(repo, digest))
	if err != nil {
		return "", GateVerdict{}, err
	}
	if g.policy != nil {
		decision := g.policy.Evaluate(pkgRef, &proxy.ScanResult{
			Clean:    len(scan.Findings) == 0,
			Findings: scan.Findings,
		})
		if !decision.Allowed {
			by := "cve"
			if decision.Reason == proxy.ReasonDenylisted {
				by = "denylist"
			}
			v := GateVerdict{Allowed: false, Reason: decision.Reason, BlockedBy: by, Findings: decision.Findings}
			_ = g.cacheVerdict(ctx, repo, digest, manifestBody, v)
			return digest, v, nil
		}
	}

	// 3. ClamAV over each layer (fail-closed on oversize / infection / error).
	if g.av != nil {
		for _, layer := range layers {
			infected, scanErr := g.scanLayer(ctx, repo, layer)
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

func blockedByForReason(reason string) string {
	switch reason {
	case "malware_found":
		return "malware"
	case proxy.ReasonDenylisted:
		return "denylist"
	case "cve_found":
		return "cve"
	default:
		return "supply_chain"
	}
}
