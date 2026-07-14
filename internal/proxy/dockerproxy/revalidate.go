package dockerproxy

import (
	"context"
	"encoding/json"
	"os"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/revalidate"
)

// Revalidator re-validates cached Docker entries by re-running the manifest gate.
// It implements revalidate.Revalidator.
type Revalidator struct {
	gate  *manifestGate
	cache cache.Cache
}

// NewRevalidator builds a Docker revalidator sharing the same upstreams,
// scanners, and cache as the live handler (HandlerDeps).
func NewRevalidator(d HandlerDeps) *Revalidator {
	adapter := NewAdapter(d.Upstreams, d.HTTPClient)
	store := newVerdictStore(d.Cache)
	mgate := newManifestGate(gateDeps{
		adapter: adapter, scanner: d.Scanner, av: d.AV,
		filter: d.Filter, policy: d.Policy, store: store, tags: newTagIndex(0),
		maxLayerBytes: d.MaxLayerBytes, logger: d.Logger,
	})
	return &Revalidator{gate: mgate, cache: d.Cache}
}

// Revalidate re-runs the gate for an image-verdict entry. Standalone blob entries
// are owned by their image and re-validated transitively, so they are a no-op.
func (r *Revalidator) Revalidate(ctx context.Context, e cache.RevalEntry) (revalidate.Outcome, *revalidate.EvictReason) {
	if e.Ref.Name == "blobs" {
		return revalidate.Keep, nil
	}
	repo, digest := e.Ref.Name, e.Ref.Version
	// skipVerdictCache=true: this entry is, by definition, already cached — a
	// plain Evaluate would short-circuit on that same verdict and never touch
	// Trivy/ClamAV again, laundering a stale clean verdict as fresh forever.
	_, v, err := r.gate.evaluate(ctx, repo, digest, true)
	if err != nil {
		return revalidate.Retry, nil // upstream/scan infra error → retry next sweep
	}
	if v.Allowed {
		return revalidate.Keep, nil
	}
	// Blocked: cascade-evict the image's config + layer blobs (their digests come
	// from the cached manifest body), then signal the manifest entry's eviction.
	for _, d := range manifestBlobDigests(e.FilePath) {
		_ = r.cache.Invalidate(blobRef(d))
	}
	return revalidate.Evict, &revalidate.EvictReason{
		Gate:      gateForBlockedBy(v.BlockedBy),
		Reason:    v.Reason,
		BlockedBy: v.BlockedBy,
	}
}

// manifestBlobDigests reads the cached manifest file and returns its config and
// layer digests. Best-effort: read/parse failures yield nil.
func manifestBlobDigests(manifestPath string) []string {
	body, err := os.ReadFile(manifestPath) // #nosec G304 -- cached manifest path from the verdict store, inside the cache root
	if err != nil {
		return nil
	}
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	var out []string
	if m.Config.Digest != "" {
		out = append(out, m.Config.Digest)
	}
	for _, l := range m.Layers {
		if l.Digest != "" {
			out = append(out, l.Digest)
		}
	}
	return out
}
