package dockerproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/sync/singleflight"
)

// maxAttestationBlobBytes caps an attestation blob fetched for a client.
// SBOM and provenance documents are kilobytes to low megabytes; anything
// bigger is not served through this un-gated path.
const maxAttestationBlobBytes = 4 << 20

// defaultAttestationBlobsMax bounds the remembered attestation blob digests.
const defaultAttestationBlobsMax = 4096

// attestationBlobs remembers which blobs belong to attestation manifests the
// proxy has served. Those manifests pass through un-gated — every layer is an
// in-toto statement (SBOM/provenance), not a filesystem — so their blobs never
// enter the gated cache; containerd-based clients still fetch them, and would
// otherwise get 404 and fail the whole pull. Only a manifest that
// isAttestationManifest accepts is remembered, and only its config and in-toto
// layers. Bounded, in-memory, scoped by repository; it is refilled whenever
// the manifest is served again, cached or not.
type attestationBlobs struct {
	mu      sync.Mutex
	max     int
	entries map[string]struct{} // "repo@digest"
	order   []string
	// fetches coalesces concurrent requests for one blob, so N clients cost
	// one upstream download and one buffer.
	fetches singleflight.Group
}

func newAttestationBlobs(max int) *attestationBlobs {
	if max <= 0 {
		max = defaultAttestationBlobsMax
	}
	return &attestationBlobs{max: max, entries: map[string]struct{}{}}
}

// remember records the config and in-toto layer digests of an attestation
// manifest served for repo. Anything isAttestationManifest rejects is ignored,
// whatever verdict the cache holds for it.
func (a *attestationBlobs) remember(repo string, manifestBody []byte) {
	if !isAttestationManifest(manifestBody) {
		return
	}
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBody, &m); err != nil {
		return
	}
	if m.Config.Digest != "" {
		a.add(repo, m.Config.Digest)
	}
	for _, l := range m.Layers {
		if l.Digest != "" && isInTotoLayer(l.MediaType) {
			a.add(repo, l.Digest)
		}
	}
}

func (a *attestationBlobs) add(repo, digest string) {
	key := repo + "@" + digest
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.entries[key]; ok {
		return
	}
	if len(a.order) >= a.max {
		delete(a.entries, a.order[0])
		a.order = a.order[1:]
	}
	a.order = append(a.order, key)
	a.entries[key] = struct{}{}
}

func (a *attestationBlobs) has(repo, digest string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.entries[repo+"@"+digest]
	return ok
}

// errAttestationBlobRejected marks a fetched attestation blob that must not be
// served: over the cap, or its bytes do not match its digest.
var errAttestationBlobRejected = errors.New("attestation blob rejected")

// fetchAttestationBlob downloads one attestation blob, capped and verified
// against its sha256 digest.
func fetchAttestationBlob(ctx context.Context, adapter *Adapter, repo, digest string) ([]byte, error) {
	want, ok := strings.CutPrefix(digest, "sha256:")
	if !ok {
		return nil, fmt.Errorf("%w: unsupported digest %q", errAttestationBlobRejected, digest)
	}
	rc, size, err := adapter.FetchBlob(ctx, repo, digest)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	if size > maxAttestationBlobBytes {
		return nil, fmt.Errorf("%w: %d bytes", errAttestationBlobRejected, size)
	}
	var buf bytes.Buffer
	if size > 0 {
		buf.Grow(int(size))
	}
	if _, err := io.Copy(&buf, io.LimitReader(rc, maxAttestationBlobBytes+1)); err != nil {
		return nil, err
	}
	if buf.Len() > maxAttestationBlobBytes {
		return nil, fmt.Errorf("%w: over %d bytes", errAttestationBlobRejected, maxAttestationBlobBytes)
	}
	sum := sha256.Sum256(buf.Bytes())
	if hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("%w: digest mismatch", errAttestationBlobRejected)
	}
	return buf.Bytes(), nil
}

// maxAttestationLayers bounds the layers an attestation manifest may have.
// Real ones carry one to a few (SBOM, provenance); a manifest with more is
// gated like an image, and cannot flush the remembered set in one go.
const maxAttestationLayers = 64

// inTotoMediaType is the layer type of BuildKit/in-toto attestations.
const inTotoMediaType = "application/vnd.in-toto+json"

// isInTotoLayer reports whether a layer media type is an in-toto statement,
// compared the way clients compare media types: case-insensitive, parameters
// ignored.
func isInTotoLayer(mediaType string) bool {
	mt, _, _ := strings.Cut(mediaType, ";")
	mt = strings.ToLower(strings.TrimSpace(mt))
	return mt == inTotoMediaType || strings.HasPrefix(mt, "application/vnd.in-toto.")
}

// isAttestationManifest reports whether a manifest is an attestation: at
// least one and at most maxAttestationLayers layers, every one of them an
// in-toto statement. This is an allowlist on purpose — any layer whose type is
// not positively in-toto (a tar layer under a name this proxy does not know,
// an empty type, an OCI artifact) makes the manifest an image to gate, never
// one to pass through.
func isAttestationManifest(manifestBody []byte) bool {
	var m struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBody, &m); err != nil {
		return false
	}
	if len(m.Layers) == 0 || len(m.Layers) > maxAttestationLayers {
		return false
	}
	for _, l := range m.Layers {
		if !isInTotoLayer(l.MediaType) {
			return false
		}
	}
	return true
}
