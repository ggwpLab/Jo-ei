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
)

// maxAttestationBlobBytes caps an attestation blob fetched for a client.
// SBOM and provenance documents are kilobytes to a few megabytes; anything
// bigger is not served through this un-gated path.
const maxAttestationBlobBytes = 16 << 20

// defaultAttestationBlobsMax bounds the remembered attestation blob digests.
const defaultAttestationBlobsMax = 4096

// attestationBlobs remembers which blobs belong to attestation manifests the
// proxy has served. Those manifests pass through un-gated — their "layers" are
// in-toto JSON (SBOM/provenance), not a filesystem — so their blobs never
// enter the gated cache; containerd-based clients still fetch them, and would
// otherwise get 404 and fail the whole pull. Only the config and
// non-filesystem layers are remembered: a tar layer listed in such a manifest
// is never served this way. Bounded, in-memory, scoped by repository; it is
// refilled whenever the manifest is served again, cached or not.
type attestationBlobs struct {
	mu      sync.Mutex
	max     int
	entries map[string]struct{} // "repo@digest"
	order   []string
}

func newAttestationBlobs(max int) *attestationBlobs {
	if max <= 0 {
		max = defaultAttestationBlobsMax
	}
	return &attestationBlobs{max: max, entries: map[string]struct{}{}}
}

// remember records the config and non-filesystem layer digests of an
// attestation manifest served for repo.
func (a *attestationBlobs) remember(repo string, manifestBody []byte) {
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
		if l.Digest != "" && !isFilesystemLayer(l.MediaType) {
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
