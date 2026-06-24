package dockerproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Manifest / index media types we accept and recognise.
const (
	mediaTypeSchema2Manifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeSchema2List     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeOCIManifest     = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeOCIIndex        = "application/vnd.oci.image.index.v1+json"
)

var manifestAccept = strings.Join([]string{
	mediaTypeSchema2Manifest, mediaTypeSchema2List,
	mediaTypeOCIManifest, mediaTypeOCIIndex,
}, ", ")

// Adapter talks to upstream Docker registries, handling bearer-token auth. It
// is safe for concurrent use.
type Adapter struct {
	upstreams []string
	client    *http.Client
}

// NewAdapter creates an Adapter over the given ordered upstream base URLs
// (e.g. "https://registry-1.docker.io"). Trailing slashes are trimmed.
func NewAdapter(upstreams []string) *Adapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &Adapter{upstreams: trimmed, client: &http.Client{Timeout: 120 * time.Second}}
}

// do issues a request to base+path with bearer-token auth retry. accept sets the
// Accept header (empty → none). Returns the response; caller closes the body.
func (a *Adapter) do(ctx context.Context, method, base, path, accept string) (*http.Response, error) {
	build := func(token string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return a.client.Do(req)
	}
	resp, err := build("")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	// Token auth: parse Www-Authenticate, fetch a token, retry once.
	challenge := resp.Header.Get("Www-Authenticate")
	resp.Body.Close()
	token, terr := a.fetchToken(ctx, challenge)
	if terr != nil {
		return nil, terr
	}
	return build(token)
}

// fetchToken resolves a Bearer challenge of the form
// `Bearer realm="https://auth.docker.io/token",service="...",scope="..."`.
func (a *Adapter) fetchToken(ctx context.Context, challenge string) (string, error) {
	if !strings.HasPrefix(challenge, "Bearer ") {
		return "", fmt.Errorf("unsupported auth challenge %q", challenge)
	}
	params := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(challenge, "Bearer "), ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			params[kv[0]] = strings.Trim(kv[1], `"`)
		}
	}
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("auth challenge missing realm")
	}
	u := realm + "?service=" + params["service"] + "&scope=" + params["scope"]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.Token != "" {
		return tok.Token, nil
	}
	return tok.AccessToken, nil
}

// ResolveDigest HEADs the manifest and returns the canonical content digest.
func (a *Adapter) ResolveDigest(ctx context.Context, repo, ref string) (string, error) {
	var lastErr error
	for _, base := range a.upstreams {
		resp, err := a.do(ctx, http.MethodHead, base, "/v2/"+repo+"/manifests/"+ref, manifestAccept)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if dg := resp.Header.Get("Docker-Content-Digest"); dg != "" {
				return dg, nil
			}
			lastErr = fmt.Errorf("upstream omitted Docker-Content-Digest for %s/%s", repo, ref)
			continue
		}
		lastErr = fmt.Errorf("HEAD manifest %s/%s: HTTP %d", repo, ref, resp.StatusCode)
	}
	return "", lastErr
}

// FetchManifest fetches the raw manifest for ref (a tag or digest) and returns
// its body, content type, and canonical digest. A multi-arch index is returned
// as-is, NOT resolved to a platform: the Docker client performs platform
// selection itself by requesting the concrete child manifest by digest, which
// the proxy then gates on its own. This guarantees the image the client
// actually pulls is the one scanned, on any host architecture.
func (a *Adapter) FetchManifest(ctx context.Context, repo, ref string) ([]byte, string, string, error) {
	return a.getManifest(ctx, repo, ref)
}

// isIndexMediaType reports whether ct is a multi-arch image index / manifest
// list, which lists per-platform child manifests rather than image content.
func isIndexMediaType(ct string) bool {
	return ct == mediaTypeOCIIndex || ct == mediaTypeSchema2List
}

// isImageManifest reports whether the manifest describes a runnable image —
// i.e. it has at least one layer and every layer is a filesystem (tar) layer.
// It is false for non-image manifests such as buildx attestation manifests,
// whose "layers" are in-toto JSON (SBOM/provenance), not tar archives. Those
// must NOT be handed to Trivy/ClamAV (extraction fails: "invalid tar header");
// they carry no executable image content and are passed through un-gated.
func isImageManifest(manifestBody []byte) bool {
	var m struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBody, &m); err != nil {
		return false
	}
	if len(m.Layers) == 0 {
		return false
	}
	for _, l := range m.Layers {
		if !isFilesystemLayer(l.MediaType) {
			return false
		}
	}
	return true
}

// isFilesystemLayer reports whether a layer media type is an actual filesystem
// layer (OCI or Docker schema2, plain/gzip/zstd tar) as opposed to a
// non-filesystem payload like an in-toto attestation.
func isFilesystemLayer(mt string) bool {
	switch mt {
	case "application/vnd.oci.image.layer.v1.tar",
		"application/vnd.oci.image.layer.v1.tar+gzip",
		"application/vnd.oci.image.layer.v1.tar+zstd",
		"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
		"application/vnd.docker.image.rootfs.diff.tar.gzip",
		"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":
		return true
	}
	return false
}

// getManifest GETs a manifest by ref/digest from the first working upstream.
func (a *Adapter) getManifest(ctx context.Context, repo, ref string) ([]byte, string, string, error) {
	var lastErr error
	for _, base := range a.upstreams {
		resp, err := a.do(ctx, http.MethodGet, base, "/v2/"+repo+"/manifests/"+ref, manifestAccept)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("GET manifest %s/%s: HTTP %d", repo, ref, resp.StatusCode)
			continue
		}
		b, rerr := io.ReadAll(resp.Body)
		dg := resp.Header.Get("Docker-Content-Digest")
		ct := resp.Header.Get("Content-Type")
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if dg == "" {
			dg = ref
		}
		return b, ct, dg, nil
	}
	return nil, "", "", lastErr
}

// FetchBlob opens a blob (config or layer) stream from the first working
// upstream. The caller must close the returned ReadCloser.
func (a *Adapter) FetchBlob(ctx context.Context, repo, digest string) (io.ReadCloser, int64, error) {
	var lastErr error
	for _, base := range a.upstreams {
		resp, err := a.do(ctx, http.MethodGet, base, "/v2/"+repo+"/blobs/"+digest, "")
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("GET blob %s/%s: HTTP %d", repo, digest, resp.StatusCode)
			continue
		}
		return resp.Body, resp.ContentLength, nil
	}
	return nil, 0, lastErr
}

// hostFromUpstream returns the host[:port] of the first upstream, scheme
// stripped, for building the image reference Trivy scans. Empty list → "".
//
// Docker Hub's registry endpoint host ("registry-1.docker.io", and the
// "index.docker.io" alias) is normalized to the canonical "docker.io". Trivy /
// go-containerregistry only apply Docker Hub's auth and pull semantics for the
// canonical name; given the literal "registry-1.docker.io" they treat it as a
// generic registry and layer pulls fail (manifests resolve, but layer blobs come
// back unusable — "archive/tar: invalid tar header"). Other registry hosts
// (GHCR, Quay, private) are returned unchanged.
func hostFromUpstream(upstreams []string) string {
	if len(upstreams) == 0 {
		return ""
	}
	h := upstreams[0]
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimRight(h, "/")
	switch h {
	case "registry-1.docker.io", "index.docker.io":
		return "docker.io"
	}
	return h
}

// ImageConfig parses a schema2/OCI manifest, fetches its config blob, and
// returns the image's created time, the config blob digest, and the ordered
// layer digests. The config digest is returned so the caller can cache the
// config blob alongside the layers (required for docker pull to succeed).
func (a *Adapter) ImageConfig(ctx context.Context, repo string, manifestBody []byte) (created time.Time, configDigest string, layers []string, err error) {
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBody, &m); err != nil {
		return time.Time{}, "", nil, fmt.Errorf("decoding manifest: %w", err)
	}
	layers = make([]string, len(m.Layers))
	for i, l := range m.Layers {
		layers[i] = l.Digest
	}
	configDigest = m.Config.Digest

	if configDigest != "" {
		rc, _, ferr := a.FetchBlob(ctx, repo, configDigest)
		if ferr != nil {
			return time.Time{}, "", nil, fmt.Errorf("fetching config blob: %w", ferr)
		}
		defer rc.Close()
		var cfg struct {
			Created string `json:"created"`
		}
		if err := json.NewDecoder(rc).Decode(&cfg); err != nil {
			return time.Time{}, "", nil, fmt.Errorf("decoding config blob: %w", err)
		}
		if cfg.Created != "" {
			t, perr := time.Parse(time.RFC3339, cfg.Created)
			if perr != nil {
				return time.Time{}, "", nil, fmt.Errorf("parsing config.created %q: %w", cfg.Created, perr)
			}
			created = t.UTC()
		}
	}
	return created, configDigest, layers, nil
}
