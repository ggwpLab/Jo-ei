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

const defaultPlatform = "linux/amd64"

// Adapter talks to upstream Docker registries, handling bearer-token auth and
// multi-arch index resolution. It is safe for concurrent use.
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

// FetchManifest fetches the manifest for ref. If it is a multi-arch index, the
// child manifest matching platform (default linux/amd64) is fetched and returned.
func (a *Adapter) FetchManifest(ctx context.Context, repo, ref, platform string) ([]byte, string, string, error) {
	if platform == "" {
		platform = defaultPlatform
	}
	body, ct, dg, err := a.getManifest(ctx, repo, ref)
	if err != nil {
		return nil, "", "", err
	}
	if ct != mediaTypeOCIIndex && ct != mediaTypeSchema2List {
		return body, ct, dg, nil
	}
	childDigest, err := selectPlatform(body, platform)
	if err != nil {
		return nil, "", "", err
	}
	return a.getManifest(ctx, repo, childDigest)
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

// selectPlatform returns the child manifest digest for "os/arch" from an index.
func selectPlatform(indexBody []byte, platform string) (string, error) {
	parts := strings.SplitN(platform, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid platform %q", platform)
	}
	wantOS, wantArch := parts[0], parts[1]
	var idx struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS   string `json:"os"`
				Arch string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexBody, &idx); err != nil {
		return "", fmt.Errorf("decoding manifest index: %w", err)
	}
	for _, m := range idx.Manifests {
		if m.Platform.OS == wantOS && m.Platform.Arch == wantArch {
			return m.Digest, nil
		}
	}
	return "", fmt.Errorf("platform %q not present in manifest index", platform)
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

// ImageConfig parses a schema2/OCI manifest, fetches its config blob, and
// returns the image's created time and the ordered layer digests.
func (a *Adapter) ImageConfig(ctx context.Context, repo string, manifestBody []byte) (time.Time, []string, error) {
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBody, &m); err != nil {
		return time.Time{}, nil, fmt.Errorf("decoding manifest: %w", err)
	}
	layers := make([]string, len(m.Layers))
	for i, l := range m.Layers {
		layers[i] = l.Digest
	}

	var created time.Time
	if m.Config.Digest != "" {
		rc, _, err := a.FetchBlob(ctx, repo, m.Config.Digest)
		if err != nil {
			return time.Time{}, nil, fmt.Errorf("fetching config blob: %w", err)
		}
		defer rc.Close()
		var cfg struct {
			Created string `json:"created"`
		}
		if err := json.NewDecoder(rc).Decode(&cfg); err != nil {
			return time.Time{}, nil, fmt.Errorf("decoding config blob: %w", err)
		}
		if cfg.Created != "" {
			t, perr := time.Parse(time.RFC3339, cfg.Created)
			if perr != nil {
				return time.Time{}, nil, fmt.Errorf("parsing config.created %q: %w", cfg.Created, perr)
			}
			created = t.UTC()
		}
	}
	return created, layers, nil
}
