package image

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Media types Box understands.
const (
	mtOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mtOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mtDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mtSchema1        = "application/vnd.docker.distribution.manifest.v1+json"
	mtSchema1Signed  = "application/vnd.docker.distribution.manifest.v1+prettyjws"
)

var manifestAccept = strings.Join([]string{mtOCIIndex, mtOCIManifest, mtDockerList, mtDockerManifest}, ", ")

const userAgent = "tkbox-image/0"

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *platform         `json:"platform,omitempty"`
	URLs        []string          `json:"urls,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

// manifestDoc is either an index (Manifests) or an image manifest (Config + Layers).
type manifestDoc struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
	Manifests     []descriptor `json:"manifests"`
}

type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
	Config       struct {
		Env        []string
		WorkingDir string
		Entrypoint []string
		Cmd        []string
		User       string
	} `json:"config"`
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// unreachableError means the registry could not be asked at all (network, TLS, 5xx, rate limit), as opposed to
// answering no. Only this kind of failure falls back to the cached ref index.
type unreachableError struct {
	host string
	err  error
}

func (e *unreachableError) Error() string {
	return fmt.Sprintf("cannot reach registry %s: %v (check the network and proxy settings, then retry)", e.host, e.err)
}

func (e *unreachableError) Unwrap() error { return e.err }

// registry is our registry v2 client: HTTPS only, anonymous with bearer tokens on demand.
type registry struct {
	client *http.Client
	stall  time.Duration

	mu     sync.Mutex
	tokens map[string]string // "host/repo" → bearer token
}

func newRegistry(opts Options, stall time.Duration) *registry {
	tr := opts.Transport
	if tr == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.RootCAs}
		t.ResponseHeaderTimeout = stall
		tr = t
	}
	return &registry{
		stall:  stall,
		tokens: map[string]string{},
		client: &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("more than 10 redirects")
			}
			// Go drops Authorization itself when a redirect leaves the host (blob CDNs).
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirected to %s, which is not HTTPS; Box refuses plain HTTP", req.URL.Redacted())
			}
			return nil
		}},
	}
}

// get sends a GET for path under the repository's /v2/ API, fetching a bearer token when the registry asks for one.
func (r *registry) get(ctx context.Context, ref reference, path, accept string) (*http.Response, error) {
	return r.do(ctx, http.MethodGet, ref, path, accept)
}

func (r *registry) do(ctx context.Context, method string, ref reference, path, accept string) (*http.Response, error) {
	u := "https://" + ref.apiHost() + "/v2/" + ref.Repo + path
	key := ref.apiHost() + "/" + ref.Repo
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		r.mu.Lock()
		tok := r.tokens[key]
		r.mu.Unlock()
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := r.client.Do(req)
		if err != nil {
			return nil, netErr(ctx, ref.apiHost(), err)
		}
		if resp.StatusCode != http.StatusUnauthorized || attempt > 0 {
			return resp, nil
		}
		chal := resp.Header.Get("WWW-Authenticate")
		drain(resp)
		tok, err = r.fetchToken(ctx, ref, chal)
		if err != nil {
			return nil, err
		}
		r.mu.Lock()
		r.tokens[key] = tok
		r.mu.Unlock()
	}
}

func netErr(ctx context.Context, host string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return &unreachableError{host: host, err: err}
}

func drain(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

// statusError turns a non-200 answer into an error that says what to do.
func statusError(ref reference, what string, resp *http.Response) error {
	defer drain(resp)
	host := ref.apiHost()
	switch c := resp.StatusCode; {
	case c == http.StatusUnauthorized || c == http.StatusForbidden:
		return fmt.Errorf("registry %s refused access to %s (%s): Box pulls public images anonymously; check the name, or make the image public (private registries are not supported in v0)", host, ref.Name(), resp.Status)
	case c == http.StatusNotFound:
		return fmt.Errorf("%s not found on %s (%s): check the image name and tag", what, host, ref.Name())
	case c == http.StatusTooManyRequests:
		return &unreachableError{host: host, err: fmt.Errorf("rate limited (%s); Docker Hub limits anonymous pulls, wait and retry or use a mirror such as public.ecr.aws or ghcr.io", resp.Status)}
	case c >= 500:
		return &unreachableError{host: host, err: fmt.Errorf("server error %s fetching %s", resp.Status, what)}
	default:
		return fmt.Errorf("registry %s answered %s fetching %s for %s", host, resp.Status, what, ref.Name())
	}
}

// fetchToken follows a Bearer challenge: GET the realm anonymously with service and scope, read token/access_token.
func (r *registry) fetchToken(ctx context.Context, ref reference, challenge string) (string, error) {
	scheme, params := parseChallenge(challenge)
	if !strings.EqualFold(scheme, "bearer") {
		return "", fmt.Errorf("registry %s wants %q credentials for %s: Box pulls public images anonymously (private registries are not supported in v0)", ref.apiHost(), scheme, ref.Name())
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Scheme != "https" || realm.Host == "" {
		return "", fmt.Errorf("registry %s sent token realm %q, which is not an HTTPS URL; refusing", ref.apiHost(), params["realm"])
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + ref.Repo + ":pull"
	}
	for _, s := range strings.Fields(scope) {
		q.Add("scope", s)
	}
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := r.client.Do(req)
	if err != nil {
		return "", netErr(ctx, realm.Host, err)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return "", &unreachableError{host: realm.Host, err: fmt.Errorf("token service answered %s", resp.Status)}
		}
		return "", fmt.Errorf("token service %s refused an anonymous token for %s (%s): the image may be private or misspelled", realm.Host, ref.Name(), resp.Status)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("token service %s sent an unreadable answer: %v", realm.Host, err)
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", fmt.Errorf("token service %s sent no token for %s", realm.Host, ref.Name())
}

// parseChallenge splits `Bearer realm="…",service="…",scope="…"` into the scheme and its parameters.
func parseChallenge(h string) (string, map[string]string) {
	h = strings.TrimSpace(h)
	scheme, rest, _ := strings.Cut(h, " ")
	params := map[string]string{}
	for {
		rest = strings.TrimLeft(rest, " \t,")
		if rest == "" {
			return scheme, params
		}
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			return scheme, params
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = strings.TrimLeft(rest[eq+1:], " \t")
		var val strings.Builder
		if strings.HasPrefix(rest, `"`) {
			i := 1
			for ; i < len(rest) && rest[i] != '"'; i++ {
				if rest[i] == '\\' && i+1 < len(rest) {
					i++
				}
				val.WriteByte(rest[i])
			}
			rest = rest[min(i+1, len(rest)):]
		} else {
			end := strings.IndexByte(rest, ',')
			if end < 0 {
				end = len(rest)
			}
			val.WriteString(strings.TrimSpace(rest[:end]))
			rest = rest[end:]
		}
		params[key] = val.String()
	}
}

// fetchManifest GETs a manifest or index by tag or digest, capped at max bytes, and returns its body, media type and
// sha256 digest. A digest request must match byte for byte; a tag request must match Docker-Content-Digest if sent.
func (r *registry) fetchManifest(ctx context.Context, ref reference, tagOrDigest string, max int64) ([]byte, string, string, error) {
	// Manifests are small: a registry that trickles one for longer than this is treated as unreachable.
	limit := 2 * r.stall
	tctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	body, ct, dg, err := r.fetchManifestOnce(tctx, ref, tagOrDigest, max)
	if err != nil && ctx.Err() == nil && tctx.Err() != nil {
		err = &unreachableError{host: ref.apiHost(), err: fmt.Errorf("no complete manifest within %s", limit)}
	}
	return body, ct, dg, err
}

// headDigest asks for a tag's digest without fetching the manifest (Docker Hub does not count HEADs against its
// anonymous pull limit). It returns "" when the registry does not say.
func (r *registry) headDigest(ctx context.Context, ref reference, tag string) string {
	tctx, cancel := context.WithTimeout(ctx, r.stall)
	defer cancel()
	resp, err := r.do(tctx, http.MethodHead, ref, "/manifests/"+tag, manifestAccept)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	if d := resp.Header.Get("Docker-Content-Digest"); resp.StatusCode == http.StatusOK && checkDigest(d) == nil {
		return d
	}
	return ""
}

func (r *registry) fetchManifestOnce(ctx context.Context, ref reference, tagOrDigest string, max int64) ([]byte, string, string, error) {
	resp, err := r.get(ctx, ref, "/manifests/"+tagOrDigest, manifestAccept)
	if err != nil {
		return nil, "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", "", statusError(ref, "manifest "+tagOrDigest, resp)
	}
	defer drain(resp)
	if resp.ContentLength > max {
		return nil, "", "", manifestTooBig(ref, max)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, "", "", netErr(ctx, ref.apiHost(), err)
	}
	if int64(len(body)) > max {
		return nil, "", "", manifestTooBig(ref, max)
	}
	sum := sha256.Sum256(body)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if strings.HasPrefix(tagOrDigest, "sha256:") && got != tagOrDigest {
		return nil, "", "", fmt.Errorf("registry %s served a manifest for %s whose sha256 is %s; refusing unverified content", ref.apiHost(), tagOrDigest, got)
	}
	if h := resp.Header.Get("Docker-Content-Digest"); strings.HasPrefix(h, "sha256:") && h != got {
		return nil, "", "", fmt.Errorf("registry %s says %s has digest %s but the bytes hash to %s; refusing unverified content", ref.apiHost(), ref.Name(), h, got)
	}
	ct, _, _ := strings.Cut(resp.Header.Get("Content-Type"), ";")
	return body, strings.TrimSpace(ct), got, nil
}

func manifestTooBig(ref reference, max int64) error {
	return fmt.Errorf("manifest for %s is over the %s limit (ManifestBytes); Box refuses oversized manifests: check the image", ref.Name(), human(max))
}

// fetchBlob streams blob d into w, failing unless it is exactly d.Size bytes with digest d.Digest. A response that
// sends nothing for the stall timeout is cancelled.
func (r *registry) fetchBlob(ctx context.Context, ref reference, d descriptor, w io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stalled atomic.Bool
	timer := time.AfterFunc(r.stall, func() { stalled.Store(true); cancel() })
	defer timer.Stop()
	resp, err := r.get(ctx, ref, "/blobs/"+d.Digest, "")
	if err != nil {
		if stalled.Load() {
			return fmt.Errorf("registry %s sent nothing for %s while fetching %s; retry", ref.apiHost(), r.stall, short(d.Digest))
		}
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return statusError(ref, "blob "+short(d.Digest), resp)
	}
	defer drain(resp)
	if resp.ContentLength >= 0 && resp.ContentLength != d.Size {
		return fmt.Errorf("registry %s sends %d bytes for blob %s but the manifest says %d; refusing", ref.apiHost(), resp.ContentLength, short(d.Digest), d.Size)
	}
	h := sha256.New()
	body := &resetReader{r: resp.Body, t: timer, d: r.stall}
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(body, d.Size+1))
	if err != nil {
		if stalled.Load() {
			return fmt.Errorf("registry %s stopped sending blob %s for %s; retry", ref.apiHost(), short(d.Digest), r.stall)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("downloading blob %s from %s: %w", short(d.Digest), ref.apiHost(), err)
	}
	if n != d.Size {
		return fmt.Errorf("blob %s from %s is %d bytes but the manifest says %d; refusing", short(d.Digest), ref.apiHost(), n, d.Size)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != d.Digest {
		return fmt.Errorf("blob %s from %s hashes to %s; refusing unverified content", short(d.Digest), ref.apiHost(), got)
	}
	return nil
}

// resetReader pushes the stall timer back whenever bytes arrive.
type resetReader struct {
	r io.Reader
	t *time.Timer
	d time.Duration
}

func (s *resetReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.t.Reset(s.d)
	}
	return n, err
}

func short(digest string) string {
	if len(digest) > 19 {
		return digest[:19]
	}
	return digest
}

func human(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%d GiB", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
