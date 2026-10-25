package image

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Options configures the builder.
type Options struct {
	CacheDir string // images/ under the state dir
	// GuestBinary returns the path of the tkbox-guest binary for arch ("arm64", "amd64").
	GuestBinary func(arch string) (string, error)
	// Mkfs is the mkfs.ext4 binary (default: found in PATH); Debugfs likewise (used to set owners without root).
	Mkfs    string
	Debugfs string
	Git     string // default: git in PATH

	// Transport replaces the registry HTTP transport (tests point it at an httptest TLS server). Default: HTTPS with
	// the system roots, or RootCAs when set.
	Transport http.RoundTripper
	RootCAs   *x509.CertPool
	// StallTimeout fails a registry response that sends nothing for this long (default 60s).
	StallTimeout time.Duration
	// Parallel is how many layers download at once (default 4).
	Parallel int

	Limits Limits
	// Logf receives warnings, e.g. falling back to a cached image when the registry is unreachable (default log.Printf).
	Logf func(format string, args ...any)
}

// Limits caps what one image or workspace may cost the host. Zero fields take the defaults.
type Limits struct {
	ManifestBytes  int64 // one manifest or index (default 4 MiB)
	ConfigBytes    int64 // one image config (default 8 MiB)
	Layers         int   // layers in one image (default 128)
	LayerBytes     int64 // one layer: its compressed download and its uncompressed files each (default 4 GiB)
	ImageBytes     int64 // all layers together: compressed downloads, and uncompressed files (default 16 GiB)
	ImageEntries   int   // tar entries across all layers (default 1,000,000)
	WorkspaceFiles int   // files and symlinks in a workspace image (default 100,000)
	WorkspaceBytes int64 // their total size (default 4 GiB)
}

func (l Limits) withDefaults() Limits {
	def := func(v *int64, d int64) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&l.ManifestBytes, 4<<20)
	def(&l.ConfigBytes, 8<<20)
	def(&l.LayerBytes, 4<<30)
	def(&l.ImageBytes, 16<<30)
	def(&l.WorkspaceBytes, 4<<30)
	if l.Layers <= 0 {
		l.Layers = 128
	}
	if l.ImageEntries <= 0 {
		l.ImageEntries = 1_000_000
	}
	if l.WorkspaceFiles <= 0 {
		l.WorkspaceFiles = 100_000
	}
	return l
}

type builder struct {
	opts     Options
	lim      Limits
	reg      *registry
	parallel int
	logf     func(string, ...any)

	mu      sync.Mutex
	flights map[string]*flight
}

// NewBuilder returns the real Builder. mkfs.ext4 and debugfs are looked up when first needed, so a host without
// e2fsprogs can still construct one.
func NewBuilder(opts Options) (Builder, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("image: Options.CacheDir is required")
	}
	if opts.GuestBinary == nil {
		return nil, errors.New("image: Options.GuestBinary is required")
	}
	dir, err := filepath.Abs(opts.CacheDir)
	if err != nil {
		return nil, err
	}
	opts.CacheDir = dir
	for _, d := range []struct {
		name string
		mode os.FileMode
	}{{"", 0o755}, {"blobs/sha256", 0o755}, {"rootfs", 0o755}, {"refs", 0o755}, {"locks", 0o700}, {"tmp", 0o700}} {
		if err := os.MkdirAll(filepath.Join(dir, d.name), d.mode); err != nil {
			return nil, fmt.Errorf("image: creating cache dir: %w", err)
		}
	}
	stall := opts.StallTimeout
	if stall <= 0 {
		stall = 60 * time.Second
	}
	b := &builder{opts: opts, lim: opts.Limits.withDefaults(), reg: newRegistry(opts, stall), parallel: opts.Parallel,
		logf: opts.Logf, flights: map[string]*flight{}}
	if b.parallel <= 0 {
		b.parallel = 4
	}
	if b.logf == nil {
		b.logf = log.Printf
	}
	b.sweepTmp(6 * time.Hour)
	return b, nil
}

func (b *builder) dir(name string) string { return filepath.Join(b.opts.CacheDir, name) }

// sweepTmp removes partial downloads and staging dirs a crashed build left behind.
func (b *builder) sweepTmp(age time.Duration) {
	ents, _ := os.ReadDir(b.dir("tmp"))
	for _, e := range ents {
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > age {
			os.RemoveAll(filepath.Join(b.dir("tmp"), e.Name()))
		}
	}
}

// resolved is an image whose manifest and config are fetched and verified; its layers are not yet downloaded.
type resolved struct {
	ref    reference
	digest string // the platform manifest's digest
	man    manifestDoc
	config imageConfig
	comp   []string // per layer: "" (plain tar) or "gzip"
}

func (b *builder) Rootfs(ctx context.Context, refStr, arch string) (Rootfs, error) {
	ref, err := parseReference(refStr)
	if err != nil {
		return Rootfs{}, err
	}
	if arch != "arm64" && arch != "amd64" {
		return Rootfs{}, fmt.Errorf("image: arch %q is not supported (use arm64 or amd64)", arch)
	}
	guestPath, guestSum, err := b.guest(arch)
	if err != nil {
		return Rootfs{}, err
	}
	finish := func(r Rootfs) Rootfs { r.Ref, r.Name = refStr, ref.Name(); return r }
	// A digest pin cannot move, so a cached build of it needs no registry round trip.
	if ref.Digest != "" {
		if r, ok := b.fromIndex(ref, arch, guestSum); ok {
			return finish(r), nil
		}
	}
	res, err := b.resolve(ctx, ref, arch)
	if err != nil {
		var ue *unreachableError
		if errors.As(err, &ue) {
			if r, ok := b.fromIndex(ref, arch, guestSum); ok {
				b.logf("tkbox: warning: %v; using the cached %s (%s) from the last successful pull", err, ref.Name(), short(r.Digest))
				return finish(r), nil
			}
		}
		return Rootfs{}, err
	}
	key := cacheKey(res.digest, guestSum, arch)
	r, err := b.once(ctx, key, func(ctx context.Context) (Rootfs, error) {
		return b.build(ctx, res, key, guestPath, arch)
	})
	if err != nil {
		return Rootfs{}, err
	}
	b.saveIndex(ref, arch, res.digest)
	return finish(r), nil
}

func cacheKey(manifestDigest, guestSum, arch string) string {
	return strings.TrimPrefix(manifestDigest, "sha256:") + "-" + guestSum + "-" + arch
}

// guest checks the guest binary is an ELF for arch and returns its path and a sha256 prefix for the cache key.
func (b *builder) guest(arch string) (string, string, error) {
	p, err := b.opts.GuestBinary(arch)
	if err != nil {
		return "", "", fmt.Errorf("image: guest binary for %s: %w", arch, err)
	}
	f, err := os.Open(p)
	if err != nil {
		return "", "", fmt.Errorf("image: guest binary: %w (run make guest)", err)
	}
	defer f.Close()
	want := map[string]elf.Machine{"arm64": elf.EM_AARCH64, "amd64": elf.EM_X86_64}[arch]
	ef, err := elf.NewFile(f)
	if err != nil {
		return "", "", fmt.Errorf("image: guest binary %s is not an ELF executable (run make guest): %v", p, err)
	}
	if ef.Machine != want || ef.Class != elf.ELFCLASS64 {
		return "", "", fmt.Errorf("image: guest binary %s is for %v, not %s (run make guest)", p, ef.Machine, arch)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", err
	}
	return p, hex.EncodeToString(h.Sum(nil))[:16], nil
}

// resolve fetches the manifest for ref (through an index to the linux/arch image) and its config, all verified.
func (b *builder) resolve(ctx context.Context, ref reference, arch string) (*resolved, error) {
	body, mt, dg, err := b.reg.fetchManifest(ctx, ref, ref.manifestRef(), b.lim.ManifestBytes)
	if err != nil {
		return nil, err
	}
	b.storeBlob(dg, body)
	for depth := 0; ; depth++ {
		doc, isIndex, err := parseManifest(ref, body, mt)
		if err != nil {
			return nil, err
		}
		if isIndex {
			if depth >= 2 {
				return nil, fmt.Errorf("%s: indexes nested more than two deep; Box refuses it", ref.Name())
			}
			d, err := pickPlatform(ref, doc.Manifests, arch, b.lim.ManifestBytes)
			if err != nil {
				return nil, err
			}
			if body, err = b.manifestByDigest(ctx, ref, d.Digest); err != nil {
				return nil, err
			}
			mt, dg = d.MediaType, d.Digest
			continue
		}
		res := &resolved{ref: ref, digest: dg, man: doc}
		if err := b.checkLayers(res); err != nil {
			return nil, err
		}
		if err := checkDigest(doc.Config.Digest); err != nil {
			return nil, fmt.Errorf("%s: config: %v", ref.Name(), err)
		}
		if doc.Config.Size < 0 || doc.Config.Size > b.lim.ConfigBytes {
			return nil, fmt.Errorf("%s: image config is %d bytes, over the %s limit (ConfigBytes); Box refuses it", ref.Name(), doc.Config.Size, human(b.lim.ConfigBytes))
		}
		p, err := b.ensureBlob(ctx, ref, doc.Config)
		if err != nil {
			return nil, fmt.Errorf("%s: config: %w", ref.Name(), err)
		}
		cfg, err := readVerified(p, doc.Config.Digest, b.lim.ConfigBytes)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(cfg, &res.config); err != nil {
			return nil, fmt.Errorf("%s: image config is not valid JSON: %v", ref.Name(), err)
		}
		c := res.config
		if c.OS != "linux" || c.Architecture != arch {
			return nil, fmt.Errorf("%s is a %s/%s image, but this box needs linux/%s; pick an image (or tag) built for linux/%s", ref.Name(), c.OS, c.Architecture, arch, arch)
		}
		if len(c.RootFS.DiffIDs) != len(doc.Layers) {
			return nil, fmt.Errorf("%s: config lists %d layer diff_ids for %d layers; the image is malformed", ref.Name(), len(c.RootFS.DiffIDs), len(doc.Layers))
		}
		for _, d := range c.RootFS.DiffIDs {
			if err := checkDigest(d); err != nil {
				return nil, fmt.Errorf("%s: config diff_id: %v", ref.Name(), err)
			}
		}
		return res, nil
	}
}

func parseManifest(ref reference, body []byte, headerType string) (manifestDoc, bool, error) {
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return doc, false, fmt.Errorf("%s: manifest is not valid JSON: %v", ref.Name(), err)
	}
	mt := doc.MediaType
	if mt == "" {
		mt = headerType
	}
	if doc.SchemaVersion == 1 || mt == mtSchema1 || mt == mtSchema1Signed {
		return doc, false, fmt.Errorf("%s uses the Docker schema 1 manifest format, which Box does not support; re-push it with a current Docker or BuildKit (schema 2 or OCI)", ref.Name())
	}
	if doc.SchemaVersion != 2 {
		return doc, false, fmt.Errorf("%s: manifest schemaVersion %d is not supported (want 2)", ref.Name(), doc.SchemaVersion)
	}
	var isIndex bool
	switch mt {
	case mtOCIIndex, mtDockerList:
		isIndex = true
	case mtOCIManifest, mtDockerManifest:
	default:
		// OCI lets mediaType be absent; then the shape decides.
		switch {
		case len(doc.Manifests) > 0 && doc.Config.Digest == "" && len(doc.Layers) == 0:
			isIndex = true
		case doc.Config.Digest != "" && len(doc.Manifests) == 0:
		default:
			return doc, false, fmt.Errorf("%s: manifest media type %q is not supported (Box reads OCI and Docker schema 2 manifests and indexes)", ref.Name(), mt)
		}
	}
	if isIndex && (len(doc.Layers) > 0 || doc.Config.Digest != "") || !isIndex && len(doc.Manifests) > 0 {
		return doc, false, fmt.Errorf("%s: manifest is both an index and an image; refusing", ref.Name())
	}
	return doc, isIndex, nil
}

func pickPlatform(ref reference, ms []descriptor, arch string, maxBytes int64) (descriptor, error) {
	var have []string
	for _, d := range ms {
		p := d.Platform
		if p == nil || p.OS == "unknown" {
			continue // attestation manifests
		}
		name := p.OS + "/" + p.Architecture
		if p.Variant != "" {
			name += "/" + p.Variant
		}
		have = append(have, name)
		if p.OS != "linux" || p.Architecture != arch {
			continue
		}
		if arch == "arm64" && p.Variant != "" && p.Variant != "v8" || arch == "amd64" && p.Variant != "" {
			continue
		}
		if err := checkDigest(d.Digest); err != nil {
			return d, fmt.Errorf("%s: index entry for %s: %v", ref.Name(), name, err)
		}
		if d.Size > maxBytes {
			return d, manifestTooBig(ref, maxBytes)
		}
		return d, nil
	}
	return descriptor{}, fmt.Errorf("%s has no linux/%s image (it has: %s); pick an image that publishes linux/%s", ref.Name(), arch, strings.Join(have, ", "), arch)
}

func (b *builder) checkLayers(res *resolved) error {
	name := res.ref.Name()
	ls := res.man.Layers
	if len(ls) > b.lim.Layers {
		return fmt.Errorf("%s has %d layers, over the limit of %d (Layers); squash the image", name, len(ls), b.lim.Layers)
	}
	var total int64
	for i, l := range ls {
		if err := checkDigest(l.Digest); err != nil {
			return fmt.Errorf("%s: layer %d: %v", name, i+1, err)
		}
		if l.Size < 0 || l.Size > b.lim.LayerBytes {
			return fmt.Errorf("%s: layer %d is %s, over the %s per-layer limit (LayerBytes); use a smaller image", name, i+1, human(l.Size), human(b.lim.LayerBytes))
		}
		total += l.Size
		comp, err := layerCompression(l.MediaType)
		if err != nil {
			return fmt.Errorf("%s: layer %d (%s): %v", name, i+1, short(l.Digest), err)
		}
		res.comp = append(res.comp, comp)
	}
	if total > b.lim.ImageBytes {
		return fmt.Errorf("%s downloads %s of layers, over the %s limit (ImageBytes); use a smaller image", name, human(total), human(b.lim.ImageBytes))
	}
	return nil
}

func layerCompression(mt string) (string, error) {
	switch mt {
	case "application/vnd.oci.image.layer.v1.tar", "application/vnd.docker.image.rootfs.diff.tar":
		return "", nil
	case "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.docker.image.rootfs.diff.tar.gzip":
		return "gzip", nil
	}
	switch {
	case strings.HasSuffix(mt, "+zstd"):
		return "", errors.New("zstd-compressed layers are not supported in v0; use an image pushed with gzip layers (docker buildx build --output type=registry,compression=gzip,force-compression=true)")
	case strings.Contains(mt, "foreign") || strings.Contains(mt, "nondistributable"):
		return "", fmt.Errorf("foreign (non-distributable) layer %q is not supported", mt)
	}
	return "", fmt.Errorf("layer media type %q is not supported (Box reads tar and tar+gzip layers)", mt)
}

// blobPath is where a verified blob (layer, config or manifest) lives in the cache.
func (b *builder) blobPath(digest string) string {
	return filepath.Join(b.dir("blobs/sha256"), strings.TrimPrefix(digest, "sha256:"))
}

// ensureBlob returns the cached blob for d, downloading and verifying it first if needed. Readers verify again.
func (b *builder) ensureBlob(ctx context.Context, ref reference, d descriptor) (string, error) {
	p := b.blobPath(d.Digest)
	if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() && fi.Size() == d.Size {
		return p, nil
	}
	f, err := os.CreateTemp(b.dir("tmp"), "blob-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	err = b.reg.fetchBlob(ctx, ref, d, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if err := os.Rename(f.Name(), p); err != nil {
		return "", err
	}
	return p, nil
}

// manifestByDigest returns a manifest by digest, from the cache when present.
func (b *builder) manifestByDigest(ctx context.Context, ref reference, digest string) ([]byte, error) {
	if body, err := readVerified(b.blobPath(digest), digest, b.lim.ManifestBytes); err == nil {
		return body, nil
	}
	body, _, _, err := b.reg.fetchManifest(ctx, ref, digest, b.lim.ManifestBytes)
	if err != nil {
		return nil, err
	}
	b.storeBlob(digest, body)
	return body, nil
}

// storeBlob caches small verified content (manifests) by digest; failures only cost a re-download.
func (b *builder) storeBlob(digest string, body []byte) {
	if checkDigest(digest) == nil {
		writeFileAtomic(b.blobPath(digest), body, 0o644)
	}
}

// readVerified reads a small cached blob and checks it still matches its digest; a corrupt file is removed.
func readVerified(p, digest string, max int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if int64(len(body)) > max || "sha256:"+hex.EncodeToString(sum[:]) != digest {
		os.Remove(p)
		return nil, fmt.Errorf("cached blob %s does not match its digest (removed it; run again)", short(digest))
	}
	return body, nil
}

// fetchLayers downloads every layer into the blob cache, a few at a time, and returns their paths in order.
func (b *builder) fetchLayers(ctx context.Context, res *resolved) ([]string, error) {
	ls := res.man.Layers
	paths := make([]string, len(ls))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, b.parallel)
	var (
		wg    sync.WaitGroup
		once  sync.Once
		first error
	)
	for i, d := range ls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			p, err := b.ensureBlob(ctx, res.ref, d)
			if err != nil {
				once.Do(func() { first = fmt.Errorf("%s: layer %d/%d: %w", res.ref.Name(), i+1, len(ls), err); cancel() })
				return
			}
			paths[i] = p
		}()
	}
	wg.Wait()
	if first != nil {
		return nil, first
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return paths, nil
}

// stage downloads and flattens the layers into dir and adds the guest. The returned stager holds every path's real
// owner and mode.
func (b *builder) stage(ctx context.Context, res *resolved, dir, guestPath string) (*stager, error) {
	paths, err := b.fetchLayers(ctx, res)
	if err != nil {
		return nil, err
	}
	st, err := newStager(dir, b.lim)
	if err != nil {
		return nil, err
	}
	for i, p := range paths {
		l := res.man.Layers[i]
		if err := st.applyLayer(ctx, p, l, res.comp[i], res.config.RootFS.DiffIDs[i]); err != nil {
			return nil, fmt.Errorf("%s: layer %d/%d (%s): %w", res.ref.Name(), i+1, len(paths), short(l.Digest), err)
		}
	}
	if err := st.addGuest(guestPath); err != nil {
		return nil, fmt.Errorf("%s: adding the guest: %w", res.ref.Name(), err)
	}
	if n := st.skipped["device"] + st.skipped["fifo"]; n > 0 {
		b.logf("tkbox: %s: skipped %d device nodes and fifos (the guest provides /dev)", res.ref.Name(), n)
	}
	return st, nil
}

// build makes the rootfs for key unless another process just did, under a cross-process lock.
func (b *builder) build(ctx context.Context, res *resolved, key, guestPath, arch string) (Rootfs, error) {
	unlock, err := lockFile(ctx, filepath.Join(b.dir("locks"), key+".lock"))
	if err != nil {
		return Rootfs{}, err
	}
	defer unlock()
	if r, ok := b.loadCached(key); ok {
		return r, nil
	}
	mkfs, debugfs, err := b.tools()
	if err != nil {
		return Rootfs{}, err
	}
	staging, err := os.MkdirTemp(b.dir("tmp"), "stage-")
	if err != nil {
		return Rootfs{}, err
	}
	defer os.RemoveAll(staging)
	st, err := b.stage(ctx, res, staging, guestPath)
	if err != nil {
		return Rootfs{}, err
	}
	tmp, err := os.CreateTemp(b.dir("rootfs"), "."+key+".tmp-")
	if err != nil {
		return Rootfs{}, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := makeExt4(ctx, mkfs, debugfs, st.root, st.meta, tmp.Name(), "tkbox-root"); err != nil {
		return Rootfs{}, fmt.Errorf("%s: %w", res.ref.Name(), err)
	}
	final := filepath.Join(b.dir("rootfs"), key+".ext4")
	if err := os.Chmod(tmp.Name(), 0o444); err != nil {
		return Rootfs{}, err
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		return Rootfs{}, err
	}
	fi, err := os.Stat(final)
	if err != nil {
		return Rootfs{}, err
	}
	c := res.config.Config
	r := Rootfs{Name: res.ref.Name(), Digest: res.digest, Arch: arch, Path: final, Size: fi.Size(),
		Config: Config{Env: c.Env, WorkingDir: c.WorkingDir, Entrypoint: c.Entrypoint, Cmd: c.Cmd, User: c.User}}
	side, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return Rootfs{}, err
	}
	if err := writeFileAtomic(filepath.Join(b.dir("rootfs"), key+".json"), side, 0o644); err != nil {
		return Rootfs{}, err
	}
	return r, nil
}

// loadCached returns the built rootfs for key: its sidecar is written last, so its presence means complete.
func (b *builder) loadCached(key string) (Rootfs, bool) {
	side, err := os.ReadFile(filepath.Join(b.dir("rootfs"), key+".json"))
	if err != nil {
		return Rootfs{}, false
	}
	var r Rootfs
	if json.Unmarshal(side, &r) != nil {
		return Rootfs{}, false
	}
	r.Path = filepath.Join(b.dir("rootfs"), key+".ext4")
	fi, err := os.Stat(r.Path)
	if err != nil || !fi.Mode().IsRegular() {
		return Rootfs{}, false
	}
	r.Size = fi.Size()
	return r, true
}

type indexEntry struct {
	Name    string    `json:"name"`
	Arch    string    `json:"arch"`
	Digest  string    `json:"digest"`
	Updated time.Time `json:"updated"`
}

func (b *builder) indexPath(ref reference, arch string) string {
	sum := sha256.Sum256([]byte(ref.Name() + "\n" + arch))
	return filepath.Join(b.dir("refs"), hex.EncodeToString(sum[:16])+".json")
}

func (b *builder) saveIndex(ref reference, arch, digest string) {
	data, _ := json.Marshal(indexEntry{Name: ref.Name(), Arch: arch, Digest: digest, Updated: time.Now().UTC()})
	writeFileAtomic(b.indexPath(ref, arch), data, 0o644)
}

// fromIndex returns the cached rootfs the ref last resolved to, if it is still built for this guest binary.
func (b *builder) fromIndex(ref reference, arch, guestSum string) (Rootfs, bool) {
	data, err := os.ReadFile(b.indexPath(ref, arch))
	if err != nil {
		return Rootfs{}, false
	}
	var e indexEntry
	if json.Unmarshal(data, &e) != nil || e.Name != ref.Name() || e.Arch != arch || checkDigest(e.Digest) != nil {
		return Rootfs{}, false
	}
	return b.loadCached(cacheKey(e.Digest, guestSum, arch))
}

// flight is one in-process build that every concurrent caller for the same key waits on. It runs on its own
// context, cancelled only when every waiter has gone.
type flight struct {
	done    chan struct{}
	res     Rootfs
	err     error
	waiters int
	cancel  context.CancelFunc
}

func (b *builder) once(ctx context.Context, key string, fn func(context.Context) (Rootfs, error)) (Rootfs, error) {
	b.mu.Lock()
	f := b.flights[key]
	if f == nil {
		fctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		f = &flight{done: make(chan struct{}), cancel: cancel}
		b.flights[key] = f
		go func() {
			res, err := fn(fctx)
			cancel()
			b.mu.Lock()
			f.res, f.err = res, err
			if b.flights[key] == f {
				delete(b.flights, key)
			}
			b.mu.Unlock()
			close(f.done)
		}()
	}
	f.waiters++
	b.mu.Unlock()
	select {
	case <-f.done:
		return f.res, f.err
	case <-ctx.Done():
		b.mu.Lock()
		if f.waiters--; f.waiters == 0 {
			f.cancel()
			if b.flights[key] == f {
				delete(b.flights, key) // the next caller starts afresh instead of joining a cancelled build
			}
		}
		b.mu.Unlock()
		return Rootfs{}, ctx.Err()
	}
}

// writeFileAtomic writes data to a temp file beside p and renames it into place.
func writeFileAtomic(p string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}
