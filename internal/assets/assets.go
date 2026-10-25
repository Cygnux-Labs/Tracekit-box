// Package assets pins the binaries a box needs that we do not build: the Firecracker VMM and the guest kernel, by URL
// and sha256 per architecture, and fetches them into a cache dir with verification.
package assets

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Asset is one pinned download.
type Asset struct {
	Name   string // "firecracker", "vmlinux"
	Arch   string // "arm64" or "amd64" (GOARCH names)
	URL    string
	SHA256 string // hex of the downloaded file
	// Member, for a .tgz download, is the path inside the archive to extract (the asset is that member, and SHA256 is
	// of the archive). Empty for a plain file.
	Member  string
	Version string
}

// Pins. Firecracker: the latest stable release with the sha256 from its .sha256.txt. Kernel: the Firecracker CI guest
// kernel 6.1 from the versioned CI prefix (dated prefixes are pruned; versioned ones are kept). Its config has
// OVERLAY_FS, VIRTIO_VSOCKETS, EXT4_FS, VIRTIO_BLK, VIRTIO_MMIO, DEVTMPFS_MOUNT and TMPFS built in (=y, no modules),
// which the guest relies on.
const (
	firecrackerVersion = "v1.17.0"
	firecrackerBase    = "https://github.com/firecracker-microvm/firecracker/releases/download/" + firecrackerVersion + "/"
	kernelVersion      = "6.1.155"
	kernelBase         = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/"
)

var firecrackerPins = map[string]Asset{
	"arm64": {
		Name: "firecracker", Arch: "arm64", Version: firecrackerVersion,
		URL:    firecrackerBase + "firecracker-" + firecrackerVersion + "-aarch64.tgz",
		SHA256: "e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256",
		Member: "release-" + firecrackerVersion + "-aarch64/firecracker-" + firecrackerVersion + "-aarch64",
	},
	"amd64": {
		Name: "firecracker", Arch: "amd64", Version: firecrackerVersion,
		URL:    firecrackerBase + "firecracker-" + firecrackerVersion + "-x86_64.tgz",
		SHA256: "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558",
		Member: "release-" + firecrackerVersion + "-x86_64/firecracker-" + firecrackerVersion + "-x86_64",
	},
}

var kernelPins = map[string]Asset{
	"arm64": {
		Name: "vmlinux", Arch: "arm64", Version: kernelVersion,
		URL:    kernelBase + "aarch64/vmlinux-" + kernelVersion,
		SHA256: "e3544b10603acbf3db492cb52e000d22ba202cb4b63b9add027565683e11c591",
	},
	"amd64": {
		Name: "vmlinux", Arch: "amd64", Version: kernelVersion,
		URL:    kernelBase + "x86_64/vmlinux-" + kernelVersion,
		SHA256: "e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2",
	},
}

// Kernel is the pinned guest kernel for arch.
func Kernel(arch string) (Asset, error) { return pinned(kernelPins, "guest kernel", arch) }

// Firecracker is the pinned Firecracker release binary for arch.
func Firecracker(arch string) (Asset, error) { return pinned(firecrackerPins, "Firecracker", arch) }

func pinned(pins map[string]Asset, what, arch string) (Asset, error) {
	a, ok := pins[arch]
	if !ok {
		return Asset{}, fmt.Errorf("assets: no pinned %s for arch %q: Box runs on arm64 and amd64 Linux hosts", what, arch)
	}
	return a, nil
}

// MaxDownloadBytes caps one download and one extracted member. The largest pin (the x86_64 kernel) is 43 MiB.
const MaxDownloadBytes = 256 << 20

// httpClient is replaced in tests. No overall timeout: a 44 MiB kernel on a slow runner can take minutes; ctx bounds
// the download and the transport bounds each phase.
var httpClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ForceAttemptHTTP2:     true,
	},
}

// One download per destination at a time in this process.
var locks sync.Map // dest path → *sync.Mutex

// Ensure returns the local path of a, downloading it into dir first if missing. The download is verified against
// a.SHA256 before it is moved into place (atomic rename); a mismatch is an error and leaves nothing behind.
func Ensure(ctx context.Context, dir string, a Asset) (string, error) {
	if err := validate(a); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, fmt.Sprintf("%s-%s-%s-%s", a.Name, a.Version, a.Arch, strings.ToLower(a.SHA256[:16])))
	mu, _ := locks.LoadOrStore(dest, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()

	// Only a verified download is ever renamed to dest, so an existing regular file is trusted.
	if fi, err := os.Lstat(dest); err == nil {
		if !fi.Mode().IsRegular() {
			return "", fmt.Errorf("assets: %s exists but is not a regular file: remove it and retry", dest)
		}
		return dest, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("assets: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("assets: create cache dir: %w", err)
	}

	tmp, err := download(ctx, dir, a)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp) // no-op once renamed

	src, mode := tmp, os.FileMode(0o644)
	if a.Name == "firecracker" {
		mode = 0o755
	}
	if a.Member != "" {
		member, exec, err := extract(dir, tmp, a)
		if err != nil {
			return "", err
		}
		defer os.Remove(member)
		src = member
		if exec {
			mode = 0o755
		}
	}
	if err := os.Chmod(src, mode); err != nil {
		return "", fmt.Errorf("assets: %w", err)
	}
	if err := os.Rename(src, dest); err != nil {
		return "", fmt.Errorf("assets: install %s: %w", dest, err)
	}
	syncDir(dir)
	return dest, nil
}

func validate(a Asset) error {
	if a.Name == "" || a.Arch == "" || a.Version == "" {
		return fmt.Errorf("assets: asset %q is missing a name, arch or version", a.URL)
	}
	for _, s := range []string{a.Name, a.Arch, a.Version} {
		if strings.ContainsAny(s, `/\`) || s == "." || s == ".." {
			return fmt.Errorf("assets: asset field %q is not a safe file name", s)
		}
	}
	if b, err := hex.DecodeString(a.SHA256); err != nil || len(b) != sha256.Size {
		return fmt.Errorf("assets: %s %s: SHA256 must be 64 hex characters", a.Name, a.Version)
	}
	if !strings.HasPrefix(a.URL, "https://") {
		return fmt.Errorf("assets: %s %s: only https URLs are fetched, got %q", a.Name, a.Version, a.URL)
	}
	return nil
}

// download fetches a.URL into a temp file in dir and verifies its sha256. On error nothing is left behind.
func download(ctx context.Context, dir string, a Asset) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return "", fmt.Errorf("assets: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("assets: download %s %s: %w: check the host's network access to %s", a.Name, a.Version, err, req.URL.Host)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("assets: download %s %s: %s from %s", a.Name, a.Version, resp.Status, a.URL)
	}
	if resp.ContentLength > MaxDownloadBytes {
		return "", fmt.Errorf("assets: download %s %s: %d bytes is over the %d byte cap", a.Name, a.Version, resp.ContentLength, MaxDownloadBytes)
	}
	f, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return "", fmt.Errorf("assets: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, MaxDownloadBytes+1))
	if err != nil {
		return "", fmt.Errorf("assets: download %s %s: %w", a.Name, a.Version, err)
	}
	if n > MaxDownloadBytes {
		return "", fmt.Errorf("assets: download %s %s: over the %d byte cap", a.Name, a.Version, MaxDownloadBytes)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(a.SHA256) {
		return "", fmt.Errorf("assets: %s %s (%s): sha256 mismatch: got %s, want %s: the download was corrupted or "+
			"tampered with and nothing was installed; retry, and report it if it persists", a.Name, a.Version, a.Arch, got, a.SHA256)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("assets: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("assets: %w", err)
	}
	ok = true
	return f.Name(), nil
}

// extract copies a.Member out of the verified .tgz at archive into a temp file in dir. Any entry with an absolute or
// escaping name fails the whole archive; the member must be a regular file and appear once.
func extract(dir, archive string, a Asset) (string, bool, error) {
	var tmp string
	exec, err := extractTo(dir, archive, a.Member, &tmp)
	if err != nil {
		if tmp != "" {
			os.Remove(tmp)
		}
		return "", false, fmt.Errorf("assets: %s %s: %w", a.Name, a.Version, err)
	}
	return tmp, exec, nil
}

func extractTo(dir, archive, member string, tmp *string) (bool, error) {
	in, err := os.Open(archive)
	if err != nil {
		return false, err
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return false, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	exec := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("bad archive: %w", err)
		}
		if path.IsAbs(hdr.Name) || strings.Contains(hdr.Name, `\`) || hasDotDot(hdr.Name) {
			return false, fmt.Errorf("archive entry %q escapes the archive; refusing it", hdr.Name)
		}
		if path.Clean(hdr.Name) != path.Clean(member) {
			continue
		}
		if *tmp != "" {
			return false, fmt.Errorf("archive has %q more than once", member)
		}
		if hdr.Typeflag != tar.TypeReg {
			return false, fmt.Errorf("archive member %q is not a regular file", member)
		}
		if hdr.Size > MaxDownloadBytes {
			return false, fmt.Errorf("archive member %q is %d bytes, over the %d byte cap", member, hdr.Size, MaxDownloadBytes)
		}
		f, err := os.CreateTemp(dir, ".extract-*")
		if err != nil {
			return false, err
		}
		*tmp = f.Name()
		_, err = io.Copy(f, io.LimitReader(tr, hdr.Size))
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return false, fmt.Errorf("extract %q: %w", member, err)
		}
		exec = hdr.Mode&0o111 != 0
	}
	if *tmp == "" {
		return false, fmt.Errorf("archive has no %q", member)
	}
	return exec, nil
}

func hasDotDot(name string) bool {
	for _, p := range strings.Split(name, "/") {
		if p == ".." {
			return true
		}
	}
	return false
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
