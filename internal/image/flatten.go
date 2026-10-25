package image

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	maxSymlinkHops  = 40   // like the kernel's ELOOP limit
	maxResolveSteps = 4096 // path components visited resolving one name, symlink targets included
	maxNameLen      = 4096
	maxTrailer      = 1 << 20 // decompressed bytes allowed after a layer's end-of-archive marker
)

// entryMeta is the owner and mode a path really has in the image; the staging dir holds owner-writable copies and
// the ext4 gets these values from debugfs.
type entryMeta struct {
	uid, gid uint32
	mode     uint32 // permission bits plus setuid, setgid and sticky (07777)
}

// stager flattens layers into root, a private dir only we write to. Every name is resolved by us, chroot style:
// symlinks in parent components are followed within root (absolute targets are rooted at it, ".." stops at it),
// the final component is never followed, so nothing an image says can reach outside root.
type stager struct {
	root    string
	lim     Limits
	meta    map[string]entryMeta // by canonical path relative to root, e.g. "usr/bin/env"
	bytes   int64                // regular file bytes written, all layers
	entries int
	skipped map[string]int // "device", "fifo", "other"

	layer      map[string]bool // paths the current layer made: true = created afresh, false = merged into a lower dir
	layerBytes int64
	skippedAt  map[string]bool // paths of skipped special files (hard links to them are skipped too)
}

func newStager(root string, lim Limits) (*stager, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if root, err = filepath.EvalSymlinks(root); err != nil { // e.g. macOS /var → /private/var
		return nil, err
	}
	if err := os.Chmod(root, 0o755); err != nil {
		return nil, err
	}
	return &stager{root: root, lim: lim, meta: map[string]entryMeta{}, skipped: map[string]int{},
		layer: map[string]bool{}, skippedAt: map[string]bool{}}, nil
}

func relOf(comps []string) string { return strings.Join(comps, "/") }

func (s *stager) host(comps []string) string {
	if len(comps) == 0 {
		return s.root
	}
	return s.root + "/" + relOf(comps)
}

// splitName turns a tar member name into components: leading "/" and "./" are dropped, ".." is refused.
func splitName(name string) ([]string, error) {
	if len(name) > maxNameLen {
		return nil, fmt.Errorf("entry name is longer than %d bytes", maxNameLen)
	}
	var out []string
	for _, c := range strings.Split(name, "/") {
		switch c {
		case "", ".":
			continue
		case "..":
			return nil, fmt.Errorf("entry %q climbs out of the image root with \"..\"; refusing the image", name)
		}
		out = append(out, c)
	}
	return out, nil
}

// walk resolves comps starting at the real dir cur (components relative to root) and returns the real dir they
// name. Symlinks are followed within root; missing dirs are created when create is set, otherwise fs.ErrNotExist.
func (s *stager) walk(cur, comps []string, create bool, hops, steps *int) ([]string, error) {
	for _, c := range comps {
		if *steps++; *steps > maxResolveSteps {
			return nil, errors.New("path resolution takes too many steps; refusing the image")
		}
		switch c {
		case "", ".":
			continue
		case "..":
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
			continue
		}
		next := append(cur[:len(cur):len(cur)], c)
		h := s.host(next)
		fi, err := os.Lstat(h)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if !create {
				return nil, fs.ErrNotExist
			}
			if err := os.Mkdir(h, 0o755); err != nil {
				return nil, err
			}
			s.meta[relOf(next)] = entryMeta{mode: 0o755}
			s.layer[relOf(next)] = true
			cur = next
		case err != nil:
			return nil, err
		case fi.IsDir():
			cur = next
		case fi.Mode()&fs.ModeSymlink != 0:
			if *hops++; *hops > maxSymlinkHops {
				return nil, fmt.Errorf("too many levels of symbolic links at /%s", relOf(next))
			}
			target, err := os.Readlink(h)
			if err != nil {
				return nil, err
			}
			base := cur
			if strings.HasPrefix(target, "/") {
				base = nil
			}
			if cur, err = s.walk(base, strings.Split(target, "/"), create, hops, steps); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("/%s is not a directory", relOf(next))
		}
	}
	return cur, nil
}

// parent resolves all but the last component of name and returns the real parent dir and the final name.
func (s *stager) parent(comps []string, create bool) ([]string, string, error) {
	var hops, steps int
	dir, err := s.walk(nil, comps[:len(comps)-1], create, &hops, &steps)
	return dir, comps[len(comps)-1], err
}

// removeExisting deletes whatever is at h, never following a symlink.
func removeExisting(h string) error {
	fi, err := os.Lstat(h)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return os.RemoveAll(h)
	}
	return os.Remove(h)
}

func headerMeta(h *tar.Header) (entryMeta, error) {
	if h.Uid < 0 || h.Uid > math.MaxUint32 || h.Gid < 0 || h.Gid > math.MaxUint32 {
		return entryMeta{}, fmt.Errorf("%s: owner %d:%d is out of range", h.Name, h.Uid, h.Gid)
	}
	return entryMeta{uid: uint32(h.Uid), gid: uint32(h.Gid), mode: uint32(h.Mode) & 0o7777}, nil
}

// applyLayer extracts one layer blob, verifying the compressed bytes against digest and the tar against diffID.
func (s *stager) applyLayer(ctx context.Context, path string, d descriptor, comp, diffID string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	blobHash := sha256.New()
	raw := io.TeeReader(bufio.NewReaderSize(f, 1<<20), blobHash)
	var dec io.Reader = raw
	if comp == "gzip" {
		zr, err := gzip.NewReader(raw)
		if err != nil {
			return s.corrupt(path, d, fmt.Errorf("not gzip: %v", err))
		}
		defer zr.Close()
		dec = zr
	}
	diffHash := sha256.New()
	tarStream := io.TeeReader(&ctxReader{ctx: ctx, r: dec}, diffHash)
	tr := tar.NewReader(tarStream)
	s.layer = map[string]bool{}
	s.layerBytes = 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return s.corrupt(path, d, fmt.Errorf("reading tar: %v", err))
		}
		if s.entries++; s.entries > s.lim.ImageEntries {
			return fmt.Errorf("the image has more than %d files across its layers (ImageEntries); use a smaller image", s.lim.ImageEntries)
		}
		if err := s.apply(h, tr); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}
	if n, err := io.Copy(io.Discard, io.LimitReader(tarStream, maxTrailer+1)); err != nil {
		return s.corrupt(path, d, err)
	} else if n > maxTrailer {
		return fmt.Errorf("more than %s of data after the end of the tar; refusing the image", human(maxTrailer))
	}
	if _, err := io.Copy(io.Discard, raw); err != nil {
		return err
	}
	if got := "sha256:" + hex.EncodeToString(blobHash.Sum(nil)); got != d.Digest {
		return s.corrupt(path, d, fmt.Errorf("hashes to %s", got))
	}
	if got := "sha256:" + hex.EncodeToString(diffHash.Sum(nil)); diffID != "" && got != diffID {
		return fmt.Errorf("uncompressed layer hashes to %s but the image config says %s; refusing the image", got, diffID)
	}
	return nil
}

// corrupt reports a cached blob that no longer matches its digest and removes it so the next run downloads it again.
func (s *stager) corrupt(path string, d descriptor, err error) error {
	f, ferr := os.Open(path)
	if ferr == nil {
		h := sha256.New()
		io.Copy(h, f)
		f.Close()
		if "sha256:"+hex.EncodeToString(h.Sum(nil)) != d.Digest {
			os.Remove(path)
			return fmt.Errorf("cached layer does not match its digest (%v); removed it, run again", err)
		}
	}
	return fmt.Errorf("layer is not a valid tar: %v", err)
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// apply extracts one tar entry.
func (s *stager) apply(h *tar.Header, r io.Reader) error {
	if h.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}
	comps, err := splitName(h.Name)
	if err != nil {
		return err
	}
	if len(comps) == 0 {
		return nil // the root itself stays root-owned 0755
	}
	if base := comps[len(comps)-1]; strings.HasPrefix(base, ".wh.") {
		return s.whiteout(comps)
	}
	meta, err := headerMeta(h)
	if err != nil {
		return err
	}
	dir, base, err := s.parent(comps, true)
	if err != nil {
		return fmt.Errorf("%s: %w", h.Name, err)
	}
	target := append(dir, base)
	rel, hp := relOf(target), s.host(target)

	switch h.Typeflag {
	case tar.TypeDir:
		if fi, err := os.Lstat(hp); err == nil && fi.IsDir() {
			if _, ok := s.layer[rel]; !ok {
				s.layer[rel] = false
			}
		} else {
			if err := removeExisting(hp); err != nil {
				return err
			}
			if err := os.Mkdir(hp, 0o700|os.FileMode(meta.mode&0o777)); err != nil {
				return err
			}
			s.layer[rel] = true
		}
		s.meta[rel] = meta
		return nil

	case tar.TypeReg:
		if h.Size < 0 || s.layerBytes+h.Size > s.lim.LayerBytes {
			return fmt.Errorf("layer unpacks to more than %s (LayerBytes); use a smaller image", human(s.lim.LayerBytes))
		}
		if s.bytes+h.Size > s.lim.ImageBytes {
			return fmt.Errorf("image unpacks to more than %s (ImageBytes); use a smaller image", human(s.lim.ImageBytes))
		}
		if err := removeExisting(hp); err != nil {
			return err
		}
		f, err := os.OpenFile(hp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		n, err := io.Copy(f, r)
		s.layerBytes += n
		s.bytes += n
		if err == nil {
			err = f.Chmod(os.FileMode(meta.mode&0o777 | 0o600))
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("%s: %w", h.Name, err)
		}
		if !h.ModTime.IsZero() {
			os.Chtimes(hp, time.Time{}, h.ModTime) // .pyc freshness checks compare source mtimes
		}

	case tar.TypeSymlink:
		if len(h.Linkname) == 0 || len(h.Linkname) > 4095 {
			return fmt.Errorf("%s: symlink target length %d is out of range", h.Name, len(h.Linkname))
		}
		if err := removeExisting(hp); err != nil {
			return err
		}
		if err := os.Symlink(h.Linkname, hp); err != nil {
			return err
		}

	case tar.TypeLink:
		if err := s.hardlink(h, target); err != nil {
			return err
		}
		s.layer[rel] = true
		return nil

	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		if err := removeExisting(hp); err != nil {
			return err
		}
		kind := "device"
		if h.Typeflag == tar.TypeFifo {
			kind = "fifo"
		}
		s.skipped[kind]++
		s.skippedAt[rel] = true
		return nil

	default:
		s.skipped["other"]++
		return nil
	}
	s.meta[rel] = meta
	s.layer[rel] = true
	delete(s.skippedAt, rel)
	return nil
}

// hardlink links target to an earlier entry, which must resolve to a non-directory inside root.
func (s *stager) hardlink(h *tar.Header, target []string) error {
	lcomps, err := splitName(h.Linkname)
	if err != nil {
		return fmt.Errorf("hard link %s: %w", h.Name, err)
	}
	if len(lcomps) == 0 {
		return fmt.Errorf("hard link %s points at the image root; refusing the image", h.Name)
	}
	ldir, lbase, err := s.parent(lcomps, false)
	if err != nil {
		return fmt.Errorf("hard link %s -> %s: target is not in the image: %w", h.Name, h.Linkname, err)
	}
	src := append(ldir, lbase)
	srel, rel := relOf(src), relOf(target)
	if srel == rel {
		return nil
	}
	if s.skippedAt[srel] {
		s.skippedAt[rel] = true
		return removeExisting(s.host(target))
	}
	fi, err := os.Lstat(s.host(src))
	if err != nil {
		return fmt.Errorf("hard link %s -> %s: target is not in the image", h.Name, h.Linkname)
	}
	hp := s.host(target)
	switch {
	case fi.IsDir():
		return fmt.Errorf("hard link %s -> %s points at a directory; refusing the image", h.Name, h.Linkname)
	case fi.Mode()&fs.ModeSymlink != 0:
		// A hard link to a symlink is the same symlink; copying it keeps link(2) from ever following it.
		dest, err := os.Readlink(s.host(src))
		if err != nil {
			return err
		}
		if err := removeExisting(hp); err != nil {
			return err
		}
		if err := os.Symlink(dest, hp); err != nil {
			return err
		}
	case fi.Mode().IsRegular():
		if err := removeExisting(hp); err != nil {
			return err
		}
		if err := os.Link(s.host(src), hp); err != nil {
			return err
		}
	default:
		return fmt.Errorf("hard link %s -> %s: unexpected target type", h.Name, h.Linkname)
	}
	if m, ok := s.meta[srel]; ok {
		s.meta[rel] = m
	}
	delete(s.skippedAt, rel)
	return nil
}

// whiteout applies ".wh.<name>" (delete name) or ".wh..wh..opq" (hide everything lower layers put in the dir).
func (s *stager) whiteout(comps []string) error {
	dir, base, err := s.parent(comps, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // nothing below to hide
	}
	if err != nil {
		return err
	}
	switch {
	case base == ".wh..wh..opq":
		return s.clearLower(dir)
	case strings.HasPrefix(base, ".wh..wh."):
		return nil // other aufs metadata
	}
	name := strings.TrimPrefix(base, ".wh.")
	if name == "" {
		return fmt.Errorf("whiteout %q names nothing", relOf(comps))
	}
	return removeExisting(s.host(append(dir, name)))
}

// clearLower removes the children of dir that this layer did not create, descending into dirs it merged.
func (s *stager) clearLower(dir []string) error {
	ents, err := os.ReadDir(s.host(dir))
	if err != nil {
		return err
	}
	for _, e := range ents {
		c := append(dir[:len(dir):len(dir)], e.Name())
		fresh, ours := s.layer[relOf(c)]
		switch {
		case !ours:
			if err := removeExisting(s.host(c)); err != nil {
				return err
			}
		case !fresh && e.IsDir():
			if err := s.clearLower(c); err != nil {
				return err
			}
		}
	}
	return nil
}

// ensureDir makes name a directory, resolving within root (a symlink to a dir inside root is kept). It returns the
// real path it resolved to.
func (s *stager) ensureDir(name string, mode uint32) ([]string, error) {
	comps, _ := splitName(name)
	dir, base, err := s.parent(comps, true)
	if err != nil {
		return nil, err
	}
	p := append(dir, base)
	fi, err := os.Lstat(s.host(p))
	switch {
	case err == nil && fi.IsDir():
		return p, nil
	case err == nil && fi.Mode()&fs.ModeSymlink != 0:
		var hops, steps int
		if real, err := s.walk(dir, []string{base}, true, &hops, &steps); err == nil {
			return real, nil
		}
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	if err := removeExisting(s.host(p)); err != nil {
		return nil, err
	}
	if err := os.Mkdir(s.host(p), 0o755); err != nil {
		return nil, err
	}
	s.meta[relOf(p)] = entryMeta{mode: mode}
	return p, nil
}

// addGuest installs /sbin/tkbox-guest (root, 0755) and the dirs the guest mounts or needs.
func (s *stager) addGuest(guestPath string) error {
	for _, d := range []struct {
		name string
		mode uint32
	}{{"proc", 0o555}, {"sys", 0o555}, {"dev", 0o755}, {"run", 0o755}, {"tmp", 0o1777}, {"workspace", 0o755}, {"etc/tkbox", 0o755}} {
		p, err := s.ensureDir(d.name, d.mode)
		if err != nil {
			return fmt.Errorf("/%s: %w", d.name, err)
		}
		if d.name == "tmp" {
			m := s.meta[relOf(p)]
			m.mode = 0o1777
			s.meta[relOf(p)] = m
		}
	}
	dir, err := s.ensureDir("sbin", 0o755)
	if err != nil {
		return fmt.Errorf("/sbin: %w", err)
	}
	dst := append(dir, "tkbox-guest")
	if err := removeExisting(s.host(dst)); err != nil {
		return err
	}
	src, err := os.Open(guestPath)
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.OpenFile(s.host(dst), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, src)
	if err == nil {
		err = out.Chmod(0o755)
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	s.meta[relOf(dst)] = entryMeta{mode: 0o755}
	return err
}
