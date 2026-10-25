package guest

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// Kind is what a tree entry is, as far as a git patch cares.
type Kind uint8

const (
	KindFile     Kind = iota + 1
	KindDir           //
	KindSymlink       //
	KindWhiteout      // an overlay whiteout: the lower entry of this name is deleted
	KindOther         // fifo, socket, device: git cannot carry it
)

// Entry is one entry of a Tree.
type Entry struct {
	Name   string
	Kind   Kind
	Perm   fs.FileMode // permission bits
	Size   int64
	Opaque bool // overlay opaque directory: nothing below it comes from the lower layer
}

// Tree is a read-only directory tree addressed by slash-separated relative paths ("" is the root). Nothing follows
// symlinks.
type Tree interface {
	Stat(rel string) (Entry, error) // fs.ErrNotExist when absent
	ReadDir(rel string) ([]Entry, error)
	Open(rel string) (io.ReadCloser, error)
	Readlink(rel string) (string, error)
}

// errOverlayFeature is returned for an upper layer that uses overlay features the diff cannot follow (redirect_dir,
// metacopy): the patch would silently miss content, so diff refuses instead.
var errOverlayFeature = errors.New("workspace overlay uses redirect_dir or metacopy; diff cannot read it")

// DirTree is a Tree over a directory. With Overlay set it reads an overlayfs upper layer: char devices 0:0 and files
// with an overlay.whiteout xattr are whiteouts, overlay.opaque="y" marks opaque directories, and redirect or metacopy
// xattrs are errOverlayFeature.
type DirTree struct {
	Root    string
	Overlay bool

	// tests set these to stand in for whiteout devices and xattrs, which need root and Linux
	isWhiteout func(rel string) bool
	isOpaque   func(rel string) bool
}

func (t *DirTree) abs(rel string) string { return filepath.Join(t.Root, filepath.FromSlash(rel)) }

func (t *DirTree) Stat(rel string) (Entry, error) {
	fi, err := os.Lstat(t.abs(rel))
	if err != nil {
		return Entry{}, err
	}
	return t.entry(rel, fi)
}

func (t *DirTree) ReadDir(rel string) ([]Entry, error) {
	des, err := os.ReadDir(t.abs(rel))
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(des))
	for _, de := range des {
		fi, err := de.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue // removed while listing
		}
		if err != nil {
			return nil, err
		}
		e, err := t.entry(joinRel(rel, de.Name()), fi)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (t *DirTree) Open(rel string) (io.ReadCloser, error) { return os.Open(t.abs(rel)) }

func (t *DirTree) Readlink(rel string) (string, error) { return os.Readlink(t.abs(rel)) }

func (t *DirTree) entry(rel string, fi fs.FileInfo) (Entry, error) {
	e := Entry{Name: fi.Name(), Perm: fi.Mode().Perm(), Size: fi.Size()}
	if rel == "" {
		e.Name = ""
	}
	m := fi.Mode()
	switch {
	case m.IsRegular():
		e.Kind = KindFile
	case m.IsDir():
		e.Kind = KindDir
	case m&fs.ModeSymlink != 0:
		e.Kind = KindSymlink
	default:
		e.Kind = KindOther
	}
	if !t.Overlay && t.isWhiteout == nil {
		return e, nil
	}
	if t.isWhiteout != nil {
		if t.isWhiteout(rel) {
			e.Kind = KindWhiteout
		}
		if e.Kind == KindDir && t.isOpaque != nil && t.isOpaque(rel) {
			e.Opaque = true
		}
		return e, nil
	}
	if e.Kind == KindOther && isWhiteoutDevice(fi) {
		e.Kind = KindWhiteout
		return e, nil
	}
	if e.Kind == KindFile || e.Kind == KindDir || e.Kind == KindSymlink {
		a, err := overlayXattrs(t.abs(rel))
		if err != nil {
			return Entry{}, err
		}
		switch {
		case a.redirect || a.metacopy:
			return Entry{}, errOverlayFeature
		case a.whiteout && e.Kind == KindFile && e.Size == 0:
			e.Kind = KindWhiteout
		case a.opaque && e.Kind == KindDir:
			e.Opaque = true
		}
	}
	return e, nil
}

// overlayAttrs are the overlay xattrs diff looks at on an upper-layer entry.
type overlayAttrs struct {
	opaque, whiteout, redirect, metacopy bool
}

func joinRel(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}
