package guest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"sort"
	"strings"
	"syscall"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// Workspace diff: walk the overlay's upper layer against the base and write a git patch that `git apply --binary`
// accepts. Only paths the upper layer touches are visited, so the cost is proportional to what changed.

// textDiffMax is the largest file (either side) diffed as text; larger files go out as binary literals.
var textDiffMax int64 = 16 << 20

// binarySniff is how far git looks for a NUL byte to call a file binary.
const binarySniff = 8000

var (
	errTooLarge          = errors.New("patch too large")
	errChangedDuringDiff = errors.New("file changed during diff")
)

// git file modes
const (
	modeFile    uint32 = 0o100644
	modeExec    uint32 = 0o100755
	modeSymlink uint32 = 0o120000
	modeDir     uint32 = 0o040000
)

func gitMode(e *Entry) uint32 {
	switch {
	case e == nil:
		return 0
	case e.Kind == KindSymlink:
		return modeSymlink
	case e.Kind == KindDir:
		return modeDir
	case e.Perm&0o100 != 0:
		return modeExec
	}
	return modeFile
}

// change is one path in the patch. old/new are files or symlinks (nil: absent); oldDir/newDir mark a directory on
// that side, which the patch cannot carry but the summary reports as a type change.
type change struct {
	path           string
	old, new       *Entry
	oldDir, newDir bool
}

type differ struct {
	upper, base Tree
	exclude     map[string]bool // directory names left out wherever they are
	changes     []change
}

// Diff compares upper (an overlay upper layer) with base and returns the summary and the patch, at most max bytes.
// A directory named one of excludeDirs (a base name: "node_modules") is left out wherever it is, on either side:
// nothing below it is in the patch or counts toward max.
func Diff(upper, base Tree, max int64, excludeDirs ...string) (proto.DiffSummary, []byte, error) {
	d := &differ{upper: upper, base: base}
	if len(excludeDirs) > 0 {
		d.exclude = make(map[string]bool, len(excludeDirs))
		for _, n := range excludeDirs {
			d.exclude[n] = true
		}
	}
	root, err := upper.Stat("")
	if err != nil {
		return proto.DiffSummary{}, nil, err
	}
	if err := d.walk("", root.Opaque, true); err != nil {
		return proto.DiffSummary{}, nil, err
	}
	sort.Slice(d.changes, func(i, j int) bool { return d.changes[i].path < d.changes[j].path })
	out := &capBuffer{max: max}
	sum := proto.DiffSummary{Files: []proto.DiffFile{}}
	for i := range d.changes {
		df, skip, err := d.render(out, &d.changes[i])
		if err != nil {
			return proto.DiffSummary{}, nil, err
		}
		if !skip {
			sum.Files = append(sum.Files, df)
		}
	}
	sum.Bytes = int64(out.Len())
	return sum, out.Bytes(), nil
}

// isGitName reports a path component the patch must never carry (any case: case-insensitive filesystems on the
// host treat .GIT as .git).
func isGitName(name string) bool { return strings.EqualFold(name, ".git") }

// excluded reports a directory the caller asked to leave out: a directory named in exclude on either side.
func (d *differ) excluded(name string, sides ...*Entry) bool {
	if !d.exclude[name] {
		return false
	}
	for _, e := range sides {
		if e != nil && e.Kind == KindDir {
			return true
		}
	}
	return false
}

// walk visits upper directory rel. opaque: the lower layer is hidden below rel (an opaque or brand-new directory);
// baseDir: base has a directory at rel.
func (d *differ) walk(rel string, opaque, baseDir bool) error {
	entries, err := d.upper.ReadDir(rel)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(entries))
	for i := range entries {
		e := &entries[i]
		if isGitName(e.Name) {
			continue
		}
		seen[e.Name] = true
		p := joinRel(rel, e.Name)
		var b *Entry
		if baseDir {
			be, err := d.base.Stat(p)
			switch {
			case err == nil && be.Kind != KindOther && be.Kind != KindWhiteout:
				b = &be
			case err != nil && !isNotExist(err):
				return err
			}
		}
		if d.excluded(e.Name, e, b) {
			continue // seen: an opaque rel does not delete the base one either
		}
		switch e.Kind {
		case KindWhiteout, KindOther:
			// gone in the merged view (git cannot carry a fifo or device either)
			if b != nil {
				if err := d.removeAll(p, b); err != nil {
					return err
				}
			}
		case KindDir:
			switch {
			case b != nil && b.Kind == KindDir:
				if err := d.walk(p, opaque || e.Opaque, true); err != nil {
					return err
				}
			case b != nil:
				d.changes = append(d.changes, change{path: p, old: b, newDir: true})
				if err := d.walk(p, true, false); err != nil {
					return err
				}
			default:
				if err := d.walk(p, true, false); err != nil {
					return err
				}
			}
		case KindFile, KindSymlink:
			switch {
			case b != nil && b.Kind == KindDir:
				if err := d.removeAll(p, b); err != nil {
					return err
				}
				d.changes = append(d.changes, change{path: p, new: e, oldDir: true})
			default:
				d.changes = append(d.changes, change{path: p, old: b, new: e})
			}
		}
	}
	if opaque && baseDir {
		bents, err := d.base.ReadDir(rel)
		if err != nil {
			return err
		}
		for i := range bents {
			be := &bents[i]
			if seen[be.Name] || isGitName(be.Name) || d.excluded(be.Name, be) {
				continue
			}
			if err := d.removeAll(joinRel(rel, be.Name), be); err != nil {
				return err
			}
		}
	}
	return nil
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// removeAll records the deletion of base entry p and, for a directory, of everything below it.
func (d *differ) removeAll(p string, b *Entry) error {
	switch b.Kind {
	case KindFile, KindSymlink:
		d.changes = append(d.changes, change{path: p, old: b})
	case KindDir:
		ents, err := d.base.ReadDir(p)
		if err != nil {
			return err
		}
		for i := range ents {
			if isGitName(ents[i].Name) || d.excluded(ents[i].Name, &ents[i]) {
				continue
			}
			if err := d.removeAll(joinRel(p, ents[i].Name), &ents[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

// side is one version of a path's content.
type side struct {
	e    *Entry
	tree Tree
	path string
	data []byte // loaded content (symlink target, or a file up to textDiffMax)
	big  bool   // too large to load: streamed
	oid  string
	size int64
}

func (d *differ) load(t Tree, p string, e *Entry) (*side, error) {
	s := &side{e: e, tree: t, path: p}
	if e == nil {
		s.oid = zeroOID
		return s, nil
	}
	if e.Kind == KindSymlink {
		target, err := t.Readlink(p)
		if err != nil {
			return nil, err
		}
		s.data = []byte(target)
		s.size = int64(len(s.data))
		s.oid = blobID(s.data)
		return s, nil
	}
	r, err := t.Open(p)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if e.Size > textDiffMax {
		s.big = true
		h := blobHasher(e.Size)
		n, err := io.Copy(h, io.LimitReader(r, e.Size+1))
		if err != nil {
			return nil, err
		}
		if n != e.Size {
			return nil, fmt.Errorf("%w: %s", errChangedDuringDiff, p)
		}
		s.size = e.Size
		s.oid = hex.EncodeToString(h.Sum(nil))
		return s, nil
	}
	data, err := io.ReadAll(io.LimitReader(r, textDiffMax+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > textDiffMax {
		return nil, fmt.Errorf("%w: %s", errChangedDuringDiff, p)
	}
	s.data = data
	s.size = int64(len(data))
	s.oid = blobID(data)
	return s, nil
}

func (s *side) binary() bool {
	if s.e == nil {
		return false
	}
	if s.big {
		return true
	}
	return bytes.IndexByte(s.data[:min(len(s.data), binarySniff)], 0) >= 0
}

// render writes the patch section(s) for c; skip reports a path that turned out unchanged.
func (d *differ) render(w io.Writer, c *change) (df proto.DiffFile, skip bool, err error) {
	old, err := d.load(d.base, c.path, c.old)
	if err != nil {
		return df, false, err
	}
	nw, err := d.load(d.upper, c.path, c.new)
	if err != nil {
		return df, false, err
	}
	df = proto.DiffFile{Path: c.path, OldMode: gitMode(c.old), NewMode: gitMode(c.new)}
	if c.oldDir {
		df.OldMode = modeDir
	}
	if c.newDir {
		df.NewMode = modeDir
	}
	switch {
	case c.old != nil && c.new != nil && c.old.Kind != c.new.Kind:
		// file <-> symlink: git writes a deletion and a creation of the same path
		df.Status, df.Symlink = "type", c.new.Kind == KindSymlink
		bin1, err := d.writeDelete(w, old)
		if err != nil {
			return df, false, err
		}
		bin2, err := d.writeCreate(w, nw)
		df.Binary = bin1 || bin2
		return df, false, err
	case c.old == nil:
		df.Status, df.Symlink = "added", c.new.Kind == KindSymlink
		if c.oldDir {
			df.Status = "type"
		}
		df.Binary, err = d.writeCreate(w, nw)
		return df, false, err
	case c.new == nil:
		df.Status, df.Symlink = "deleted", c.old.Kind == KindSymlink
		if c.newDir {
			df.Status = "type"
		}
		df.Binary, err = d.writeDelete(w, old)
		return df, false, err
	}
	modeChanged := df.OldMode != df.NewMode
	same := old.oid == nw.oid
	if same && !modeChanged {
		return df, true, nil
	}
	df.Status, df.Symlink = "modified", c.new.Kind == KindSymlink
	if same {
		df.Status = "mode"
	}
	if _, err := fmt.Fprintf(w, "diff --git %s %s\n", quotePath("a/", c.path), quotePath("b/", c.path)); err != nil {
		return df, false, err
	}
	if modeChanged {
		if _, err := fmt.Fprintf(w, "old mode %o\nnew mode %o\n", df.OldMode, df.NewMode); err != nil {
			return df, false, err
		}
	}
	if same {
		return df, false, nil
	}
	idx := fmt.Sprintf("index %s..%s", old.oid, nw.oid)
	if !modeChanged {
		idx += fmt.Sprintf(" %o", df.NewMode)
	}
	if _, err := io.WriteString(w, idx+"\n"); err != nil {
		return df, false, err
	}
	if old.binary() || nw.binary() {
		df.Binary = true
		return df, false, d.writeLiteral(w, nw)
	}
	if err := writeFileHeaders(w, c.path, c.path); err != nil {
		return df, false, err
	}
	a, b := splitLines(old.data), splitLines(nw.data)
	return df, false, writeHunks(w, a, b, lineDiff(a, b))
}

func (d *differ) writeCreate(w io.Writer, s *side) (bool, error) {
	mode := gitMode(s.e)
	if _, err := fmt.Fprintf(w, "diff --git %s %s\nnew file mode %o\nindex %s..%s\n",
		quotePath("a/", s.path), quotePath("b/", s.path), mode, zeroOID, s.oid); err != nil {
		return false, err
	}
	if s.size == 0 {
		return false, nil
	}
	if s.binary() {
		return true, d.writeLiteral(w, s)
	}
	if err := writeFileHeaders(w, "", s.path); err != nil {
		return false, err
	}
	b := splitLines(s.data)
	es := make([]edit, len(b))
	for i := range b {
		es[i] = edit{opIns, 0, i}
	}
	return false, writeHunks(w, nil, b, es)
}

func (d *differ) writeDelete(w io.Writer, s *side) (bool, error) {
	mode := gitMode(s.e)
	if _, err := fmt.Fprintf(w, "diff --git %s %s\ndeleted file mode %o\nindex %s..%s\n",
		quotePath("a/", s.path), quotePath("b/", s.path), mode, s.oid, zeroOID); err != nil {
		return false, err
	}
	if s.size == 0 {
		return false, nil
	}
	if s.binary() {
		return true, writeBinaryLiteral(w, bytes.NewReader(nil), 0)
	}
	if err := writeFileHeaders(w, s.path, ""); err != nil {
		return false, err
	}
	a := splitLines(s.data)
	es := make([]edit, len(a))
	for i := range a {
		es[i] = edit{opDel, i, 0}
	}
	return false, writeHunks(w, a, nil, es)
}

// writeLiteral writes s's content as a binary literal, streaming files too large to hold.
func (d *differ) writeLiteral(w io.Writer, s *side) error {
	if !s.big {
		return writeBinaryLiteral(w, bytes.NewReader(s.data), s.size)
	}
	r, err := s.tree.Open(s.path)
	if err != nil {
		return err
	}
	defer r.Close()
	return writeBinaryLiteral(w, r, s.size)
}

// writeFileHeaders writes the ---/+++ lines; an empty name is /dev/null. Like git, a name with a space gets a
// trailing tab so patch(1) can find its end.
func writeFileHeaders(w io.Writer, oldPath, newPath string) error {
	name := func(prefix, p string) string {
		if p == "" {
			return "/dev/null"
		}
		s := quotePath(prefix, p)
		if strings.Contains(p, " ") {
			s += "\t"
		}
		return s
	}
	_, err := fmt.Fprintf(w, "--- %s\n+++ %s\n", name("a/", oldPath), name("b/", newPath))
	return err
}

// capBuffer is a bytes.Buffer that refuses to grow past max.
type capBuffer struct {
	bytes.Buffer
	max int64
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if int64(c.Len())+int64(len(p)) > c.max {
		return 0, errTooLarge
	}
	return c.Buffer.Write(p)
}

func (c *capBuffer) WriteString(s string) (int, error) { return c.Write([]byte(s)) }

func (s *Server) handleDiff(c net.Conn, f proto.Frame, st *state) {
	var req proto.DiffRequest
	if err := f.Decode(&req); err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	if st.ws == nil {
		sendError(c, proto.CodeNotFound, "this box has no workspace")
		return
	}
	if err := proto.CheckExcludeDirs(req.ExcludeDirs); err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	max := req.MaxBytes
	if max <= 0 {
		max = proto.DefaultMaxDiffBytes
	}
	sum, patch, err := Diff(st.ws.Upper, st.ws.Base, max, req.ExcludeDirs...)
	switch {
	case errors.Is(err, errTooLarge):
		sendError(c, proto.CodeTooLarge, fmt.Sprintf("the workspace patch is over max_bytes (%d bytes): "+
			"remove generated files (dependencies, build output, caches) from %s or raise the limit", max, st.ws.Path))
		return
	case err != nil:
		sendError(c, proto.CodeInternal, "diff: "+err.Error())
		return
	}
	if err := proto.WriteJSON(c, proto.TypeJSON, sum); err != nil {
		if errors.Is(err, proto.ErrFrameTooLarge) {
			sendError(c, proto.CodeTooLarge, fmt.Sprintf("%d changed files: the diff summary is over 1 MiB; "+
				"remove generated files (dependencies, build output, caches) from %s", len(sum.Files), st.ws.Path))
		}
		return
	}
	if _, err := (proto.ChunkWriter{W: c, Type: proto.TypeStdout}).Write(patch); err != nil {
		return
	}
	proto.WriteJSON(c, proto.TypeExit, proto.ExitStatus{})
}
