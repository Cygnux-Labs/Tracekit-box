package guest

import (
	"bytes"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

// diffFixture builds a base tree, a simulated overlay upper layer (whiteouts and opaque dirs recorded in maps) and
// the merged tree the upper layer should produce, so a patch can be checked with the real git apply.
type diffFixture struct {
	t                 *testing.T
	base, upper, want string
	wh, opq           map[string]bool
}

func newDiffFixture(t *testing.T) *diffFixture {
	d := t.TempDir()
	f := &diffFixture{t: t, base: filepath.Join(d, "base"), upper: filepath.Join(d, "upper"), want: filepath.Join(d, "want"),
		wh: map[string]bool{}, opq: map[string]bool{}}
	for _, p := range []string{f.base, f.upper} {
		must(t, os.MkdirAll(p, 0o755))
	}
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, root, rel, content string, perm fs.FileMode) {
	t.Helper()
	p := filepath.Join(root, rel)
	must(t, os.MkdirAll(filepath.Dir(p), 0o755))
	os.RemoveAll(p)
	must(t, os.WriteFile(p, []byte(content), perm))
	must(t, os.Chmod(p, perm))
}

func writeLink(t *testing.T, root, rel, target string) {
	t.Helper()
	p := filepath.Join(root, rel)
	must(t, os.MkdirAll(filepath.Dir(p), 0o755))
	os.RemoveAll(p)
	must(t, os.Symlink(target, p))
}

func (f *diffFixture) baseFile(rel, content string, perm fs.FileMode) {
	writeFile(f.t, f.base, rel, content, perm)
}
func (f *diffFixture) baseLink(rel, target string) { writeLink(f.t, f.base, rel, target) }

// seal copies base to want; call it after the base is built and before upper operations.
func (f *diffFixture) seal() {
	must(f.t, copyTree(f.base, f.want))
}

func (f *diffFixture) write(rel, content string, perm fs.FileMode) {
	writeFile(f.t, f.upper, rel, content, perm)
	writeFile(f.t, f.want, rel, content, perm)
}

func (f *diffFixture) link(rel, target string) {
	writeLink(f.t, f.upper, rel, target)
	writeLink(f.t, f.want, rel, target)
}

// remove leaves a whiteout in upper.
func (f *diffFixture) remove(rel string) {
	writeFile(f.t, f.upper, rel, "", 0o644)
	f.wh[rel] = true
	must(f.t, os.RemoveAll(filepath.Join(f.want, rel)))
}

// opaque replaces a base directory with an empty opaque one.
func (f *diffFixture) opaque(rel string) {
	p := filepath.Join(f.upper, rel)
	os.RemoveAll(p)
	must(f.t, os.MkdirAll(p, 0o755))
	f.opq[rel] = true
	must(f.t, os.RemoveAll(filepath.Join(f.want, rel)))
	must(f.t, os.MkdirAll(filepath.Join(f.want, rel), 0o755))
}

// copyUp copies a base file into upper with perm (a chmod or a no-op rewrite).
func (f *diffFixture) copyUp(rel string, perm fs.FileMode) {
	b, err := os.ReadFile(filepath.Join(f.base, rel))
	must(f.t, err)
	f.write(rel, string(b), perm)
}

func (f *diffFixture) upperTree() *DirTree {
	return &DirTree{Root: f.upper,
		isWhiteout: func(rel string) bool { return f.wh[rel] },
		isOpaque:   func(rel string) bool { return f.opq[rel] }}
}

// check diffs, applies the patch with git to a copy of base and compares the result with want.
func (f *diffFixture) check() (string, map[string]string) {
	f.t.Helper()
	sum, patch, err := Diff(f.upperTree(), &DirTree{Root: f.base}, 64<<20)
	must(f.t, err)
	if sum.Bytes != int64(len(patch)) {
		f.t.Fatalf("summary bytes %d, patch %d", sum.Bytes, len(patch))
	}
	gitApply(f.t, f.base, f.want, patch)
	st := map[string]string{}
	for _, df := range sum.Files {
		st[df.Path] = df.Status
	}
	return string(patch), st
}

func gitApply(t *testing.T, base, want string, patch []byte) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	work := filepath.Join(t.TempDir(), "work")
	must(t, copyTree(base, work))
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = work
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s\npatch:\n%s", args, err, out, patch)
		}
	}
	run("init", "-q")
	pf := filepath.Join(t.TempDir(), "p.patch")
	must(t, os.WriteFile(pf, patch, 0o644))
	run("apply", "--binary", "--whitespace=nowarn", pf)
	got, exp := snapshot(t, work), snapshot(t, want)
	if !mapsEqual(got, exp) {
		var diffs []string
		for k, v := range exp {
			if got[k] != v {
				diffs = append(diffs, fmt.Sprintf("%q: want %.60q got %.60q", k, v, got[k]))
			}
		}
		for k, v := range got {
			if _, ok := exp[k]; !ok {
				diffs = append(diffs, fmt.Sprintf("%q: unexpected %.60q", k, v))
			}
		}
		sort.Strings(diffs)
		t.Fatalf("applied tree differs:\n%s\npatch:\n%s", strings.Join(diffs, "\n"), patch)
	}
}

// snapshot maps every file and symlink (never directories, never .git) to its kind, exec bit and content.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	must(t, filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() && isGitName(de.Name()) {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(root, p)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			tgt, _ := os.Readlink(p)
			out[rel] = "link:" + tgt
		case fi.Mode().IsRegular():
			b, _ := os.ReadFile(p)
			out[rel] = fmt.Sprintf("file:%v:%s", fi.Mode()&0o100 != 0, b)
		}
		return nil
	}))
	return out
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// copyTree copies files, symlinks and modes (cp -a without owners).
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case fi.IsDir():
			return os.MkdirAll(target, fi.Mode().Perm()|0o700)
		case fi.Mode()&fs.ModeSymlink != 0:
			tgt, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(tgt, target)
		case fi.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.WriteFile(target, b, fi.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(target, fi.Mode().Perm())
		}
		return nil
	})
}

func lines(n int, f func(i int) string) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		b.WriteString(f(i))
		b.WriteByte('\n')
	}
	return b.String()
}

func randBytes(seed int64, n int) string {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return string(b)
}

func TestDiffApplies(t *testing.T) {
	f := newDiffFixture(t)
	readme := lines(40, func(i int) string { return fmt.Sprintf("line %d", i) })
	f.baseFile("README.md", readme, 0o644)
	f.baseFile("src/main.go", "package main\n", 0o644)
	f.baseFile("del.txt", "bye\n", 0o644)
	f.baseFile("empty.txt", "", 0o644)
	f.baseFile("noeol.txt", "a\nb\nc", 0o644)
	f.baseFile("eol-add.txt", "x", 0o644)
	f.baseFile("eol-del.txt", "x\n", 0o644)
	f.baseFile("run.sh", "#!/bin/sh\necho hi\n", 0o644)
	f.baseFile("tool.sh", "#!/bin/sh\necho v1\n", 0o755)
	f.baseLink("link", "README.md")
	f.baseLink("link-del", "src")
	f.baseFile("f2l", "file then link\n", 0o644)
	f.baseLink("l2f", "README.md")
	f.baseFile("f2d", "file then dir\n", 0o644)
	f.baseFile("d2f/a.txt", "a\n", 0o644)
	f.baseFile("d2f/b/c.txt", "c\n", 0o644)
	f.baseFile("gone/x.txt", "x\n", 0o644)
	f.baseFile("gone/deep/y.txt", "y\n", 0o644)
	f.baseLink("gone/l", "x.txt")
	f.baseFile("opq/keep.txt", "keep\n", 0o644)
	f.baseFile("opq/change.txt", "before\n", 0o644)
	f.baseFile("opq/drop.txt", "drop\n", 0o644)
	f.baseFile("opq/sub/x.txt", "x\n", 0o644)
	f.baseFile("bin/blob.bin", "\x00\x01\x02binary\x00"+randBytes(1, 3000), 0o644)
	f.baseFile("bin/old.bin", "\x00old", 0o644)
	f.baseFile("bin/text2bin", "text\n", 0o644)
	f.baseFile("base sp.txt", "one\ntwo\n", 0o644)
	f.baseFile("crlf.txt", "a\r\nb\r\nc\r\n", 0o644)
	f.baseFile("touched.txt", "same\n", 0o644)
	f.seal()

	f.write("README.md", strings.Replace(strings.Replace(readme, "line 5\n", "line five\n", 1), "line 30\n", "line 30\nline 30.5\n", 1), 0o644)
	f.copyUp("src/main.go", 0o644) // copied up, unchanged
	f.remove("del.txt")
	f.remove("empty.txt")
	f.write("noeol.txt", "a\nB\nc", 0o644)
	f.write("eol-add.txt", "x\n", 0o644)
	f.write("eol-del.txt", "x", 0o644)
	f.copyUp("run.sh", 0o755)
	f.write("tool.sh", "#!/bin/sh\necho v2\n", 0o644)
	f.link("link", "src/main.go")
	f.remove("link-del")
	f.link("f2l", "README.md")
	f.write("l2f", "now a file\n", 0o644)
	must(t, os.Remove(filepath.Join(f.want, "f2d")))
	f.write("f2d/inner.txt", "inner\n", 0o644)
	must(t, os.RemoveAll(filepath.Join(f.want, "d2f")))
	f.write("d2f", "dir then file\n", 0o644)
	f.remove("gone")
	f.opaque("opq")
	f.write("opq/keep.txt", "keep\n", 0o644)
	f.write("opq/change.txt", "after\n", 0o644)
	f.write("opq/new.txt", "new\n", 0o644)
	f.write("bin/blob.bin", "\x00\x01\x02BINARY\x00"+randBytes(2, 3000), 0o644)
	f.remove("bin/old.bin")
	f.write("bin/text2bin", "now\x00binary", 0o644)
	f.write("bin/new.bin", randBytes(3, 10000), 0o755)
	f.write("bin/zeros.bin", strings.Repeat("\x00", 200000), 0o644)
	f.write("added.txt", "hello\nworld\n", 0o644)
	f.write("added-empty", "", 0o644)
	f.write("new/dir/deep.txt", "deep\n", 0o644)
	f.link("newlink", "new/dir")
	f.write("base sp.txt", "one\n2\n", 0o644)
	f.write("crlf.txt", "a\r\nB\r\nc\r\n", 0o644)
	f.copyUp("touched.txt", 0o644)
	for _, name := range []string{"sp ace.txt", "tab\there.txt", "quo\"te.txt", "back\\slash.txt", "ünï.txt", "new\nline.txt", "dir with space/f"} {
		f.write(name, "odd name "+name+"\n", 0o644)
	}
	// never in a patch: .git anywhere, fifos
	writeFile(t, f.upper, ".git/config", "[core]\n", 0o644)
	writeFile(t, f.upper, "src/.GIT/HEAD", "ref\n", 0o644)
	must(t, syscall.Mkfifo(filepath.Join(f.upper, "fifo"), 0o644))

	patch, st := f.check()
	want := map[string]string{
		"README.md": "modified", "del.txt": "deleted", "empty.txt": "deleted", "noeol.txt": "modified",
		"run.sh": "mode", "tool.sh": "modified", "link": "modified", "link-del": "deleted", "f2l": "type",
		"l2f": "type", "f2d": "type", "f2d/inner.txt": "added", "d2f": "type", "d2f/a.txt": "deleted",
		"d2f/b/c.txt": "deleted", "gone/x.txt": "deleted", "gone/deep/y.txt": "deleted", "gone/l": "deleted",
		"opq/change.txt": "modified", "opq/drop.txt": "deleted", "opq/sub/x.txt": "deleted", "opq/new.txt": "added",
		"bin/blob.bin": "modified", "bin/old.bin": "deleted", "added-empty": "added", "newlink": "added",
	}
	for p, s := range want {
		if st[p] != s {
			t.Errorf("%s: status %q, want %q", p, st[p], s)
		}
	}
	for _, p := range []string{"src/main.go", "touched.txt", "opq/keep.txt", "fifo", ".git/config", "src/.GIT/HEAD"} {
		if _, ok := st[p]; ok {
			t.Errorf("%s should not be in the summary", p)
		}
	}
	for _, s := range []string{".git/", ".GIT/", "fifo"} {
		if strings.Contains(patch, s) {
			t.Errorf("patch mentions %q", s)
		}
	}
	for _, s := range []string{"@@ -2,7 +2,7 @@", "@@ -28,6 +28,7 @@", "\\ No newline at end of file", "GIT binary patch",
		`"b/tab\there.txt"`, `"b/\303\274n\303\257.txt"`, "+++ b/sp ace.txt\t", "old mode 100644\nnew mode 100755"} {
		if !strings.Contains(patch, s) {
			t.Errorf("patch lacks %q", s)
		}
	}
}

func TestDiffDeterministic(t *testing.T) {
	f := newDiffFixture(t)
	f.baseFile("a", "1\n", 0o644)
	f.seal()
	for i := 0; i < 50; i++ {
		f.write(fmt.Sprintf("d%d/f%d", i%7, i), fmt.Sprint(i), 0o644)
	}
	_, p1, err := Diff(f.upperTree(), &DirTree{Root: f.base}, 1<<20)
	must(t, err)
	_, p2, err := Diff(f.upperTree(), &DirTree{Root: f.base}, 1<<20)
	must(t, err)
	if !bytes.Equal(p1, p2) {
		t.Fatal("diff output is not deterministic")
	}
	f.check()
}

func TestDiffFallbacks(t *testing.T) {
	defer func(d int, m int64) { myersMaxD, textDiffMax = d, m }(myersMaxD, textDiffMax)
	myersMaxD, textDiffMax = 4, 4096
	f := newDiffFixture(t)
	f.baseFile("many.txt", lines(200, func(i int) string { return fmt.Sprint("l", i) }), 0o644)
	f.baseFile("big.txt", lines(1000, func(i int) string { return "big" }), 0o644)
	f.seal()
	f.write("many.txt", lines(200, func(i int) string {
		if i%10 == 0 {
			return fmt.Sprint("changed", i)
		}
		return fmt.Sprint("l", i)
	}), 0o644)
	f.write("big.txt", lines(1100, func(i int) string { return "big" }), 0o644)
	patch, st := f.check()
	if st["many.txt"] != "modified" || !strings.Contains(patch, "@@ -7,194 +7,194 @@") {
		t.Errorf("many.txt: want one replacement hunk, got status %q", st["many.txt"])
	}
	if !strings.Contains(patch, "GIT binary patch\nliteral 4400") {
		t.Error("big.txt should go out as a binary literal")
	}
}

func TestDiffTooLarge(t *testing.T) {
	f := newDiffFixture(t)
	f.seal()
	f.write("x.bin", randBytes(9, 50000), 0o644)
	if _, _, err := Diff(f.upperTree(), &DirTree{Root: f.base}, 10000); err != errTooLarge {
		t.Fatalf("want errTooLarge, got %v", err)
	}
}

func TestDiffEmpty(t *testing.T) {
	f := newDiffFixture(t)
	f.baseFile("a", "a\n", 0o644)
	f.seal()
	sum, patch, err := Diff(f.upperTree(), &DirTree{Root: f.base}, 1<<20)
	must(t, err)
	if len(patch) != 0 || len(sum.Files) != 0 || sum.Files == nil {
		t.Fatalf("empty diff: %+v %q", sum, patch)
	}
}

// TestLineDiffMinimal checks the script rebuilds the new text and is as short as an LCS says it can be.
func TestLineDiffMinimal(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for iter := 0; iter < 300; iter++ {
		gen := func() [][]byte {
			n := r.Intn(30)
			out := make([][]byte, n)
			for i := range out {
				out[i] = []byte(string(rune('a'+r.Intn(4))) + "\n")
			}
			return out
		}
		a, b := gen(), gen()
		es := lineDiff(a, b)
		var rebuilt [][]byte
		edits := 0
		ai := 0
		for _, e := range es {
			switch e.op {
			case opEq:
				if !bytes.Equal(a[e.a], b[e.b]) || e.a != ai {
					t.Fatalf("bad eq edit %+v", e)
				}
				rebuilt = append(rebuilt, a[e.a])
				ai++
			case opDel:
				if e.a != ai {
					t.Fatalf("bad del edit %+v", e)
				}
				ai++
				edits++
			case opIns:
				rebuilt = append(rebuilt, b[e.b])
				edits++
			}
		}
		if ai != len(a) || !bytes.Equal(bytes.Join(rebuilt, nil), bytes.Join(b, nil)) {
			t.Fatalf("script does not rebuild b")
		}
		if want := len(a) + len(b) - 2*lcs(a, b); edits != want {
			t.Fatalf("edits %d, minimal %d", edits, want)
		}
	}
}

func lcs(a, b [][]byte) int {
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if bytes.Equal(a[i], b[j]) {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	return dp[0][0]
}

// TestDiffExcludeDirs: excluded directory names are left out wherever they are (new, changed, deleted, below an
// opaque dir, nested), do not count toward max, and the patch still applies; a file with such a name is kept.
func TestDiffExcludeDirs(t *testing.T) {
	f := newDiffFixture(t)
	f.baseFile("app.js", "v1\n", 0o644)
	f.baseFile("node_modules/left/index.js", "left\n", 0o644)
	f.baseFile("pkg/__pycache__/old.pyc", "\x00old", 0o644)
	f.baseFile("pkg/mod.py", "x = 1\n", 0o644)
	f.baseFile("lib/a.txt", "a\n", 0o644)
	f.baseFile("lib/node_modules/z.js", "z\n", 0o644)
	f.seal()

	f.write("app.js", "v2\n", 0o644)
	f.write("src/m.py", "print(1)\n", 0o644)
	f.write("notes/__pycache__", "a file, not a dir\n", 0o644)
	f.write("node_modules.txt", "kept\n", 0o644)
	// excluded: written to upper only, so want keeps the base's version
	writeFile(t, f.upper, "node_modules/left/index.js", "changed\n", 0o644)
	writeFile(t, f.upper, "node_modules/big/blob.bin", randBytes(3, 300000), 0o644)
	writeFile(t, f.upper, "sub/deep/node_modules/x/y.js", "y\n", 0o644)
	writeFile(t, f.upper, "src/__pycache__/m.cpython-312.pyc", "\x00pyc", 0o644)
	writeFile(t, f.upper, "pkg/__pycache__", "", 0o644) // whiteout of the base dir
	f.wh["pkg/__pycache__"] = true
	f.opaque("lib") // drops lib/a.txt, but not the excluded lib/node_modules
	must(t, copyTree(filepath.Join(f.base, "lib/node_modules"), filepath.Join(f.want, "lib/node_modules")))

	if _, _, err := Diff(f.upperTree(), &DirTree{Root: f.base}, 64<<10); err != errTooLarge {
		t.Fatalf("without exclusions the 300 KB blob should be over 64 KiB, got %v", err)
	}
	sum, patch, err := Diff(f.upperTree(), &DirTree{Root: f.base}, 64<<10, "node_modules", "__pycache__")
	must(t, err)
	gitApply(t, f.base, f.want, patch)
	var paths []string
	for _, df := range sum.Files {
		paths = append(paths, df.Path)
	}
	sort.Strings(paths)
	want := []string{"app.js", "lib/a.txt", "node_modules.txt", "notes/__pycache__", "src/m.py"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("files %v, want %v\n%s", paths, want, patch)
	}
}

func TestQuotePath(t *testing.T) {
	for in, want := range map[string]string{
		"plain/x.go": "a/plain/x.go",
		"sp ace":     "a/sp ace",
		"t\tb":       `"a/t\tb"`,
		"q\"":        `"a/q\""`,
		"é":          `"a/\303\251"`,
		"\x01":       `"a/\001"`,
	} {
		if got := quotePath("a/", in); got != want {
			t.Errorf("quotePath(%q) = %s, want %s", in, got, want)
		}
	}
}
