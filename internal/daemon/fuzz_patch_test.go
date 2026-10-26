package daemon

import (
	"bytes"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"
	"testing"
)

// F1 (fuzz): /dev/null on a --- line without "new file mode", or on a +++ line without "deleted file mode", is a file
// named dev/null to git (a rename of x to it), not a creation or deletion: the parser itself refuses it, whatever the
// apply-time oracle says.
func TestFuzzF1DevNullNeedsItsModeLine(t *testing.T) {
	for _, p := range []string{
		"diff --git a/x b/x\nindex 1111111..0000000\n--- a/x\n+++ /dev/null\n@@ -1,2 +1,2 @@\n-a\n+agent-chosen content\n b\n",
		"diff --git a/x b/x\nindex 1111111..0000000\n--- a/x\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n",
		"diff --git a/x b/x\nindex 0000000..1111111\n--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+a\n",
		"diff --git a/x b/x\nnew mode 100755\n--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+a\n",
	} {
		if files, err := parsePatch(p); err == nil || !strings.Contains(err.Error(), "/dev/null without") {
			t.Errorf("parsed %q as %+v (err %v)", p, files, err)
		}
	}
	for _, p := range []string{
		"diff --git a/gone b/gone\ndeleted file mode 100644\nindex 1111111..0000000\n--- a/gone\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n",
		newFileSection("new.txt", "x"),
	} {
		if _, err := parsePatch(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
}

func patchSeeds(f *testing.F) {
	for _, p := range []string{
		modify("src/a.go"), modify("../x"), modify(".git/hooks/pre-commit"), modify(".git./config"),
		"diff --git a//etc/passwd b//etc/passwd\n--- a//etc/passwd\n+++ b//etc/passwd\n@@ -1 +1 @@\n-a\n+b\n",
		"diff --git \"a/sp ace\\tx\" \"b/sp ace\\tx\"\n--- \"a/sp ace\\tx\"\n+++ \"b/sp ace\\tx\"\n@@ -1 +1 @@\n-a\n+b\n",
		"diff --git \"a/\\056git/config\" \"b/\\056git/config\"\n--- \"a/\\056git/config\"\n+++ \"b/\\056git/config\"\n@@ -1 +1 @@\n-a\n+b\n",
		"diff --git a/ok.txt b/ok2.txt\nsimilarity index 100%\nrename from ok.txt\nrename to ../evil.txt\n",
		"diff --git a/ok.txt b/new.txt\nsimilarity index 100%\nrename from ok.txt\nrename to new.txt\n",
		"diff --git a/x b/y\nsimilarity index 100%\ncopy from .git/config\ncopy to y\n",
		"diff --git a/a b/a\n--- a/a\n+++ b/../../etc/x\n@@ -1 +1 @@\n-a\n+b\n",
		"diff --git a/d/l b/d/l\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/d/l\n@@ -0,0 +1 @@\n+../real/f\n\\ No newline at end of file\n",
		"diff --git a/inside b/inside\nindex 1111111..2222222 120000\n--- a/inside\n+++ b/inside\n@@ -1 +1 @@\n-real\n\\ No newline at end of file\n+/etc\n\\ No newline at end of file\n",
		"--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
		"diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n-a\ndiff --git a/../x b/../x\n",
		"diff --git a/gone b/gone\ndeleted file mode 100644\nindex 1111111..0000000\n--- a/gone\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n",
		"diff --git a/b.bin b/b.bin\nnew file mode 100644\nindex 0000000..1111111\nGIT binary patch\nliteral 3\nKcmZ?wWME_f\n\nliteral 0\nHcmV?d00001\n\n",
		"From abc Mon Sep 17 00:00:00 2001\nSubject: [PATCH] x\n\nbody text\n---\n a | 1 +\n" + modify("a") + "-- \n2.40.0\n",
		"diff --git a/.gitignore b/notes.txt\nindex 1111111..2222222 100644\n--- a/.gitignore\n+++ b/notes.txt\n@@ -1 +1 @@\n-build/\n+notes\n",
		"diff --git a/x b/x\nindex 1111111..0000000\n--- a/x\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n",
		"diff --git a/x b/x\nindex 1111111..0000000\n--- a/x\n+++ /dev/null\n@@ -1,2 +1,2 @@\n-a\n+agent-chosen content\n b\n",
		"diff --git a/m b/m\nold mode 100644\nnew mode 100755\n",
		"diff --git a/e b/e\nnew file mode 100644\nindex 0000000..e69de29\n",
		"diff --git a/a b c/a b\nnew file mode 100644\nindex 0000000..e69de29\n",
		"diff --git a/x\tb/x\nnew file mode 100644\nindex 0000000..e69de29\n",
		modify("a.txt") + modify("a.txt"),
	} {
		f.Add(p)
	}
}

// FuzzParsePatch: no panic; every path a section names is one of its Names; and once checkPatch finds no problem,
// every path it returns (what apply decides and writes) and every name is relative, clean and inside the root.
func FuzzParsePatch(f *testing.F) {
	patchSeeds(f)
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, patch string) {
		files, err := parsePatch(patch)
		summarize([]byte(patch))
		if err != nil {
			return
		}
		for _, pf := range files {
			if pf.Old != "" && !slices.Contains(pf.Names, pf.Old) || pf.New != "" && !slices.Contains(pf.Names, pf.New) {
				t.Fatalf("section old %q new %q not among its names %q", pf.Old, pf.New, pf.Names)
			}
			if !strings.Contains(patch, strings.TrimSuffix(pf.Raw, "\n")) {
				t.Fatalf("section text %q is not part of the patch", pf.Raw)
			}
		}
		out, problems := checkPatch(files, dir)
		if len(problems) > 0 {
			return
		}
		inside := func(p string) bool {
			return p != "" && !strings.HasPrefix(p, "/") && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../") &&
				!strings.ContainsRune(p, 0)
		}
		for _, pf := range files {
			for _, n := range pf.Names {
				if !inside(n) {
					t.Fatalf("accepted name %q", n)
				}
			}
		}
		for _, p := range out {
			if !inside(p) || checkRelPath(p) != nil {
				t.Fatalf("accepted target %q", p)
			}
		}
	})
}

// gitPaths lists every path `git apply --numstat -z --summary` (which only reads the patch) says the patch touches.
func gitPaths(t *testing.T, dir, patch string) ([]string, bool) {
	cmd := exec.Command("git", "apply", "--numstat", "-z", "--summary", "--binary", "-")
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "PATH=" + os.Getenv("PATH"),
		"GIT_CEILING_DIRECTORIES=" + path.Dir(dir), "LC_ALL=C"}
	cmd.Stdin = strings.NewReader(patch)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, false
	}
	var paths []string
	b := out.Bytes()
	for len(b) > 0 {
		// numstat: "A\tD\tpath\0" or, for a rename/copy, "A\tD\t\0old\0new\0"; summary lines end with '\n'
		if i := bytes.IndexByte(b, 0); i >= 0 && bytes.Count(b[:i], []byte("\t")) == 2 && !bytes.Contains(b[:i], []byte("\n")) {
			fields := bytes.SplitN(b[:i], []byte("\t"), 3)
			b = b[i+1:]
			if len(fields[2]) > 0 {
				paths = append(paths, string(fields[2]))
				continue
			}
			for k := 0; k < 2; k++ {
				j := bytes.IndexByte(b, 0)
				if j < 0 {
					t.Fatalf("short numstat rename: %q", out.String())
				}
				paths = append(paths, string(b[:j]))
				b = b[j+1:]
			}
			continue
		}
		// summary text: " create mode 100644 x\n", " rename a => b (100%)\n", ...; numstat already listed the paths
		j := bytes.IndexByte(b, '\n')
		if j < 0 {
			break
		}
		b = b[j+1:]
	}
	return paths, true
}

// FuzzParsePatchVsGit: when the parser accepts a patch (no problems), git's own reading of it (git apply --numstat,
// which applies nothing) names no path the parser did not return as a target.
func FuzzParsePatchVsGit(f *testing.F) {
	if _, err := exec.LookPath("git"); err != nil {
		f.Skip("git not installed")
	}
	patchSeeds(f)
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, patch string) {
		if len(patch) > 8<<10 {
			return
		}
		files, err := parsePatch(patch)
		if err != nil {
			return
		}
		out, problems := checkPatch(files, dir)
		if len(problems) > 0 {
			return
		}
		paths, ok := gitPaths(t, dir, patch)
		if !ok {
			return // git refuses the patch: nothing would be applied
		}
		for _, p := range paths {
			if !slices.Contains(out, p) {
				t.Fatalf("git reads the patch as touching %q; the parser's targets are %q (names %q)", p, out, patchNames(files))
			}
		}
	})
}

func patchNames(files []*patchFile) [][]string {
	var out [][]string
	for _, f := range files {
		out = append(out, f.Names)
	}
	return out
}
