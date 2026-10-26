package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// otherOwnerGit puts a git first in PATH that makes every repository look owned by another user
// (GIT_TEST_ASSUME_DIFFERENT_OWNER, set after the daemon dropped every GIT_* variable): the daemon running as a
// dedicated user on the operator's checkout.
func otherOwnerGit(t *testing.T) {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nGIT_TEST_ASSUME_DIFFERENT_OWNER=1; export GIT_TEST_ASSUME_DIFFERENT_OWNER\nexec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// verify3b (A3b note): a patch with two sections for one path is refused outright (a symlink created and then
// retargeted by a second section would have that section judged against the checkout), not by a side effect later.
func TestVerify3bTwoSectionsForOnePathRefused(t *testing.T) {
	link := func(target string) string {
		return "diff --git a/l b/l\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+" + target + "\n\\ No newline at end of file\n"
	}
	retarget := "diff --git a/l b/l\n--- a/l\n+++ b/l\n@@ -1 +1 @@\n-inside\n\\ No newline at end of file\n+/etc/passwd\n\\ No newline at end of file\n"
	del := "diff --git a/a.txt b/a.txt\ndeleted file mode 100644\n--- a/a.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n"
	for name, p := range map[string]string{
		"symlink retargeted":  link("inside") + retarget,
		"modified twice":      modify("a.txt") + modify("a.txt"),
		"deleted then made":   del + newFileSection("a.txt", "x"),
		"created twice":       newFileSection("n.txt", "x") + newFileSection("n.txt", "y"),
		"renamed onto a path": modify("b.txt") + "diff --git a/c.txt b/b.txt\nsimilarity index 100%\nrename from c.txt\nrename to b.txt\n",
	} {
		files, err := parsePatch(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "a.txt"), []byte("old\n"), 0o644)
		if _, problems := checkPatch(files, dir); !slices.ContainsFunc(problems, func(s string) bool { return strings.Contains(s, "more than one section for") }) {
			t.Errorf("%s: problems %q", name, problems)
		}
	}
	files, _ := parsePatch(link("inside") + modify("a.txt"))
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("old\n"), 0o644)
	if _, problems := checkPatch(files, dir); len(problems) != 0 {
		t.Fatalf("one section per path: %q", problems)
	}

	// and through apply: refused before anything is decided
	e := newTestEnv(t, nil)
	ws, _ := filepath.EvalSymlinks(t.TempDir())
	gitInit(t, ws)
	e.guest.Patch = link("inside") + retarget
	e.create(api.CreateBoxRequest{Name: "two", Workspace: ws})
	e.d.Stop(context.Background(), "two", api.StopRequest{})
	_, err := e.d.Apply(context.Background(), "two", api.ApplyRequest{})
	if errCode(err) != api.CodeBadRequest || !strings.Contains(err.Error(), "more than one section") {
		t.Fatalf("apply: %v", err)
	}
	for _, r := range e.run(0).Records {
		if r.Call.Tool == tracekit.ToolWrite {
			t.Fatalf("a Write was decided: %+v", r)
		}
	}
}

// verify3b V3: the scratch git that builds and checks an apply reads no user git files: a hostile
// ~/.config/git/attributes (eol=crlf, ident) changes nothing written.
func TestVerify3bScratchGitReadsNoUserAttributes(t *testing.T) {
	needGit(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	for _, d := range []string{filepath.Join(home, ".config", "git")} {
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "attributes"), []byte("* text eol=crlf ident\n"), 0o644)
	}
	e := newTestEnv(t, nil)
	ws, _ := filepath.EvalSymlinks(t.TempDir())
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	e.guest.Patch = modify("a.txt") + newFileSection("b.txt", "$Id$ two")
	e.create(api.CreateBoxRequest{Name: "attr", Workspace: ws})
	e.d.Stop(context.Background(), "attr", api.StopRequest{})
	if _, err := e.d.Apply(context.Background(), "attr", api.ApplyRequest{}); err != nil {
		t.Fatal(err)
	}
	if a, b := readFile(t, filepath.Join(ws, "a.txt")), readFile(t, filepath.Join(ws, "b.txt")); a != "new\n" || b != "$Id$ two\n" {
		t.Fatalf("the user's git attributes changed what was written: a.txt %q, b.txt %q", a, b)
	}
}

// verify3b V1: a daemon that does not own the checkout works where the operator listed it in safe.directory (global
// config: read and passed back with -c, since the contained git reads no global config); where git refuses the
// checkout, apply fails closed rather than skip its git-dir and hooks-dir checks.
func TestVerify3bSafeDirectoryAndGitDirsFailClosed(t *testing.T) {
	needGit(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	ws, _ := filepath.EvalSymlinks(t.TempDir())
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	otherOwnerGit(t)
	if out, err := exec.Command("git", "-C", ws, "status").CombinedOutput(); err == nil || !strings.Contains(string(out), "dubious ownership") {
		t.Skipf("this git does not simulate another owner: %v %s", err, out)
	}
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[safe]\n\tdirectory = "+ws+"\n"), 0o644)

	e := newTestEnv(t, nil)
	e.guest.Patch = modify("a.txt")
	v := e.create(api.CreateBoxRequest{Name: "owned", Workspace: ws})
	if slices.Contains(v.Notices, ws+notGitNotice) {
		t.Fatalf("a checkout listed in safe.directory was taken for a non-git dir: %v", v.Notices)
	}
	e.d.Stop(context.Background(), "owned", api.StopRequest{})
	if res, err := e.d.Apply(context.Background(), "owned", api.ApplyRequest{}); err != nil || len(res.Applied) != 1 {
		t.Fatalf("apply with safe.directory: %+v %v", res, err)
	}
	if readFile(t, filepath.Join(ws, "a.txt")) != "new\n" {
		t.Fatal("not applied")
	}

	// without safe.directory git refuses the checkout: a patch into its hooks dir is refused, never written
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(""), 0o644)
	e.guest.Patch = newFileSection(".git-hooks/pre-commit", "evil")
	e.create(api.CreateBoxRequest{Name: "noworkspace"})
	e.d.Stop(context.Background(), "noworkspace", api.StopRequest{})
	n := len(e.run(1).Methods())
	_, err := e.d.Apply(context.Background(), "noworkspace", api.ApplyRequest{Dir: ws})
	if errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "git can't say where its git and hooks dirs are") {
		t.Fatalf("apply into a checkout git refuses: %v", err)
	}
	if _, serr := os.Lstat(filepath.Join(ws, ".git-hooks")); !os.IsNotExist(serr) {
		t.Fatal("written into a checkout whose hooks dir can't be told")
	}
	for _, r := range e.run(1).Records[n:] {
		if r.Call.Tool == tracekit.ToolWrite {
			t.Fatalf("a Write was decided: %+v", r)
		}
	}
}
