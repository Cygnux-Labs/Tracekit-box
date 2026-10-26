package image

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// review-1 docs-pass follow-up: the workspace builder's git in the host checkout gets the same isolation as apply's:
// no inherited GIT_* variables, no pager, no global or system config (global excludes passed back explicitly).
func TestWorkspaceGitIsIsolated(t *testing.T) {
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	run := func(args ...string) {
		c := exec.Command(realGit, append([]string{"-C", repo}, args...)...)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	os.MkdirAll(repo, 0o755)
	run("init", "-q")
	os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(repo, "secret.txt"), []byte("s"), 0o644)
	excl := filepath.Join(dir, "global-ignore")
	os.WriteFile(excl, []byte("secret.txt\n"), 0o644)
	home := filepath.Join(dir, "home")
	os.MkdirAll(home, 0o755)
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[core]\n\texcludesFile = "+excl+"\n"), 0o644)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GIT_DIR", filepath.Join(dir, "evil")) // an inherited GIT_* variable must not reach git
	t.Setenv("GIT_EXTERNAL_DIFF", "/bin/false")

	logf := filepath.Join(dir, "calls.log")
	shim := filepath.Join(dir, "git-shim")
	os.WriteFile(shim, []byte("#!/bin/sh\n{ printf 'ARGS'; printf ' %s' \"$@\"; echo; env | grep '^GIT_' | sed 's/^/ENV /'; } >> "+
		logf+"\nexec "+realGit+" \"$@\"\n"), 0o755)

	b := &builder{opts: Options{Git: shim}, lim: Limits{}.withDefaults()}
	names, err := b.listWorkspace(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "a.txt" {
		t.Fatalf("listed %q: the global excludes file must still keep secret.txt out", names)
	}
	logb, _ := os.ReadFile(logf)
	log := string(logb)
	var lsArgs string
	for _, l := range strings.Split(log, "\n") {
		if strings.HasPrefix(l, "ARGS") && strings.Contains(l, "ls-files") {
			lsArgs = l
		}
	}
	for _, want := range []string{" --no-pager", "core.pager=cat", "core.fsmonitor=false", "diff.external=", "core.hooksPath=/dev/null"} {
		if !strings.Contains(lsArgs, want) {
			t.Errorf("git ls-files ran without %q: %s", want, lsArgs)
		}
	}
	for _, bad := range []string{"ENV GIT_DIR=", "ENV GIT_EXTERNAL_DIFF="} {
		if strings.Contains(log, bad) {
			t.Errorf("an inherited %s reached git", strings.TrimPrefix(bad, "ENV "))
		}
	}
	if !strings.Contains(log, "ENV GIT_CONFIG_GLOBAL=/dev/null") || !strings.Contains(log, "ENV GIT_PAGER=cat") {
		t.Errorf("ls-files must run without global config and with no pager:\n%s", log)
	}
}
