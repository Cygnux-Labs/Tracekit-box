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
)

// gitCall is one git command the daemon ran, as the logging git shim saw it.
type gitCall struct {
	cwd  string
	args []string
	env  map[string]string
}

// gitShim puts a git first in PATH that logs each call (cwd, args, the env that steers config and paging) and then
// runs the real git. It returns a func that reads the calls logged since the last read.
func gitShim(t *testing.T) func() []gitCall {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\n{ printf 'CALL\\n'; printf 'cwd=%s\\n' \"$(pwd -P)\"; for a in \"$@\"; do printf 'arg=%s\\n' \"$a\"; done\n" +
		"  for v in GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM GIT_PAGER PAGER GIT_EXTERNAL_DIFF; do eval \"printf 'env=%s=%s\\n' $v \\\"\\${$v-unset}\\\"\"; done\n" +
		"} >> '" + log + "'\nexec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []gitCall {
		b, _ := os.ReadFile(log)
		os.Remove(log)
		var calls []gitCall
		for _, ln := range strings.Split(string(b), "\n") {
			k, v, _ := strings.Cut(ln, "=")
			switch {
			case ln == "CALL":
				calls = append(calls, gitCall{env: map[string]string{}})
			case k == "cwd":
				calls[len(calls)-1].cwd = v
			case k == "arg":
				calls[len(calls)-1].args = append(calls[len(calls)-1].args, v)
			case k == "env":
				ek, ev, _ := strings.Cut(v, "=")
				calls[len(calls)-1].env[ek] = ev
			}
		}
		return calls
	}
}

// inCheckout reports whether the call ran in (or with its work tree in) the checkout ws.
func (c gitCall) inCheckout(ws string) bool {
	if c.cwd == ws || strings.HasPrefix(c.cwd, ws+"/") {
		return true
	}
	return slices.Contains(c.args, "--work-tree="+ws)
}

// A1: no git command apply runs in the operator's checkout can run a program that checkout's config (or the
// user's global config) names: a hostile .git/config, an included file, .gitattributes filters and a global
// ~/.gitconfig all point at a script, and neither a checked nor a real apply runs it. Every git call in the checkout
// reads no global or system config, pages nothing and overrides every program setting; the global excludes file
// still counts.
func TestApplyLeadsCheckoutGitRunsNoProgram(t *testing.T) {
	calls := gitShim(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	markers := t.TempDir()
	evil := filepath.Join(markers, "evil.sh")
	os.WriteFile(evil, []byte("#!/bin/sh\ntouch \"$0.ran.$$\"\nexit 0\n"), 0o755)

	e := newTestEnv(t, nil)
	ws, _ := filepath.EvalSymlinks(t.TempDir())
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	os.WriteFile(filepath.Join(ws, ".gitattributes"), []byte("* filter=evil diff=evil\n"), 0o644)
	inc := filepath.Join(markers, "included.cfg")
	os.WriteFile(inc, []byte("[core]\n\tfsmonitor = "+evil+"\n\tpager = "+evil+"\n"), 0o644)
	f, err := os.OpenFile(filepath.Join(ws, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("[core]\n\tfsmonitor = " + evil + "\n\tpager = " + evil + "\n\tuntrackedCache = true\n" +
		"[include]\n\tpath = " + inc + "\n" +
		"[pager]\n\tcheck-ignore = " + evil + "\n\trev-parse = " + evil + "\n\tconfig = " + evil + "\n\tapply = " + evil + "\n" +
		"[diff]\n\texternal = " + evil + "\n[diff \"evil\"]\n\ttextconv = " + evil + "\n\tcommand = " + evil + "\n" +
		"[alias]\n\tcheck-ignore = !" + evil + "\n\tst = !" + evil + "\n" +
		"[filter \"evil\"]\n\tprocess = " + evil + "\n\tclean = " + evil + "\n\tsmudge = " + evil + "\n\trequired = true\n")
	f.Close()
	os.WriteFile(filepath.Join(home, "global-ignore"), []byte("ignored-by-global.txt\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[core]\n\tfsmonitor = "+evil+"\n\tpager = "+evil+
		"\n\texcludesFile = "+filepath.Join(home, "global-ignore")+"\n[pager]\n\tcheck-ignore = "+evil+"\n"), 0o644)

	e.guest.Patch = modify("a.txt") +
		"diff --git a/ignored-by-global.txt b/ignored-by-global.txt\nnew file mode 100644\n--- /dev/null\n+++ b/ignored-by-global.txt\n@@ -0,0 +1 @@\n+x\n"
	calls() // drop the setup's own calls
	e.create(api.CreateBoxRequest{Name: "hostile", Workspace: ws})
	e.d.Stop(context.Background(), "hostile", api.StopRequest{})
	if res, err := e.d.Apply(context.Background(), "hostile", api.ApplyRequest{Check: true}); err != nil || !res.Checked {
		t.Fatalf("check: %+v %v", res, err)
	}
	res, err := e.d.Apply(context.Background(), "hostile", api.ApplyRequest{})
	if err != nil || !slices.Equal(res.Applied, []string{"a.txt"}) || !slices.Equal(res.Ignored, []string{"ignored-by-global.txt"}) {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if readFile(t, filepath.Join(ws, "a.txt")) != "new\n" {
		t.Fatal("a.txt not applied")
	}
	if ran, _ := filepath.Glob(evil + ".ran.*"); len(ran) > 0 {
		t.Fatalf("a program from the checkout's or the global git config ran %d times", len(ran))
	}

	seen := map[string]bool{}
	for _, c := range calls() {
		if !c.inCheckout(ws) {
			continue
		}
		sub := ""
		for i, a := range c.args {
			if a == "-c" || strings.HasPrefix(a, "--git-dir=") || strings.HasPrefix(a, "--work-tree=") || a == "--no-pager" {
				continue
			}
			if i > 0 && c.args[i-1] == "-c" {
				continue
			}
			sub = a
			break
		}
		seen[sub] = true
		if len(c.args) == 0 || c.args[0] != "--no-pager" || c.env["GIT_PAGER"] != "cat" || c.env["PAGER"] != "cat" || c.env["GIT_EXTERNAL_DIFF"] != "unset" {
			t.Errorf("git %v in the checkout may page or diff externally (env %v)", c.args, c.env)
		}
		for _, want := range []string{"core.fsmonitor=false", "core.pager=cat", "diff.external=", "core.untrackedCache=false"} {
			if !slices.Contains(c.args, want) {
				t.Errorf("git %v in the checkout lacks -c %s", c.args, want)
			}
		}
		if sub == "config" {
			if n := len(c.args); n < 2 || c.args[n-2] != "--get" || (c.args[n-1] != "core.excludesFile" && c.args[n-1] != "core.hooksPath") {
				t.Errorf("unexpected git config read in the checkout: %v", c.args)
			}
			continue // reading config is the one call that sees the global config: it runs nothing
		}
		if c.env["GIT_CONFIG_GLOBAL"] != "/dev/null" || c.env["GIT_CONFIG_NOSYSTEM"] != "1" {
			t.Errorf("git %v in the checkout reads the global or system config (env %v)", c.args, c.env)
		}
		if sub != "rev-parse" && sub != "check-ignore" && !slices.Contains(c.args, "core.hooksPath=/dev/null") {
			t.Errorf("git %v in the checkout may run hooks", c.args)
		}
	}
	if !seen["rev-parse"] || !seen["check-ignore"] {
		t.Fatalf("expected git calls in the checkout not seen: %v", seen)
	}
}

// A3 (a): a GIT binary patch section is parsed exactly as git reads it; a line git would read differently, a hidden
// header, or a missing terminating empty line refuses the patch.
func TestApplyLeadsStrictBinarySections(t *testing.T) {
	const head = "diff --git a/b.bin b/b.bin\nnew file mode 100644\nindex 0000000..1111111\nGIT binary patch\n"
	const good = "literal 3\nLc-mrMWC9ET00#gB\n\n"
	const next = "diff --git a/c.txt b/c.txt\nnew file mode 100644\n--- /dev/null\n+++ b/c.txt\n@@ -0,0 +1 @@\n+c\n"
	ok := map[string]string{
		"literal only":           head + good,
		"literal then reverse":   head + good + "literal 0\nHcmV?d00001\n\n",
		"then another section":   head + good + next,
		"reverse then a section": head + good + "literal 0\nHcmV?d00001\n\n" + next,
		"delta hunk":             head + "delta 3\nLc-mrMWC9ET00#gB\n\n",
	}
	for name, p := range ok {
		files, err := parsePatch(p)
		if err != nil || !files[0].Binary {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]string{
		// a header line inside binary data (no empty line ended it): git reads it as a corrupt data line
		"header hidden in the data": head + "literal 3\nLc-mrMWC9ET00#gB\n" + next,
		"no terminating empty line": head + good[:len(good)-1],
		"ends after the literal":    head + "literal 3\n",
		"no literal or delta":       head + "Lc-mrMWC9ET00#gB\n\n",
		"length char lies":          head + "literal 3\nGc-mrMWC9ET00#gB\n\n",
		"not base85":                head + "literal 3\nLc-mrMWC9ET00#g\"\n\n",
		"spaces in the data":        head + "literal 3\nLc-mr MWC9ET00#g\n\n",
		"a hunk header in the data": head + "literal 3\n@@ -0,0 +1 @@\n\n",
		"bad size":                  head + "literal 3x\nLc-mrMWC9ET00#gB\n\n",
	}
	for name, p := range bad {
		if _, err := parsePatch(p); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "binary") && !strings.Contains(err.Error(), "outside a git file header") &&
			!strings.Contains(err.Error(), "hunk outside") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
