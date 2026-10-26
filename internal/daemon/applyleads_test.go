package daemon

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/guest"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
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

// oracle runs gitAgrees on patch against files.
func oracle(t *testing.T, patch string, files []*patchFile) error {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "p.patch")
	os.WriteFile(p, []byte(patch), 0o600)
	return gitAgrees(context.Background(), dir, p, files)
}

// A3 (b): git is the oracle: before anything is decided, the set of paths (and creations, deletions, mode changes)
// git reads from the patch must be exactly the parser's. A patch the parser reads but git does not is refused before
// any decision.
func TestApplyLeadsGitIsTheOracle(t *testing.T) {
	needGit(t)
	a := modify("a.txt") + newFileSection("dir/b c.txt", "b") +
		"diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n" +
		"diff --git a/gone.txt b/gone.txt\ndeleted file mode 100644\n--- a/gone.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n" +
		"diff --git \"a/q\\\"\\tü\" \"b/q\\\"\\tü\"\nnew file mode 120000\n--- /dev/null\n+++ \"b/q\\\"\\tü\"\n@@ -0,0 +1 @@\n+target\n\\ No newline at end of file\n" +
		"diff --git a/b.bin b/b.bin\nnew file mode 100644\nindex 0000000..1111111\nGIT binary patch\nliteral 3\nLc-mrMWC9ET00#gB\n\n"
	fa, err := parsePatch(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := oracle(t, a, fa); err != nil {
		t.Fatalf("git and tkbox read the same patch differently: %v", err)
	}
	fb, _ := parsePatch(modify("a.txt") + newFileSection("other.txt", "b"))
	if err := oracle(t, a, fb); err == nil {
		t.Fatal("a different set of paths passed")
	}
	fc, _ := parsePatch(strings.Replace(a, "new mode 100755", "new mode 100644\nnew mode 100755", 1))
	fc[2].OldMode = "100755" // tkbox would see no mode change
	if err := oracle(t, a, fc); err == nil {
		t.Fatal("a different mode change passed")
	}

	// the parser reads a short "\" line inside a hunk as "no newline"; git reads the patch as corrupt
	bad := "diff --git a/a.txt b/a.txt\nindex 1111111..2222222 100644\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n\\x\n+new\n"
	if _, err := parsePatch(bad); err != nil {
		t.Fatalf("the parser refuses the probe patch already: %v", err)
	}
	e := newTestEnv(t, nil)
	ws := t.TempDir()
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	e.guest.Patch = bad
	e.create(api.CreateBoxRequest{Name: "o", Workspace: ws})
	e.d.Stop(context.Background(), "o", api.StopRequest{})
	_, err = e.d.Apply(context.Background(), "o", api.ApplyRequest{})
	if errCode(err) != api.CodeBadRequest || !strings.Contains(err.Error(), "git reads the patch differently") {
		t.Fatalf("a patch git reads differently: %v", err)
	}
	for _, r := range e.run(0).Records {
		if r.Call.Tool == tracekit.ToolWrite {
			t.Fatalf("a Write was decided for a patch git reads differently: %+v", r)
		}
	}
}

// A3: a differential test over the guest's real patches (binary literals of every line length, text, new files,
// modes and symlinks): the parser and git must read them the same way, and the binary sections parse strictly.
func TestApplyLeadsParserAgreesWithGitOnGuestPatches(t *testing.T) {
	needGit(t)
	base, upper := t.TempDir(), t.TempDir()
	rng := rand.New(rand.NewPCG(1, 2))
	var sizes []int
	for _, n := range []int{0, 1, 2, 3, 4, 5, 25, 26, 27, 51, 52, 53, 104, 1000, 70000} {
		sizes = append(sizes, n)
	}
	for _, n := range sizes {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(rng.UintN(256))
		}
		if n > 0 {
			data[0] = 0 // binary
		}
		os.WriteFile(filepath.Join(upper, fmt.Sprintf("bin-%d.dat", n)), data, 0o644)
		os.WriteFile(filepath.Join(base, fmt.Sprintf("mod-%d.dat", n)), append([]byte{0}, data...), 0o644)
		os.WriteFile(filepath.Join(upper, fmt.Sprintf("mod-%d.dat", n)), append([]byte{0, 1}, data...), 0o755)
	}
	os.WriteFile(filepath.Join(base, "text.txt"), []byte("one\ntwo\nthree\n"), 0o644)
	os.WriteFile(filepath.Join(upper, "text.txt"), []byte("one\n2\nthree\nfour"), 0o644)
	os.WriteFile(filepath.Join(base, "exec.sh"), []byte("echo\n"), 0o644)
	os.WriteFile(filepath.Join(upper, "exec.sh"), []byte("echo\n"), 0o755)
	os.MkdirAll(filepath.Join(upper, "dir with space", "ü"), 0o755)
	os.WriteFile(filepath.Join(upper, "dir with space", "ü", "tab\tname"), []byte("x\n"), 0o644)
	os.Symlink("../target", filepath.Join(upper, "link"))
	sum, patch, err := guest.Diff(&guest.DirTree{Root: upper}, &guest.DirTree{Root: base}, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	files, err := parsePatch(string(patch))
	if err != nil {
		t.Fatalf("the parser refuses the guest's patch: %v", err)
	}
	if len(files) != len(sum.Files) {
		t.Fatalf("%d sections parsed, the guest wrote %d", len(files), len(sum.Files))
	}
	bins := 0
	for i, f := range files {
		if f.Binary != sum.Files[i].Binary {
			t.Errorf("%s: binary %v, the guest says %v", sum.Files[i].Path, f.Binary, sum.Files[i].Binary)
		}
		if f.Binary {
			bins++
		}
	}
	if bins < 2*len(sizes)-2 {
		t.Fatalf("only %d binary sections", bins)
	}
	if err := oracle(t, string(patch), files); err != nil {
		t.Fatalf("git and tkbox read the guest's patch differently: %v", err)
	}
}

// A2: git never applies the patch to the checkout itself. The result is built in a scratch copy and written only once
// it matches the decisions exactly and the checkout is unchanged; otherwise nothing is written. Writes never follow a
// parent symlink that appeared after the decisions.
func TestApplyLeadsWritesOnlyWhatWasDecided(t *testing.T) {
	calls := gitShim(t)
	var hook atomic.Pointer[func()]
	e := newTestEnv(t, func(o *Options) {
		o.Gate = func(ctx context.Context, r tracekit.Run, call tracekit.Call, h tracekit.GateHooks) (tracekit.Outcome, error) {
			out, err := fakeGate(ctx, r, call, h)
			if f := hook.Load(); f != nil && call.Tool == tracekit.ToolWrite {
				(*f)()
			}
			return out, err
		}
	})
	setup := func(name string) string {
		ws, _ := filepath.EvalSymlinks(t.TempDir())
		gitInit(t, ws)
		os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
		os.Mkdir(filepath.Join(ws, "sub"), 0o755)
		e.guest.Patch = modify("a.txt") + newFileSection("sub/new.txt", "x") + newFileSection("run.sh", "echo")
		e.create(api.CreateBoxRequest{Name: name, Workspace: ws})
		e.d.Stop(context.Background(), name, api.StopRequest{})
		return ws
	}
	untouched := func(ws string) {
		t.Helper()
		if readFile(t, filepath.Join(ws, "a.txt")) != "old\n" {
			t.Fatal("a.txt was written")
		}
		for _, p := range []string{"sub/new.txt", "run.sh"} {
			if _, err := os.Lstat(filepath.Join(ws, p)); !os.IsNotExist(err) {
				t.Fatalf("%s was written", p)
			}
		}
	}

	// the scratch result differs from the decision (injected): nothing is written, the writes complete as not written
	ws := setup("mismatch")
	applyScratchHook = func(scratch string) { os.WriteFile(filepath.Join(scratch, "a.txt"), []byte("evil\n"), 0o644) }
	_, err := e.d.Apply(context.Background(), "mismatch", api.ApplyRequest{})
	applyScratchHook = nil
	if errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "differ from what was decided: a.txt") {
		t.Fatalf("mismatch: %v", err)
	}
	untouched(ws)
	for _, r := range e.run(0).Records {
		if r.Method == "complete" && r.Call.Tool == tracekit.ToolWrite {
			if m, _ := r.Value.(map[string]any); r.Status != "error" || m["written"] != false {
				t.Fatalf("complete after a mismatch: %s %v", r.Status, r.Value)
			}
		}
	}

	// the checkout changes after the decisions: nothing is written
	ws = setup("changed")
	change := func() { os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\nmore\n"), 0o644) }
	hook.Store(&change)
	_, err = e.d.Apply(context.Background(), "changed", api.ApplyRequest{})
	hook.Store(nil)
	if errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "checkout changed") {
		t.Fatalf("changed checkout: %v", err)
	}
	if readFile(t, filepath.Join(ws, "a.txt")) != "old\nmore\n" {
		t.Fatal("a.txt overwritten")
	}

	// a parent turns into a symlink after the decisions: the write under it is refused, nothing lands outside
	ws = setup("symlinked")
	outside := t.TempDir()
	swap := func() {
		os.Remove(filepath.Join(ws, "sub"))
		os.Symlink(outside, filepath.Join(ws, "sub"))
	}
	hook.Store(&swap)
	_, err = e.d.Apply(context.Background(), "symlinked", api.ApplyRequest{})
	hook.Store(nil)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked parent: %v", err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("written through a symlinked parent: %v", ents)
	}

	// a normal apply writes exactly the decided results, and git apply never ran in the checkout
	calls()
	ws = setup("ok")
	res, err := e.d.Apply(context.Background(), "ok", api.ApplyRequest{})
	if err != nil || len(res.Applied) != 3 {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if readFile(t, filepath.Join(ws, "a.txt")) != "new\n" || readFile(t, filepath.Join(ws, "sub/new.txt")) != "x\n" || readFile(t, filepath.Join(ws, "run.sh")) != "echo\n" {
		t.Fatal("not applied")
	}
	if fi, _ := os.Stat(filepath.Join(ws, "a.txt")); fi.Mode().Perm() != 0o644 {
		t.Fatalf("a.txt mode %v", fi.Mode())
	}
	for _, c := range calls() {
		if c.inCheckout(ws) && slices.Contains(c.args, "apply") {
			t.Fatalf("git apply ran in the checkout: %v (cwd %s)", c.args, c.cwd)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(ws, "*", ".tkbox-apply-*")); len(left) > 0 {
		t.Fatalf("temp files left: %v", left)
	}
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
			if n := len(c.args); n < 2 || c.args[n-2] != "--get-all" || (c.args[n-1] != "core.excludesFile" && c.args[n-1] != "core.hooksPath") {
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
