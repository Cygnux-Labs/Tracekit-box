package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

func modify(name string) string {
	return "diff --git a/" + name + " b/" + name + "\nindex 1111111..2222222 100644\n--- a/" + name + "\n+++ b/" + name +
		"\n@@ -1 +1 @@\n-old\n+new\n"
}

func TestParsePatchAndCheckPaths(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "real"), 0o755)
	os.Symlink("/etc", filepath.Join(dir, "linkdir"))
	os.Symlink("real", filepath.Join(dir, "inside"))
	cases := map[string]struct {
		patch string
		want  string // "" = accepted
	}{
		"plain":           {modify("src/a.go"), ""},
		"dotdot":          {modify("../x"), "leaves the checkout"},
		"dotdot inside":   {modify("src/../../x"), "not a clean"},
		"git hooks":       {modify(".git/hooks/pre-commit"), "touches .git"},
		"GIT upper":       {modify(".GIT/config"), "touches .git"},
		"nested git":      {modify("sub/.Git/config"), "touches .git"},
		"git trailing":    {modify(".git./config"), "touches .git"},
		"absolute":        {"diff --git a//etc/passwd b//etc/passwd\n--- a//etc/passwd\n+++ b//etc/passwd\n@@ -1 +1 @@\n-a\n+b\n", "absolute"},
		"symlink parent":  {modify("linkdir/passwd"), "is a symlink"},
		"quoted ok":       {"diff --git \"a/sp ace\\tx\" \"b/sp ace\\tx\"\n--- \"a/sp ace\\tx\"\n+++ \"b/sp ace\\tx\"\n@@ -1 +1 @@\n-a\n+b\n", ""},
		"quoted dotgit":   {"diff --git \"a/\\056git/config\" \"b/\\056git/config\"\n--- \"a/\\056git/config\"\n+++ \"b/\\056git/config\"\n@@ -1 +1 @@\n-a\n+b\n", "touches .git"},
		"quoted dotdot":   {"diff --git \"a/../x\" \"b/../x\"\n--- \"a/../x\"\n+++ \"b/../x\"\n@@ -1 +1 @@\n-a\n+b\n", "leaves the checkout"},
		"rename out":      {"diff --git a/ok.txt b/ok2.txt\nsimilarity index 100%\nrename from ok.txt\nrename to ../evil.txt\n", "leaves the checkout"},
		"rename into git": {"diff --git a/ok.txt b/x\nsimilarity index 100%\nrename from ok.txt\nrename to .git/config\n", "touches .git"},
		"rename ok":       {"diff --git a/ok.txt b/new.txt\nsimilarity index 100%\nrename from ok.txt\nrename to new.txt\n", ""},
		"copy from git":   {"diff --git a/x b/y\nsimilarity index 100%\ncopy from .git/config\ncopy to y\n", "touches .git"},
		"plus header":     {"diff --git a/a b/a\n--- a/a\n+++ b/../../etc/x\n@@ -1 +1 @@\n-a\n+b\n", "leaves the checkout"},
		"new symlink abs": {"diff --git a/l b/l\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+/etc/passwd\n\\ No newline at end of file\n", "absolute path"},
		"new symlink out": {"diff --git a/d/l b/d/l\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/d/l\n@@ -0,0 +1 @@\n+../../x\n\\ No newline at end of file\n", "outside the checkout"},
		"symlink to git":  {"diff --git a/l b/l\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+.git/config\n\\ No newline at end of file\n", "into .git"},
		"new symlink ok":  {"diff --git a/d/l b/d/l\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/d/l\n@@ -0,0 +1 @@\n+../real/f\n\\ No newline at end of file\n", ""},
		"retarget link":   {"diff --git a/inside b/inside\nindex 1111111..2222222 120000\n--- a/inside\n+++ b/inside\n@@ -1 +1 @@\n-real\n\\ No newline at end of file\n+/etc\n\\ No newline at end of file\n", "absolute path"},
		"traditional":     {"--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n", "only git-format"},
		"stray after":     {modify("ok") + "--- a/../../x\n+++ b/../../x\n@@ -1 +1 @@\n-a\n+b\n", "only git-format"},
		"hunk hides hdr":  {"diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n-a\ndiff --git a/../x b/../x\n", "inside a hunk"},
		"binary no data":  {"diff --git a/b b/b\nBinary files a/b and b/b differ\n", "without its data"},
		"deleted":         {"diff --git a/gone b/gone\ndeleted file mode 100644\nindex 1111111..0000000\n--- a/gone\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n", ""},
		"binary ok":       {"diff --git a/b.bin b/b.bin\nnew file mode 100644\nindex 0000000..1111111\nGIT binary patch\nliteral 3\nLc-mrMWC9ET00#gB\n\nliteral 0\nHcmV?d00001\n\n", ""},
		"commit message":  {"From abc Mon Sep 17 00:00:00 2001\nSubject: [PATCH] x\n\nbody text\n---\n a | 1 +\n" + modify("a") + "-- \n2.40.0\n", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			files, err := parsePatch(c.patch)
			var problems []string
			if err == nil {
				_, problems = checkPatch(files, dir)
			} else {
				problems = []string{err.Error()}
			}
			msg := strings.Join(problems, "; ")
			if c.want == "" && msg != "" {
				t.Fatalf("refused a good patch: %s", msg)
			}
			if c.want != "" && !strings.Contains(msg, c.want) {
				t.Fatalf("problems %q, want %q", msg, c.want)
			}
		})
	}
	files, _ := parsePatch("diff --git a/old b/new\nsimilarity index 90%\nrename from old\nrename to new\n--- a/old\n+++ b/new\n@@ -1 +1 @@\n-a\n+b\n")
	paths, _ := checkPatch(files, dir)
	if !slices.Equal(paths, []string{"new", "old"}) {
		t.Fatalf("a rename writes both paths: %v", paths)
	}
}

func gitInit(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	cmd := exec.Command("git", "init", "-q", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
}

func TestApply(t *testing.T) {
	e := newTestEnv(t, nil)
	ws := t.TempDir()
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	e.guest.Patch = modify("a.txt") +
		"diff --git a/b.txt b/b.txt\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/b.txt\n@@ -0,0 +1 @@\n+hello\n"
	e.create(api.CreateBoxRequest{Name: "ap", Workspace: ws})
	e.d.Stop(context.Background(), "ap", api.StopRequest{})
	ctx := context.Background()

	// the signer refuses one file: nothing is written
	e.tk.DecideFunc = func(c tracekit.Call) tracekit.Decision {
		if c.Tool == tracekit.ToolWrite && c.Args["file_path"] == filepath.Join(ws, "b.txt") {
			return tracekit.Decision{Decision: "deny", RuleIDs: []string{"TK-F001"}}
		}
		return tracekit.Decision{Decision: "allow"}
	}
	res, err := e.d.Apply(ctx, "ap", api.ApplyRequest{})
	if err != nil || !slices.Equal(res.Denied, []string{"b.txt"}) || len(res.Applied) != 0 {
		t.Fatalf("denied apply %+v %v", res, err)
	}
	if readFile(t, filepath.Join(ws, "a.txt")) != "old\n" {
		t.Fatal("a.txt changed although b.txt was denied")
	}
	if _, err := os.Stat(filepath.Join(ws, "b.txt")); !os.IsNotExist(err) {
		t.Fatal("b.txt written although denied")
	}
	e.tk.DecideFunc = nil

	// check writes nothing
	res, err = e.d.Apply(ctx, "ap", api.ApplyRequest{Check: true})
	if err != nil || !res.Checked || !slices.Equal(res.Applied, []string{"a.txt", "b.txt"}) || readFile(t, filepath.Join(ws, "a.txt")) != "old\n" {
		t.Fatalf("check %+v %v", res, err)
	}

	// allowed: applied (built by git apply in a scratch copy, written by Box), every file decided as a Write of its
	// absolute path
	res, err = e.d.Apply(ctx, "ap", api.ApplyRequest{})
	if err != nil || !slices.Equal(res.Applied, []string{"a.txt", "b.txt"}) || !strings.HasSuffix(res.Patch, "diff.patch") {
		t.Fatalf("apply %+v %v", res, err)
	}
	if readFile(t, filepath.Join(ws, "a.txt")) != "new\n" || readFile(t, filepath.Join(ws, "b.txt")) != "hello\n" {
		t.Fatal("files not applied")
	}
	var writes []string
	for _, r := range e.tk.Runs[0].Records {
		if r.Method == "decide" && r.Call.Tool == tracekit.ToolWrite {
			writes = append(writes, r.Call.Args["file_path"].(string))
		}
	}
	if len(writes) != 6 || writes[4] != filepath.Join(ws, "a.txt") {
		t.Fatalf("write decisions %v", writes)
	}

	// a conflicting checkout: git apply fails and says where the patch is
	if _, err := e.d.Apply(ctx, "ap", api.ApplyRequest{}); errCode(err) != api.CodeConflict {
		t.Fatalf("re-apply: %v", err)
	}

	// an unsafe patch is refused before any decision
	e.guest.Patch = modify(".git/config")
	e.create(api.CreateBoxRequest{Name: "evil", Workspace: ws})
	e.d.Stop(ctx, "evil", api.StopRequest{})
	n := len(e.tk.Runs[1].Methods())
	if _, err := e.d.Apply(ctx, "evil", api.ApplyRequest{}); errCode(err) != api.CodeBadRequest || !strings.Contains(err.Error(), ".git") {
		t.Fatalf("unsafe apply: %v", err)
	}
	if len(e.tk.Runs[1].Methods()) != n {
		t.Fatal("decisions made for an unsafe patch")
	}
	if _, err := e.d.Apply(ctx, "evil", api.ApplyRequest{Dir: "relative"}); errCode(err) != api.CodeBadRequest {
		t.Fatalf("relative dir: %v", err)
	}
}

// The config and instruction files coding agents read when they next run on the host, and anything under their
// config dirs (.claude/, .opencode/, .cursor/, .kilocode/), need --allow-sensitive, in any directory and any case
// (as a case-insensitive APFS checkout folds it: U+017F is s), and so does a symlink in a sensitive dir's place. The host's
// global git excludes (which often list .claude/settings.local.json) are kept out.
func TestApplyAgentConfigNeedsAllowSensitive(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	e := newTestEnv(t, nil)
	ws := t.TempDir()
	gitInit(t, ws)
	ctx := context.Background()
	n := 0
	newFile := func(p string) string {
		return "diff --git a/" + p + " b/" + p + "\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/" + p +
			"\n@@ -0,0 +1 @@\n+steer\n"
	}
	boxIn := func(ws, patch string) string {
		t.Helper()
		n++
		name := fmt.Sprintf("b%d", n)
		e.guest.Patch = patch
		e.create(api.CreateBoxRequest{Name: name, Workspace: ws})
		e.d.Stop(ctx, name, api.StopRequest{})
		return name
	}
	box := func(p string) string { return boxIn(ws, newFile(p)) }
	for _, f := range []string{".claude/settings.json", ".claude/settings.local.json", ".mcp.json", "CLAUDE.md", "AGENTS.md",
		".codex/config.toml", ".gemini/settings.json", ".vscode/settings.json", ".vscode/tasks.json",
		".claude/commands/review.md", ".claude/hooks/pre.sh", ".claude/skills/x/SKILL.md", ".opencode/plugin/p.ts",
		".cursor/rules/r.mdc", ".kilocode/rules/r.md", "CLAUDE.local.md", "GEMINI.md", "opencode.json", "opencode.jsonc",
		".cursorrules", ".windsurfrules", ".clinerules", ".goosehints", ".github/copilot-instructions.md"} {
		for _, p := range []string{f, "svc/api/" + f} {
			name := box(p)
			if _, err := e.d.Apply(ctx, name, api.ApplyRequest{}); errCode(err) != api.CodeBadRequest ||
				!strings.Contains(err.Error(), "steer the next run or host automation: "+p) {
				t.Errorf("%s without --allow-sensitive: %v", p, err)
			}
			if _, err := os.Lstat(filepath.Join(ws, p)); !os.IsNotExist(err) {
				t.Fatalf("%s written although refused", p)
			}
			res, err := e.d.Apply(ctx, name, api.ApplyRequest{AllowSensitive: true})
			if err != nil || !slices.Equal(res.Applied, []string{p}) || !slices.Equal(res.Sensitive, []string{p}) ||
				readFile(t, filepath.Join(ws, p)) != "steer\n" {
				t.Errorf("%s with --allow-sensitive: %+v %v", p, res, err)
			}
		}
	}
	for _, p := range []string{"docs/settings.json.md", "docs/claude.md.txt", "src/opencode.json.bak", "claude/commands/x.md",
		"docs/cursor/rules.md", "copilot-instructions.md"} {
		name := box(p)
		if res, err := e.d.Apply(ctx, name, api.ApplyRequest{}); err != nil || len(res.Sensitive) != 0 ||
			readFile(t, filepath.Join(ws, p)) != "steer\n" {
			t.Fatalf("an unrelated file %s: %+v %v", p, res, err)
		}
	}
	// a symlink in a sensitive dir's place, plus a file where it points: the link is the sensitive path
	links := t.TempDir()
	gitInit(t, links)
	for i, c := range []struct{ link, file string }{
		{".claude", "settings.json"}, {"web/.claude", "settings.json"}, {".opencode", "plugin/p.ts"}, {".cursor", "rules/r.mdc"},
		{".kilocode", "rules/r.md"}, {".husky", "pre-commit"}, {".vscode", "tasks.json"}, {".github/workflows", "ci.yml"},
		{"svc/.github", "workflows/ci.yml"},
	} {
		cfg := fmt.Sprintf("cfg%d", i)
		name := boxIn(links, "diff --git a/"+c.link+" b/"+c.link+"\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/"+
			c.link+"\n@@ -0,0 +1 @@\n+"+strings.Repeat("../", strings.Count(c.link, "/"))+cfg+"\n\\ No newline at end of file\n"+
			newFile(cfg+"/"+c.file))
		if _, err := e.d.Apply(ctx, name, api.ApplyRequest{}); errCode(err) != api.CodeBadRequest ||
			!strings.Contains(err.Error(), "steer the next run or host automation: "+c.link) {
			t.Errorf("link %s without --allow-sensitive: %v", c.link, err)
		}
		for _, p := range []string{c.link, cfg} {
			if _, err := os.Lstat(filepath.Join(links, p)); !os.IsNotExist(err) {
				t.Fatalf("%s written although refused", p)
			}
		}
		res, err := e.d.Apply(ctx, name, api.ApplyRequest{AllowSensitive: true})
		if err != nil || !slices.Equal(res.Sensitive, []string{c.link}) || readFile(t, filepath.Join(links, c.link, c.file)) != "steer\n" {
			t.Errorf("link %s with --allow-sensitive: %+v %v", c.link, res, err)
		}
	}
	for p, want := range map[string]bool{
		".claude": true, "a/.cursor": true, ".github": true, ".github/workflows": true, ".github/actions": true,
		".vscode": true, "x/.cargo": true, ".codex": true, ".gemini": true, ".husky": true, ".devcontainer": true,
		".claude-old": false, "claude": false, ".github/x": false,
		"AGENT\u017f.md": true, ".cur\u017for/rules/r.mdc": true, ".hu\u017fky/pre-commit": true, ".mcp.j\u017fon": true,
		".github/copilot-in\ufb06ructions.md": true, ".cargo/con\ufb01g.toml": true, ".pre-commit-con\ufb01g.yaml": true,
		".\u00dfh/config": true, ".\u1e9eh/config": true, "deploy/id_r\u017fa": true,
		"Web/.Claude/Settings.JSON": true, "pkg/Agents.MD": true, "a/b/.MCP.json": true, ".CODEX/config.TOML": true,
		".claude/settings.json.bak": true, "a/.OpenCode/Plugin/p.ts": true, ".Cursor/rules/r.mdc": true,
		"x/.KiloCode/r.md": true, "web/.clinerules/r.md": true, "pkg/Gemini.MD": true, "Claude.Local.MD": true,
		"svc/.GitHub/Copilot-Instructions.md": true, "OpenCode.JSONC": true, "a/.GooseHints": true,
		"settings.json": false, "config.toml": false, "claude/settings.json": false, "docs/claude.md.txt": false,
		"codex/config.toml": false, ".gemini/settings.json/x": false, "src/opencode.json.bak": false, "opencode/p.ts": false,
		".github/copilot-instructions.md.bak": false, "docs/.cursorrules.txt": false,
	} {
		if got := isSensitive(p); got != want {
			t.Errorf("isSensitive(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestApplyInSubdirOfRepo(t *testing.T) {
	e := newTestEnv(t, nil)
	repo := t.TempDir()
	gitInit(t, repo)
	sub := filepath.Join(repo, "pkg")
	os.Mkdir(sub, 0o755)
	os.WriteFile(filepath.Join(sub, "a.txt"), []byte("old\n"), 0o644)
	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "sub", Workspace: sub})
	e.d.Stop(context.Background(), "sub", api.StopRequest{})
	if _, err := e.d.Apply(context.Background(), "sub", api.ApplyRequest{}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(sub, "a.txt")) != "new\n" {
		t.Fatal("not applied relative to the workspace dir")
	}
}
