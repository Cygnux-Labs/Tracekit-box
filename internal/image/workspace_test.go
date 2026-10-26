package image

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		".gitignore":         ".env\nbuild/\n",
		".env":               "API_KEY=secret",
		"src/main.go":        "package main",
		"src/.env":           "nested secret",
		"build/out.bin":      "artifact",
		"untracked.txt":      "new",
		"docs/README.md":     "docs",
		"sub/.git/config":    "a nested repo's git dir",
		"weird \"name\".txt": "q",
	})
	if err := os.Symlink("src/main.go", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(dir, "src/main.go"), 0o4755) // setuid must not survive
	for _, args := range [][]string{{"init", "-q"}, {"add", ".gitignore", "src/main.go", "docs/README.md", "link"},
		{"-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "init"}} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func stagedNames(t *testing.T, root string) []string {
	t.Helper()
	var names []string
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if p != root && !fi.IsDir() {
			names = append(names, filepath.ToSlash(p[len(root)+1:]))
		}
		return nil
	})
	sort.Strings(names)
	return names
}

func TestWorkspaceGitListing(t *testing.T) {
	dir := gitRepo(t)
	b := newTestBuilder(t, nil, nil)
	staging := t.TempDir()
	ws, meta, err := b.copyWorkspace(t.Context(), dir, staging, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(stagedNames(t, staging), ",")
	want := `.gitignore,docs/README.md,link,src/main.go,untracked.txt,weird "name".txt`
	if got != want {
		t.Errorf("staged %s\nwant   %s", got, want)
	}
	if ws.Files != 5 { // regular files; the symlink is not counted
		t.Errorf("files %d", ws.Files)
	}
	if fi, err := os.Lstat(filepath.Join(staging, "link")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink not copied as a symlink")
	}
	if m := meta["src/main.go"]; m.uid != 0 || m.mode != 0o755 {
		t.Errorf("main.go meta %+v (setuid must be dropped)", m)
	}

	// From a subdirectory, only that subtree, still filtered by git.
	sub := t.TempDir()
	if _, _, err := b.copyWorkspace(t.Context(), filepath.Join(dir, "src"), sub, nil); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(stagedNames(t, sub), ","); got != "main.go" {
		t.Errorf("subdir staged %s", got)
	}

	// A git failure inside a work tree is an error, never a fallback that would copy .env.
	b.opts.Git = "/bin/false"
	if _, _, err := b.copyWorkspace(t.Context(), dir, t.TempDir(), nil); err == nil {
		t.Error("git failure fell back to copying everything")
	}
}

func TestWorkspaceWalkAndLimits(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"a.txt": "a", "d/b.txt": "bb", "vendor/.git/config": "x", "x/.git": "gitdir: elsewhere"})
	os.Mkdir(filepath.Join(dir, "empty"), 0o750)
	b := newTestBuilder(t, nil, nil)
	staging := t.TempDir()
	ws, meta, err := b.copyWorkspace(t.Context(), dir, staging, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(stagedNames(t, staging), ","); got != "a.txt,d/b.txt" || ws.Files != 2 || ws.Bytes != 3 {
		t.Errorf("staged %s (%+v)", got, ws)
	}
	if m, ok := meta["empty"]; !ok || m.mode != 0o750 {
		t.Errorf("empty dir meta %+v %v", m, ok)
	}
	// A .git that git does not accept fails closed instead of copying everything.
	fake := t.TempDir()
	writeFiles(t, fake, map[string]string{".git/config": "not a repo", ".env": "secret"})
	if _, _, err := b.copyWorkspace(t.Context(), fake, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "git ls-files") {
		t.Errorf("fake .git: got %v", err)
	}
	for _, c := range []struct {
		lim  Limits
		want string
	}{{Limits{WorkspaceFiles: 1}, "WorkspaceFiles"}, {Limits{WorkspaceBytes: 2}, "WorkspaceBytes"}} {
		b := newTestBuilder(t, nil, func(o *Options) { o.Limits = c.lim })
		if _, _, err := b.copyWorkspace(t.Context(), dir, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: got %v", c.lim, err)
		}
	}
}

func TestWorkspaceExt4(t *testing.T) {
	debugfs := needE2fs(t)
	dir := gitRepo(t)
	b := newTestBuilder(t, nil, nil)
	out := filepath.Join(t.TempDir(), "workspace-base.ext4")
	ws, err := b.Workspace(t.Context(), dir, out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Path != out || ws.Files != 5 {
		t.Errorf("%+v", ws)
	}
	fsck(t, out)
	for path, want := range map[string]inodeStat{
		"/src/main.go":      {0, 0, 0o755, "regular"},
		"/src":              {0, 0, 0o755, "directory"},
		"/link":             {0, 0, 0o777, "symlink"},
		`/weird "name".txt`: {0, 0, 0o644, "regular"},
		"/":                 {0, 0, 0o755, "directory"},
	} {
		if got, ok := debugfsStat(t, debugfs, out, path); !ok || got != want {
			t.Errorf("%s: got %+v (found %v), want %+v", path, got, ok, want)
		}
	}
	for _, p := range []string{"/.env", "/src/.env", "/.git", "/build", "/sub", "/fifo"} {
		if _, ok := debugfsStat(t, debugfs, out, p); ok {
			t.Errorf("%s is in the workspace image", p)
		}
	}
	stats, _ := exec.Command(debugfs, "-R", "stats", out).CombinedOutput()
	if strings.Contains(string(stats), "has_journal") {
		t.Error("workspace base has a journal")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(out), ".*")); len(left) != 0 {
		t.Errorf("leftovers: %v", left)
	}
}

// S5: credential files stay out of a workspace even when git does not ignore them (tracked or untracked) and when the
// dir is not a git work tree at all: an apply that edits .gitignore can't pull them into the next box.
func TestCredentialFilesSkippedUnlessIgnored(t *testing.T) {
	creds := map[string]string{".npmrc": "//registry/:_authToken=x", ".netrc": "machine m", ".pypirc": "[pypi]",
		"deploy/key.pem": "pem", "certs/server.key": "key", ".ssh/id_rsa": "rsa", ".aws/credentials": "aws", "id_ed25519": "k"}
	files := map[string]string{"src/main.go": "package main"}
	for k, v := range creds {
		files[k] = v
	}
	check := func(t *testing.T, dir string) {
		t.Helper()
		b := newTestBuilder(t, nil, nil)
		staging := t.TempDir()
		if _, _, err := b.copyWorkspace(t.Context(), dir, staging, nil); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(stagedNames(t, staging), ","); got != "src/main.go" {
			t.Errorf("staged %s, want only src/main.go", got)
		}
	}
	t.Run("outside git", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, files)
		if inGitWorkTree(dir) {
			t.Skip("the temp dir is inside a git work tree")
		}
		check(t, dir)
	})
	t.Run("git, not ignored", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("needs git")
		}
		dir := t.TempDir()
		writeFiles(t, dir, files)
		for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}, // tracked, and nothing is ignored
			{"-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "init"}} {
			if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
		check(t, dir)
	})
}

func TestCredentialPath(t *testing.T) {
	for name, want := range map[string]bool{
		".env": true, "app/.env.local": true, ".ENV.production": true, ".env.example": false, "config/.env.sample": false,
		"deploy/key.pem": true, "certs/server.KEY": true, "home/.ssh/config": true, ".aws/credentials": true,
		".config/gcloud/creds.db": true, ".npmrc": true, "sub/.git-credentials": true, "id_ed25519.pub": true,
		"infra/prod.tfstate": true, "infra/main.tf": false, "src/keyboard.go": false, "README.md": false,
		".docker/config.json": true, "docs/environment.md": false,
	} {
		comps, _ := workspaceComps(name)
		if got := credentialPath(comps); got != want {
			t.Errorf("credentialPath(%q) = %v, want %v", name, got, want)
		}
	}
}

// B1 (final check): a workspace file whose content, path or symlink target holds a secret's value refuses the copy,
// naming the file and the secret, never the value: a value read from a from_file next to tkbox.yaml under
// `workspace: .`, or kept in a file under an MCP --workspace-root, would otherwise be in the box. A value split
// across the copy's reads is found too; one shorter than MinSecretScan is not looked for.
func TestWorkspaceRefusesSecretValue(t *testing.T) {
	const val = "ghp_finalcheck0123456789"
	secrets := []SecretValue{{Name: "OTHER", Value: "never-in-this-workspace"}, {Name: "GH", Value: val}, {Name: "PIN", Value: "1234"}}
	for _, c := range []struct {
		name, path string
		setup      func(dir string)
	}{
		{"content", "key.txt", func(dir string) { os.WriteFile(filepath.Join(dir, "key.txt"), []byte("token: "+val+"\n"), 0o600) }},
		{"split across reads", "secrets/gh.txt", func(dir string) {
			os.Mkdir(filepath.Join(dir, "secrets"), 0o755)
			body := strings.Repeat("x", 32<<10-10) + val + strings.Repeat("y", 1000)
			os.WriteFile(filepath.Join(dir, "secrets", "gh.txt"), []byte(body), 0o600)
		}},
		{"name", "notes-[secret GH].txt", func(dir string) { os.WriteFile(filepath.Join(dir, "notes-"+val+".txt"), nil, 0o600) }},
		{"symlink target", "link", func(dir string) { os.Symlink("/tmp/"+val, filepath.Join(dir, "link")) }},
	} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main // PIN 1234\n"), 0o644)
		c.setup(dir)
		b := newTestBuilder(t, nil, nil)
		_, _, err := b.copyWorkspace(t.Context(), dir, t.TempDir(), secrets)
		var se *SecretInWorkspaceError
		if !errors.As(err, &se) || se.Path != c.path || se.Secret != "GH" || strings.Contains(err.Error(), val[4:]) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main // PIN 1234\n"), 0o644)
	if _, _, err := newTestBuilder(t, nil, nil).copyWorkspace(t.Context(), dir, t.TempDir(), secrets); err != nil {
		t.Fatalf("a workspace without a value (a 4-byte one is not looked for): %v", err)
	}
}
