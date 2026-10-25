package image

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func (b *builder) Workspace(ctx context.Context, dir, out string) (Workspace, error) {
	mkfs, debugfs, err := b.tools()
	if err != nil {
		return Workspace{}, err
	}
	src, err := filepath.Abs(dir)
	if err == nil {
		src, err = filepath.EvalSymlinks(src)
	}
	if err != nil {
		return Workspace{}, fmt.Errorf("workspace: %w", err)
	}
	if fi, err := os.Stat(src); err != nil || !fi.IsDir() {
		return Workspace{}, fmt.Errorf("workspace: %s is not a directory", dir)
	}
	staging, err := os.MkdirTemp(filepath.Dir(out), ".workspace-staging-")
	if err != nil {
		return Workspace{}, fmt.Errorf("workspace: %w", err)
	}
	defer os.RemoveAll(staging)
	ws, meta, err := b.copyWorkspace(ctx, src, staging)
	if err != nil {
		return Workspace{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), "."+filepath.Base(out)+".tmp-")
	if err != nil {
		return Workspace{}, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := makeExt4(ctx, mkfs, debugfs, staging, meta, tmp.Name(), "tkbox-ws"); err != nil {
		return Workspace{}, fmt.Errorf("workspace: %w", err)
	}
	if err := os.Rename(tmp.Name(), out); err != nil {
		return Workspace{}, err
	}
	ws.Path = out
	return ws, nil
}

// copyWorkspace copies the workspace files of src into staging and returns what it copied plus the owner and mode
// of every staged path (root-owned, permission bits only: no setuid from a host checkout).
func (b *builder) copyWorkspace(ctx context.Context, src, staging string) (Workspace, map[string]entryMeta, error) {
	staging, err := filepath.EvalSymlinks(staging)
	if err != nil {
		return Workspace{}, nil, err
	}
	if err := os.Chmod(staging, 0o755); err != nil {
		return Workspace{}, nil, err
	}
	names, err := b.listWorkspace(ctx, src)
	if err != nil {
		return Workspace{}, nil, err
	}
	var ws Workspace
	var skipped []string // credential files left out
	defer func() {
		if len(skipped) > 0 {
			b.logf("tkbox: workspace %s: left out %d credential file(s) the box must not see: %s", src, len(skipped),
				strings.Join(skipped[:min(len(skipped), 5)], ", "))
		}
	}()
	entries := 0 // files and symlinks, for the cap
	meta := map[string]entryMeta{}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return Workspace{}, nil, err
		}
		comps, ok := workspaceComps(name)
		if !ok {
			continue
		}
		if credentialPath(comps) {
			skipped = append(skipped, strings.Join(comps, "/"))
			continue
		}
		fi, ok, err := lstatNoFollow(src, comps)
		if err != nil {
			return Workspace{}, nil, err
		}
		if !ok {
			continue // gone, under a symlinked dir, or a dir
		}
		mode := fi.Mode()
		if !mode.IsRegular() && mode&fs.ModeSymlink == 0 && !mode.IsDir() {
			continue // sockets, fifos, devices
		}
		if mode.IsDir() {
			if err := mkdirs(staging, comps, meta, fi.Mode().Perm()); err != nil {
				return Workspace{}, nil, err
			}
			continue
		}
		if entries++; entries > b.lim.WorkspaceFiles {
			return Workspace{}, nil, fmt.Errorf("workspace %s has more than %d files (WorkspaceFiles); add generated or vendored dirs to .gitignore, or point the box at a smaller directory", src, b.lim.WorkspaceFiles)
		}
		if err := mkdirs(staging, comps[:len(comps)-1], meta, 0o755); err != nil {
			return Workspace{}, nil, err
		}
		from := filepath.Join(src, filepath.Join(comps...))
		to := filepath.Join(staging, filepath.Join(comps...))
		rel := strings.Join(comps, "/")
		if mode&fs.ModeSymlink != 0 {
			target, err := os.Readlink(from)
			if err != nil {
				return Workspace{}, nil, fmt.Errorf("workspace: %w", err)
			}
			if err := os.Symlink(target, to); err != nil {
				return Workspace{}, nil, fmt.Errorf("workspace: %w", err)
			}
			meta[rel] = entryMeta{mode: 0o777}
			continue
		}
		if ws.Bytes+fi.Size() > b.lim.WorkspaceBytes {
			return Workspace{}, nil, fmt.Errorf("workspace %s holds more than %s of files (WorkspaceBytes); add large or generated files to .gitignore, or point the box at a smaller directory", src, human(b.lim.WorkspaceBytes))
		}
		n, err := copyFile(from, to, fi)
		if err != nil {
			return Workspace{}, nil, err
		}
		ws.Bytes += n
		ws.Files++
		meta[rel] = entryMeta{mode: uint32(fi.Mode().Perm()) | 0o400}
	}
	return ws, meta, nil
}

// Credential files never enter a workspace, git-ignored or not: an apply that edits .gitignore must not be able to
// pull them into the next box. Names are compared case-insensitively.
var (
	credentialDirs  = map[string]bool{".ssh": true, ".aws": true, ".gnupg": true, ".kube": true, ".docker": true, ".azure": true}
	credentialNames = map[string]bool{".netrc": true, "_netrc": true, ".npmrc": true, ".pypirc": true,
		".git-credentials": true, ".pgpass": true, ".htpasswd": true, ".dockercfg": true}
	credentialPrefixes = []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
	credentialSuffixes = []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".tfstate", ".tfstate.backup", ".tfvars"}
	envTemplates       = map[string]bool{"example": true, "sample": true, "template": true, "dist": true}
)

// credentialPath reports whether a workspace path is a credential file or lies in a credential dir.
func credentialPath(comps []string) bool {
	for i, c := range comps {
		lc := strings.ToLower(c)
		if i < len(comps)-1 {
			if credentialDirs[lc] || (lc == ".config" && strings.EqualFold(comps[i+1], "gcloud")) {
				return true
			}
			continue
		}
		if credentialDirs[lc] || credentialNames[lc] {
			return true
		}
		if lc == ".env" || (strings.HasPrefix(lc, ".env.") && !envTemplates[strings.TrimPrefix(lc, ".env.")]) {
			return true
		}
		for _, p := range credentialPrefixes {
			if strings.HasPrefix(lc, p) {
				return true
			}
		}
		for _, sfx := range credentialSuffixes {
			if strings.HasSuffix(lc, sfx) {
				return true
			}
		}
	}
	return false
}

// workspaceComps splits a listed name, dropping anything absolute, with "..", or with a .git component.
func workspaceComps(name string) ([]string, bool) {
	name = strings.TrimSuffix(name, "/")
	if name == "" || strings.HasPrefix(name, "/") {
		return nil, false
	}
	comps := strings.Split(filepath.ToSlash(name), "/")
	for _, c := range comps {
		if c == "" || c == "." || c == ".." || strings.EqualFold(c, ".git") {
			return nil, false
		}
	}
	return comps, true
}

// lstatNoFollow stats src/comps without following a symlink anywhere: every parent must be a real directory.
func lstatNoFollow(src string, comps []string) (fs.FileInfo, bool, error) {
	p := src
	for i, c := range comps {
		p = filepath.Join(p, c)
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("workspace: %w", err)
		}
		if i == len(comps)-1 {
			return fi, true, nil
		}
		if !fi.IsDir() {
			return nil, false, nil
		}
	}
	return nil, false, nil
}

func mkdirs(staging string, comps []string, meta map[string]entryMeta, perm fs.FileMode) error {
	p := staging
	for i, c := range comps {
		p = filepath.Join(p, c)
		rel := strings.Join(comps[:i+1], "/")
		if _, ok := meta[rel]; ok {
			continue
		}
		if err := os.Mkdir(p, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("workspace: %w", err)
		}
		m := uint32(0o755)
		if i == len(comps)-1 {
			m = uint32(perm) | 0o700
		}
		meta[rel] = entryMeta{mode: m}
	}
	return nil
}

// copyFile copies one regular file, opened without following symlinks and checked to be the file that was listed.
func copyFile(from, to string, listed fs.FileInfo) (int64, error) {
	in, err := os.OpenFile(from, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, fmt.Errorf("workspace: cannot read %s: %v; fix its permissions or add it to .gitignore", from, err)
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(fi, listed) {
		return 0, fmt.Errorf("workspace: %s changed while it was being copied; retry", from)
	}
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return 0, fmt.Errorf("workspace: %w", err)
	}
	n, err := io.CopyN(out, in, fi.Size())
	if err == nil {
		err = out.Chmod(fi.Mode().Perm() | 0o400)
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, fmt.Errorf("workspace: copying %s: %v (if it changed while copying, retry)", from, err)
	}
	os.Chtimes(to, time.Time{}, fi.ModTime())
	return n, nil
}

// listWorkspace lists the files to copy. Inside a git work tree it asks git for tracked plus untracked-not-ignored
// files; a git failure there is an error, never a fallback to copying everything (that would leak ignored .env
// files). Outside one it walks the tree.
func (b *builder) listWorkspace(ctx context.Context, src string) ([]string, error) {
	if !inGitWorkTree(src) {
		return b.walkWorkspace(src)
	}
	gitBin := b.opts.Git
	if gitBin == "" {
		p, err := exec.LookPath("git")
		if err != nil {
			return nil, fmt.Errorf("workspace %s is a git work tree but git is not installed; install git so ignored files (.env) stay out", src)
		}
		gitBin = p
	}
	var stderr capBuffer
	cmd := exec.CommandContext(ctx, gitBin, "-c", "core.fsmonitor=false", "-C", src, "ls-files", "-z", "-co", "--exclude-standard")
	cmd.Env = append(os.Environ(), "LC_ALL=C", "GIT_OPTIONAL_LOCKS=0")
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("workspace: running git: %w", err)
	}
	seen := map[string]bool{}
	var names []string
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	sc.Split(splitNUL)
	tooMany := false
	for sc.Scan() {
		n := sc.Text()
		if seen[n] {
			continue // unmerged paths are listed once per stage
		}
		seen[n] = true
		names = append(names, n)
		if len(names) > b.lim.WorkspaceFiles {
			tooMany = true
			cmd.Process.Kill()
			break
		}
	}
	scanErr := sc.Err()
	io.Copy(io.Discard, stdout)
	werr := cmd.Wait()
	if tooMany {
		return nil, fmt.Errorf("workspace %s has more than %d files (WorkspaceFiles); add generated or vendored dirs to .gitignore, or point the box at a smaller directory", src, b.lim.WorkspaceFiles)
	}
	if werr != nil {
		msg := strings.TrimSpace(stderr.String())
		hint := ""
		if strings.Contains(msg, "dubious ownership") {
			hint = "; run tkbox as the user who owns the checkout, or add it to git's safe.directory"
		}
		return nil, fmt.Errorf("workspace: git ls-files in %s failed: %v: %s%s", src, werr, msg, hint)
	}
	if scanErr != nil {
		return nil, fmt.Errorf("workspace: reading git ls-files: %w", scanErr)
	}
	return names, nil
}

func splitNUL(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// inGitWorkTree reports whether dir or a parent holds a .git entry (a dir, or a file for worktrees and submodules).
func inGitWorkTree(dir string) bool {
	for d := dir; ; {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return true
		}
		up := filepath.Dir(d)
		if up == d {
			return false
		}
		d = up
	}
}

// walkWorkspace lists every file, symlink and dir under src except .git, without following symlinks.
func (b *builder) walkWorkspace(src string) ([]string, error) {
	var names []string
	files := 0
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("workspace: %w", err)
		}
		if p == src {
			return nil
		}
		if strings.EqualFold(d.Name(), ".git") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			if files++; files > b.lim.WorkspaceFiles {
				return fmt.Errorf("workspace %s has more than %d files (WorkspaceFiles); point the box at a smaller directory", src, b.lim.WorkspaceFiles)
			}
		}
		names = append(names, filepath.ToSlash(p[len(src)+1:]))
		return nil
	})
	return names, err
}

func (b *builder) Scratch(ctx context.Context, out string, sizeBytes int64) error {
	if sizeBytes < 16<<20 {
		return fmt.Errorf("scratch disk of %d bytes is too small: give the box at least 16 MiB of disk", sizeBytes)
	}
	mkfs, err := findTool(b.opts.Mkfs, "mkfs.ext4")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(out), "."+filepath.Base(out)+".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = f.Truncate(sizeBytes &^ 4095)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := run(ctx, mkfs, "-q", "-F", "-b", "4096", "-m", "0", "-E", "root_owner=0:0", "-L", "tkbox-upper", f.Name(),
		strconv.FormatInt((sizeBytes&^4095)/1024, 10)+"k"); err != nil {
		return fmt.Errorf("scratch disk: %w", err)
	}
	return os.Rename(f.Name(), out)
}
