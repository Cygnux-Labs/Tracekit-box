package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/image"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// patchFile is one file section of a git-format patch, as far as apply needs to judge it.
type patchFile struct {
	Old, New     string // relative paths; "" for /dev/null
	Names        []string
	NewMode      string // "new file mode" / "new mode"
	OldMode      string // "old mode" / "deleted file mode"
	IndexMode    string // mode on the index line (unchanged mode)
	Deleted      bool
	Rename, Copy bool
	Binary       bool
	Added        []string // '+' lines of the hunks (the target of a symlink)
	HasHunks     bool
	Raw          string // the section's own text, from its "diff --git" line up to the next section
}

var (
	hunkRE      = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)
	indexRE     = regexp.MustCompile(`^index [0-9a-f]+\.\.[0-9a-f]+(?: ([0-7]{6}))?$`)
	binHunkRE   = regexp.MustCompile(`^(?:literal|delta) (?:0|[1-9][0-9]{0,18})$`)
	base85Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
)

// base85Line reports whether ln is one data line of a GIT binary patch hunk as git reads it: a length character
// ('A'..'Z' for 1..26 bytes, 'a'..'z' for 27..52) and then exactly the base85 characters that many bytes take.
func base85Line(ln string) bool {
	if len(ln) < 6 || (len(ln)-1)%5 != 0 {
		return false
	}
	var n int
	switch c := ln[0]; {
	case c >= 'A' && c <= 'Z':
		n = int(c-'A') + 1
	case c >= 'a' && c <= 'z':
		n = int(c-'a') + 27
	default:
		return false
	}
	if max := (len(ln) - 1) / 5 * 4; n > max || n <= max-4 {
		return false
	}
	for i := 1; i < len(ln); i++ {
		if strings.IndexByte(base85Chars, ln[i]) < 0 {
			return false
		}
	}
	return true
}

// parsePatch reads the file sections of a git-format patch. It is strict: anything git apply could read as a
// header outside a git section (a traditional ---/+++ patch, a stray hunk) is refused, so every path git will touch
// is one this parser saw.
func parsePatch(patch string) ([]*patchFile, error) {
	var files []*patchFile
	var cur *patchFile
	const (
		outside    = iota // before the first section or between sections
		header            // after "diff --git", before hunks
		hunk              // inside a hunk, counting lines
		binStart          // after "GIT binary patch": a "literal N" or "delta N" line must follow
		binData           // inside a binary hunk: base85 lines up to an empty line
		binReverse        // after the first binary hunk: an optional second (reverse) hunk
		after             // after a hunk ended, inside a section
	)
	state := outside
	var oldLeft, newLeft, binHunks int
	lines := strings.Split(patch, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	var starts []int
	defer func() {
		for k, f := range files {
			end := len(lines)
			if k+1 < len(starts) {
				end = starts[k+1]
			}
			f.Raw = strings.Join(lines[starts[k]:end], "\n") + "\n"
		}
	}()
	for i, ln := range lines {
		lineNo := i + 1
		bad := func(format string, a ...any) error {
			return fmt.Errorf("patch line %d: %s", lineNo, fmt.Sprintf(format, a...))
		}
		if state == hunk {
			switch {
			case strings.HasPrefix(ln, `\`):
				continue
			case ln == "" || ln[0] == ' ':
				oldLeft--
				newLeft--
			case ln[0] == '-':
				oldLeft--
			case ln[0] == '+':
				newLeft--
				cur.Added = append(cur.Added, ln[1:])
			default:
				return nil, bad("unexpected line inside a hunk")
			}
			if oldLeft < 0 || newLeft < 0 {
				return nil, bad("hunk is longer than its header says")
			}
			if oldLeft == 0 && newLeft == 0 {
				state = after
			}
			continue
		}
		// a binary section is read exactly as git reads it (apply.c parse_binary): "literal N"/"delta N", base85
		// lines, an empty line, then at most one more such hunk. Anything else inside it is refused, so no line can
		// hide in it that git would read as a header (or the other way round)
		if state == binStart || state == binReverse {
			if binHunkRE.MatchString(ln) {
				binHunks++
				state = binData
				continue
			}
			if state == binStart {
				return nil, bad("a GIT binary patch must start with \"literal N\" or \"delta N\", not %q", trunc(ln))
			}
			state = after // no reverse hunk: this line is read as usual
		}
		if state == binData {
			switch {
			case ln == "" && binHunks == 1:
				state = binReverse
			case ln == "":
				state = after
			case !base85Line(ln):
				return nil, bad("not a line of a GIT binary patch (%q); git would read it differently", trunc(ln))
			}
			continue
		}
		if strings.HasPrefix(ln, "diff --git ") {
			cur = &patchFile{}
			files = append(files, cur)
			starts = append(starts, i)
			state = header
			a, b, ok := splitGitHeader(strings.TrimPrefix(ln, "diff --git "))
			if ok {
				for _, n := range []string{a, b} {
					p, err := stripPrefix(n)
					if err != nil {
						return nil, bad("%v", err)
					}
					cur.Names = append(cur.Names, p)
				}
				cur.Old, cur.New = cur.Names[0], cur.Names[1]
			}
			continue
		}
		if m := hunkRE.FindStringSubmatch(ln); m != nil {
			if cur == nil || state == outside {
				return nil, bad("a hunk outside a git file section")
			}
			oldLeft, newLeft = count(m[2]), count(m[4])
			cur.HasHunks = true
			state = hunk
			if oldLeft == 0 && newLeft == 0 {
				state = after
			}
			continue
		}
		isHeaderish := strings.HasPrefix(ln, "--- ") || strings.HasPrefix(ln, "+++ ") || strings.HasPrefix(ln, "*** ") ||
			strings.HasPrefix(ln, "@@")
		if state != header {
			if isHeaderish {
				return nil, bad("only git-format patches are applied (found %q outside a git file header)", trunc(ln))
			}
			continue // commit message text, trailers, "-- " signatures
		}
		switch {
		case strings.HasPrefix(ln, "--- "), strings.HasPrefix(ln, "+++ "):
			name, err := parseName(ln[4:], true)
			if err != nil {
				return nil, bad("%v", err)
			}
			if name == "/dev/null" {
				if ln[0] == '-' {
					cur.Old = ""
				} else {
					cur.New = ""
				}
				continue
			}
			p, err := stripPrefix(name)
			if err != nil {
				return nil, bad("%v", err)
			}
			cur.Names = append(cur.Names, p)
			if ln[0] == '-' {
				cur.Old = p
			} else {
				cur.New = p
			}
		case strings.HasPrefix(ln, "rename from "), strings.HasPrefix(ln, "rename to "),
			strings.HasPrefix(ln, "copy from "), strings.HasPrefix(ln, "copy to "):
			key, rest, _ := strings.Cut(ln, " ")
			dirn, rest, _ := strings.Cut(rest, " ")
			p, err := parseName(rest, false)
			if err != nil {
				return nil, bad("%v", err)
			}
			cur.Names = append(cur.Names, p)
			if key == "rename" {
				cur.Rename = true
			} else {
				cur.Copy = true
			}
			if dirn == "from" {
				cur.Old = p
			} else {
				cur.New = p
			}
		case strings.HasPrefix(ln, "new file mode "):
			cur.NewMode = strings.TrimPrefix(ln, "new file mode ")
			cur.Old = ""
		case strings.HasPrefix(ln, "deleted file mode "):
			cur.Deleted = true
			cur.OldMode = strings.TrimPrefix(ln, "deleted file mode ")
		case strings.HasPrefix(ln, "new mode "):
			cur.NewMode = strings.TrimPrefix(ln, "new mode ")
		case strings.HasPrefix(ln, "old mode "):
			cur.OldMode = strings.TrimPrefix(ln, "old mode ")
		case strings.HasPrefix(ln, "similarity index "), strings.HasPrefix(ln, "dissimilarity index "):
		case strings.HasPrefix(ln, "index "):
			m := indexRE.FindStringSubmatch(ln)
			if m == nil {
				return nil, bad("malformed index line")
			}
			cur.IndexMode = m[1]
		case ln == "GIT binary patch":
			cur.Binary = true
			state, binHunks = binStart, 0
		case strings.HasPrefix(ln, "Binary files "):
			return nil, bad("a binary change without its data; make the patch with --binary")
		default:
			return nil, bad("unexpected line in a git file header: %q", trunc(ln))
		}
	}
	if state == hunk {
		return nil, errors.New("patch ends inside a hunk")
	}
	if state == binStart || state == binData {
		return nil, errors.New("patch ends inside a GIT binary patch (no terminating empty line)")
	}
	for _, f := range files {
		if f.Deleted {
			f.New = ""
		}
		if len(f.Names) == 0 {
			return nil, errors.New("a git file section names no file this parser can read unambiguously")
		}
	}
	return files, nil
}

func count(s string) int {
	if s == "" {
		return 1
	}
	n, _ := strconv.Atoi(s)
	return n
}

func trunc(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}

// splitGitHeader splits the two names of a "diff --git" line. Quoted names are unquoted; unquoted names with spaces
// are split only when both halves name the same path (as git does); otherwise ok is false and the ---/+++ or
// rename/copy lines must name the files.
func splitGitHeader(s string) (string, string, bool) {
	if strings.HasPrefix(s, `"`) {
		a, rest, err := unquoteC(s)
		if err != nil || !strings.HasPrefix(rest, " ") {
			return "", "", false
		}
		rest = rest[1:]
		if strings.HasPrefix(rest, `"`) {
			b, tail, err := unquoteC(rest)
			if err != nil || tail != "" {
				return "", "", false
			}
			return a, b, true
		}
		return a, rest, true
	}
	if i := strings.Index(s, ` "`); i >= 0 {
		b, tail, err := unquoteC(s[i+1:])
		if err == nil && tail == "" {
			return s[:i], b, true
		}
	}
	// "a/X b/X": the same name twice
	if (len(s)-1)%2 == 0 {
		h := (len(s) - 1) / 2
		a, b := s[:h], s[h+1:]
		if s[h] == ' ' && len(a) > 2 && len(b) > 2 && a[2:] == b[2:] && strings.Contains(a, "/") && strings.Contains(b, "/") {
			return a, b, true
		}
	}
	if strings.Count(s, " ") == 1 {
		a, b, _ := strings.Cut(s, " ")
		return a, b, true
	}
	return "", "", false
}

// parseName reads a name from a ---/+++ (tabTerm: an unquoted name ends at a tab) or rename/copy line.
func parseName(s string, tabTerm bool) (string, error) {
	if strings.HasPrefix(s, `"`) {
		n, rest, err := unquoteC(s)
		if err != nil {
			return "", err
		}
		if rest != "" && !(tabTerm && strings.HasPrefix(rest, "\t")) {
			return "", fmt.Errorf("trailing text after quoted name")
		}
		return n, nil
	}
	if tabTerm {
		if i := strings.IndexByte(s, '\t'); i >= 0 {
			s = s[:i]
		}
	}
	if s == "" {
		return "", errors.New("empty file name")
	}
	return s, nil
}

// stripPrefix drops the a/ or b/ component of a git header name (git apply -p1).
func stripPrefix(n string) (string, error) {
	i := strings.IndexByte(n, '/')
	if i < 0 {
		return "", fmt.Errorf("file name %q has no a/ or b/ prefix", n)
	}
	return n[i+1:], nil
}

// unquoteC reads one C-quoted name from the start of s (git's quote_c_style) and returns it and the rest.
func unquoteC(s string) (string, string, error) {
	if !strings.HasPrefix(s, `"`) {
		return "", s, errors.New("not quoted")
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			return b.String(), s[i+1:], nil
		case '\\':
			i++
			if i >= len(s) {
				return "", "", errors.New("unterminated escape in a quoted name")
			}
			switch e := s[i]; e {
			case 'a':
				b.WriteByte('\a')
			case 'b':
				b.WriteByte('\b')
			case 't':
				b.WriteByte('\t')
			case 'n':
				b.WriteByte('\n')
			case 'v':
				b.WriteByte('\v')
			case 'f':
				b.WriteByte('\f')
			case 'r':
				b.WriteByte('\r')
			case '"', '\\':
				b.WriteByte(e)
			case '0', '1', '2', '3':
				if i+2 >= len(s) {
					return "", "", errors.New("short octal escape in a quoted name")
				}
				v, err := strconv.ParseUint(s[i:i+3], 8, 8)
				if err != nil {
					return "", "", errors.New("bad octal escape in a quoted name")
				}
				b.WriteByte(byte(v))
				i += 2
			default:
				return "", "", fmt.Errorf("unknown escape \\%c in a quoted name", e)
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", "", errors.New("unterminated quoted name")
}

// checkRelPath refuses anything but a clean relative path with no .. and no .git component (in any case).
func checkRelPath(p string) error {
	switch {
	case p == "":
		return errors.New("empty path")
	case strings.ContainsRune(p, 0):
		return fmt.Errorf("%q has a NUL byte", p)
	case strings.HasPrefix(p, "/"), filepath.IsAbs(p):
		return fmt.Errorf("%q is absolute", p)
	case path.Clean(p) != p:
		return fmt.Errorf("%q is not a clean relative path", p)
	}
	for _, c := range strings.Split(p, "/") {
		if c == ".." || c == "." {
			return fmt.Errorf("%q leaves the checkout", p)
		}
		if gitLike(c) {
			return fmt.Errorf("%q touches .git", p)
		}
	}
	return nil
}

// gitLike reports whether a path component is, or on some file system resolves to, .git: any case, trailing dots and
// spaces (NTFS), code points HFS+ ignores when it compares names, and the NTFS short name GIT~1.
func gitLike(c string) bool {
	c = strings.Map(func(r rune) rune {
		switch {
		case r == 0x200b, r >= 0x200c && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x206a && r <= 0x206f, r == 0xfeff:
			return -1
		}
		return r
	}, c)
	c = strings.TrimRight(c, ". ")
	return strings.EqualFold(c, ".git") || strings.EqualFold(c, "git~1")
}

// checkPatch validates every path of a parsed patch against dir and returns the paths it writes (sorted, unique).
func checkPatch(files []*patchFile, dir string) ([]string, []string) {
	var problems []string
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		for _, n := range f.Names {
			if err := checkRelPath(n); err != nil {
				problems = append(problems, err.Error())
			}
		}
		if len(problems) > 0 {
			continue
		}
		// a section that names two different files without saying it renames or copies one is read by git apply as
		// a rename: the old file would be deleted with no decision about it
		if f.Old != "" && f.New != "" && f.Old != f.New && !f.Rename && !f.Copy {
			problems = append(problems, fmt.Sprintf("a section changes %q into %q without a rename or copy header (git apply would delete %q); a box never makes such patches", f.Old, f.New, f.Old))
			continue
		}
		// every path git apply touches is a target: the new path, and the old one unless it is only read (copy)
		targets := []string{}
		if f.New != "" {
			targets = append(targets, f.New)
		}
		if f.Old != "" && !f.Copy {
			targets = append(targets, f.Old)
		}
		for _, t := range targets {
			if err := checkParents(dir, t); err != nil {
				problems = append(problems, err.Error())
				continue
			}
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
		if f.New == "" {
			continue
		}
		if err := checkSymlink(f, dir); err != nil {
			problems = append(problems, err.Error())
		}
	}
	sort.Strings(out)
	return out, problems
}

// checkParents refuses a path whose existing parent in dir is a symlink (or not a dir).
func checkParents(dir, rel string) error {
	parts := strings.Split(rel, "/")
	cur := dir
	for _, c := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, c)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%q: %v", rel, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%q: its parent %s is a symlink", rel, strings.TrimPrefix(cur, dir+string(filepath.Separator)))
		}
		if !fi.IsDir() {
			return fmt.Errorf("%q: its parent is not a directory", rel)
		}
	}
	return nil
}

// checkSymlink refuses a symlink the patch creates, retargets, renames or copies unless its target is relative and
// stays inside the checkout (and out of .git).
func checkSymlink(f *patchFile, dir string) error {
	isLink := f.NewMode == "120000" || (f.NewMode == "" && f.IndexMode == "120000")
	var target string
	haveTarget := false
	if f.NewMode == "" && f.IndexMode == "" {
		src := f.New
		if f.Rename || f.Copy {
			src = f.Old
		}
		if fi, err := os.Lstat(filepath.Join(dir, src)); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			isLink = true
		}
	}
	if !isLink {
		return nil
	}
	if f.Binary {
		return fmt.Errorf("%q: a symlink as a binary patch", f.New)
	}
	if f.HasHunks {
		target, haveTarget = strings.Join(f.Added, "\n"), true
	} else if f.Rename || f.Copy {
		t, err := os.Readlink(filepath.Join(dir, f.Old))
		if err != nil {
			return fmt.Errorf("%q: cannot read the symlink it copies: %v", f.New, err)
		}
		target, haveTarget = t, true
	}
	if !haveTarget {
		return nil // a mode-only change of an existing link: its target is not changing
	}
	if target == "" || strings.ContainsRune(target, 0) || strings.ContainsRune(target, '\n') {
		return fmt.Errorf("%q: bad symlink target", f.New)
	}
	if strings.HasPrefix(target, "/") {
		return fmt.Errorf("%q: symlink to an absolute path %q", f.New, target)
	}
	resolved := path.Clean(path.Join(path.Dir(f.New), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("%q: symlink %q points outside the checkout", f.New, target)
	}
	for _, c := range strings.Split(resolved, "/") {
		if gitLike(c) {
			return fmt.Errorf("%q: symlink %q points into .git", f.New, target)
		}
	}
	return nil
}

// summarize is the host's own summary of a patch (the guest's is never trusted): one entry per file section, and the
// patch's sha256, so a client can tell whether a patch it holds is the one summarized (for a running box, the patch
// and a summary read separately come from two guest diffs).
func summarize(patch []byte) api.DiffSummary {
	ps := sha256.Sum256(patch)
	sum := api.DiffSummary{Files: []proto.DiffFile{}, Bytes: int64(len(patch)), PatchSHA256: hex.EncodeToString(ps[:])}
	files, err := parsePatch(string(patch))
	if err != nil {
		return sum
	}
	for _, f := range files {
		df := proto.DiffFile{Path: f.New, Binary: f.Binary,
			Symlink: f.NewMode == "120000" || (f.NewMode == "" && f.IndexMode == "120000")}
		switch {
		case f.Deleted:
			df.Path, df.Status = f.Old, "deleted"
		case f.Rename:
			df.Status = "renamed"
		case f.Copy:
			df.Status = "copied"
		case f.Old == "":
			df.Status = "added"
		case f.NewMode != "" && !f.HasHunks && !f.Binary:
			df.Status = "mode"
		default:
			df.Status = "modified"
		}
		if df.Path == "" && len(f.Names) > 0 {
			df.Path = f.Names[len(f.Names)-1]
		}
		sum.Files = append(sum.Files, df)
	}
	return sum
}

// isSensitive reports whether a path steers the next run or host automation: git's own trust inputs (.gitignore,
// .gitattributes, .gitmodules), tkbox.yaml, files tools run on the host (.husky/, .github/workflows/,
// .github/actions/, .circleci/, .devcontainer/, .gitlab-ci.yml, .envrc, .pre-commit-config.yaml, lefthook.yml,
// .vscode/tasks.json, .cargo/config.toml, .yarnrc.yml), and credential files (.npmrc, .netrc, *.pem, *.key, …: the
// ones a workspace never copies into a box). Case-insensitive, at any depth.
func isSensitive(p string) bool {
	if image.IsCredentialPath(p) {
		return true
	}
	lower := strings.ToLower(p)
	switch path.Base(lower) {
	case ".gitignore", ".gitattributes", ".gitmodules", "tkbox.yaml", "tkbox.yml", ".envrc", ".pre-commit-config.yaml",
		".pre-commit-config.yml", ".gitlab-ci.yml", ".gitlab-ci.yaml", ".yarnrc.yml", ".yarnrc.yaml", ".yarnrc",
		"lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml", "lefthook-local.yml", "lefthook-local.yaml":
		return true
	}
	comps := strings.Split(lower, "/")
	for i, c := range comps[:len(comps)-1] {
		switch c {
		case ".husky", ".circleci", ".devcontainer":
			return true
		}
		next := comps[i+1]
		if c == ".github" && i+1 < len(comps)-1 && (next == "workflows" || next == "actions") {
			return true
		}
		if i+1 == len(comps)-1 {
			if c == ".vscode" && next == "tasks.json" {
				return true
			}
			if c == ".cargo" && (next == "config.toml" || next == "config") {
				return true
			}
		}
	}
	return false
}
