package image

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// debugfsBufsiz is glibc's BUFSIZ, the fgets buffer debugfs's source_file reads command files with.
const debugfsBufsiz = 8192

// debugfsLines is debugfs's source_file: fgets lines of at most BUFSIZ-1 bytes, '#' lines are comments, the line
// ends at its first '\n' and then at its first '\r'.
func debugfsLines(cmds []byte) []string {
	var out []string
	for len(cmds) > 0 {
		n := bytes.IndexByte(cmds, '\n') + 1
		if n == 0 {
			n = len(cmds)
		}
		if n > debugfsBufsiz-1 {
			n = debugfsBufsiz - 1
		}
		buf := string(cmds[:n])
		cmds = cmds[n:]
		if strings.HasPrefix(buf, "#") {
			continue
		}
		if i := strings.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[:i]
		}
		if i := strings.IndexByte(buf, '\r'); i >= 0 {
			buf = buf[:i]
		}
		if i := strings.IndexByte(buf, 0); i >= 0 {
			buf = buf[:i] // C string
		}
		out = append(out, buf)
	}
	return out
}

// ssParse is e2fsprogs lib/ss/parse.c: words split on space and tab; '"' opens a quoted string in which '""' is one
// quote; a quote in the middle of a token switches to quoted mode. A line starting with '!' (after blanks) is a
// shell escape.
func ssParse(line string) ([]string, error) {
	l := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(l, "!") {
		return nil, errors.New("shell escape")
	}
	const (
		white = iota
		token
		quoted
	)
	mode := white
	var argv []string
	var cur []byte
	for i := 0; ; i++ {
		var c byte
		if i < len(l) {
			c = l[i]
		}
		switch mode {
		case white:
			if c == 0 {
				return argv, nil
			}
			if c == ' ' || c == '\t' {
				continue
			}
			cur = cur[:0]
			if c == '"' {
				mode = quoted
			} else {
				mode = token
				cur = append(cur, c)
			}
		case token:
			switch {
			case c == 0:
				return append(argv, string(cur)), nil
			case c == ' ' || c == '\t':
				argv = append(argv, string(cur))
				mode = white
			case c == '"':
				mode = quoted
			default:
				cur = append(cur, c)
			}
		case quoted:
			switch {
			case c == 0:
				return nil, errors.New("unbalanced quotes")
			case c == '"':
				if i+1 < len(l) && l[i+1] == '"' {
					cur = append(cur, '"')
					i++
				} else {
					mode = token
				}
			default:
				cur = append(cur, c)
			}
		}
	}
}

// FuzzDebugfsQuote: a quoted path never breaks out of its line or its quotes: the command file line debugfs reads
// parses to exactly sif, the path, the field and the value.
func FuzzDebugfsQuote(f *testing.F) {
	for _, s := range []string{"/etc/passwd", `/a "b"`, "/a\nb", "/a\rb", "/" + strings.Repeat("x", 3990), `/""`, "/a\tb",
		"/#x", "/!x", `/a"`, "/<12>", "/a\x00b", "/\xff\xfe", "/ lead", "/trail "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		q, err := debugfsQuote(p)
		if err != nil {
			return
		}
		for _, field := range []string{"mode 0100644", "uid 4294967295", "gid 0"} {
			line := "sif " + q + " " + field + "\n"
			lines := debugfsLines([]byte(line))
			if len(lines) != 1 {
				t.Fatalf("debugfsQuote(%q) = %q: debugfs reads %d lines %q", p, q, len(lines), lines)
			}
			argv, err := ssParse(lines[0])
			if err != nil {
				t.Fatalf("debugfsQuote(%q) = %q: %v", p, q, err)
			}
			want := append([]string{"sif", p}, strings.Fields(field)...)
			if len(argv) != len(want) {
				t.Fatalf("debugfsQuote(%q) = %q parses to %q, want %q", p, q, argv, want)
			}
			for i := range want {
				if argv[i] != want[i] {
					t.Fatalf("debugfsQuote(%q) = %q parses to %q, want %q", p, q, argv, want)
				}
			}
		}
	})
}

// FuzzFixups: for any file name in a staged tree, every command fixups writes addresses a file that exists in the
// tree, with one of the fields it means to set.
func FuzzFixups(f *testing.F) {
	for _, s := range []string{"plain", `a "b"`, "a\nb", "#c", "!d", "e\tf", `""`, "g\rh"} {
		f.Add(s, uint32(1000), uint32(0o4755))
	}
	f.Fuzz(func(t *testing.T, name string, uid, mode uint32) {
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || len(name) > 200 {
			return
		}
		root := t.TempDir()
		dir := filepath.Join(root, "d")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			return // the host file system refuses the name
		}
		meta := map[string]entryMeta{"d/" + name: {uid: uid, gid: uid, mode: mode & 0o7777}, "d": {mode: 0o700}}
		cmds, _, err := fixups(root, meta)
		if err != nil {
			return
		}
		for _, l := range debugfsLines(cmds) {
			argv, err := ssParse(l)
			if err != nil {
				t.Fatalf("fixups line %q: %v", l, err)
			}
			if len(argv) != 4 || argv[0] != "sif" || !strings.HasPrefix(argv[1], "/") {
				t.Fatalf("fixups line %q parses to %q", l, argv)
			}
			if _, err := os.Lstat(filepath.Join(root, argv[1])); err != nil {
				t.Fatalf("fixups line %q addresses %q, not in the tree: %v", l, argv[1], err)
			}
			switch argv[2] {
			case "uid", "gid", "mode":
			default:
				t.Fatalf("fixups line %q sets field %q", l, argv[2])
			}
		}
	})
}
