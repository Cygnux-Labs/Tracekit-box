package tracekit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// posixWords splits one POSIX shell command line into the words of a simple command, refusing anything that is not
// a plain simple command of literal words: operators, expansions, unquoted glob and tilde characters, comments,
// more than one command, an assignment or a reserved word where the command name goes.
func posixWords(line string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord, quotedAny := false, false
	wordStart := true // the next character starts a word
	end := func() {
		if inWord {
			words = append(words, cur.String())
		}
		cur.Reset()
		inWord, quotedAny, wordStart = false, false, true
	}
	_ = quotedAny
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			end()
			continue
		case c == '\n':
			return nil, errors.New("newline outside quotes: a second command")
		case c == '\'':
			j := strings.IndexByte(line[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("unterminated single quote")
			}
			cur.WriteString(line[i+1 : i+1+j])
			i += j + 1
			inWord, quotedAny = true, true
		case c == '"':
			i++
			for ; i < len(line) && line[i] != '"'; i++ {
				switch line[i] {
				case '$', '`':
					return nil, fmt.Errorf("expansion %q inside double quotes", line[i])
				case '\\':
					if i+1 < len(line) && strings.IndexByte("$`\"\\\n", line[i+1]) >= 0 {
						i++
					}
				}
				cur.WriteByte(line[i])
			}
			if i >= len(line) {
				return nil, errors.New("unterminated double quote")
			}
			inWord, quotedAny = true, true
		case c == '\\':
			if i+1 >= len(line) {
				return nil, errors.New("trailing backslash")
			}
			i++
			if line[i] != '\n' {
				cur.WriteByte(line[i])
				inWord, quotedAny = true, true
			}
		case strings.IndexByte(";&|<>()", c) >= 0:
			return nil, fmt.Errorf("operator %q", c)
		case c == '$' || c == '`':
			return nil, fmt.Errorf("expansion %q", c)
		case c == '*' || c == '?' || c == '[':
			return nil, fmt.Errorf("pathname expansion %q", c)
		case c == '#' && wordStart:
			return nil, errors.New("comment")
		case c == '~' && (wordStart || (i > 0 && (line[i-1] == '=' || line[i-1] == ':'))):
			return nil, errors.New("tilde expansion")
		case c == '{' || c == '}':
			return nil, fmt.Errorf("brace %q (bash brace expansion or a group)", c)
		case c == '!' && wordStart:
			return nil, errors.New("! (pipeline negation or history)")
		default:
			cur.WriteByte(c)
			inWord = true
		}
		wordStart = false
	}
	end()
	return words, nil
}

var posixReserved = map[string]bool{"!": true, "{": true, "}": true, "case": true, "do": true, "done": true, "elif": true,
	"else": true, "esac": true, "fi": true, "for": true, "if": true, "in": true, "then": true, "until": true, "while": true,
	"[[": true, "]]": true, "function": true, "select": true, "time": true, "coproc": true}

// commandWordProblem reports why a shell would not run the first word of line as the program name.
func commandWordProblem(line string) string {
	// the first word as written (before quote removal)
	raw := line
	if i := strings.IndexAny(raw, " \t"); i >= 0 {
		raw = raw[:i]
	}
	if posixReserved[raw] {
		return "a reserved word"
	}
	if eq := strings.IndexByte(raw, '='); eq > 0 {
		name := raw[:eq]
		if strings.TrimLeft(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789") == "" &&
			!(name[0] >= '0' && name[0] <= '9') {
			return "an assignment"
		}
		if strings.HasSuffix(name, "+") && !strings.ContainsAny(name[:len(name)-1], "'\"\\") && len(name) > 1 {
			return "a bash += assignment"
		}
	}
	return ""
}

// refusedArgv0 is a program name the daemon refuses before anything is signed: an empty one, and one starting with
// %, which bash and zsh read as a job spec (internal/daemon/exec.go).
func refusedArgv0(a string) bool { return a == "" || strings.HasPrefix(a, "%") }

func splitArgv(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	return strings.Split(string(data), "\x00")
}

// FuzzShellQuote: the signed command line parses (POSIX words, no expansions, one simple command) back to exactly
// argv, and its first word is the program the guest runs.
func FuzzShellQuote(f *testing.F) {
	for _, argv := range [][]string{
		{"python", "-c", "print(1+1)"}, {"ls", "-la", "/workspace"}, {"echo", "it's"}, {"sh", "-c", "echo $HOME > x"},
		{"printf", ""}, {"tracekit", "verify", "/tmp/x.tkb", "--trust", "/tmp/t.json"}, {"a", "~", "#x", "x=~/y"},
		{"%1"}, {"-"}, {"=x"}, {"@", "+", ",", ":"}, {"a\nb"}, {"\xff\xfe"}, {"''"}, {"a b", "c\td"},
		{"FOO=bar", "x"}, {"if", "true"}, // an assignment or a reserved word as the program name
	} {
		f.Add([]byte(strings.Join(argv, "\x00")))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		argv := splitArgv(data)
		if len(argv) == 0 || refusedArgv0(argv[0]) {
			return
		}
		line := ShellQuote(argv)
		words, err := posixWords(line)
		if err != nil {
			t.Fatalf("ShellQuote(%q) = %q, which is not a plain command: %v", argv, line, err)
		}
		if len(words) != len(argv) {
			t.Fatalf("ShellQuote(%q) = %q parses to %d words %q", argv, line, len(words), words)
		}
		for i := range argv {
			if words[i] != argv[i] {
				t.Fatalf("ShellQuote(%q) = %q: word %d is %q, want %q", argv, line, i, words[i], argv[i])
			}
		}
		if why := commandWordProblem(line); why != "" {
			t.Fatalf("ShellQuote(%q) = %q: a shell reads its first word as %s", argv, line, why)
		}
	})
}

// TestShellQuoteRealShells runs the fuzz corpus and generated argvs through real shells: `set --` must give back argv
// in dash, bash and zsh (sh mode); and bash's command_not_found_handle must receive exactly argv when argv[0] is not
// a builtin, function or reserved word.
func TestShellQuoteRealShells(t *testing.T) {
	shells := []string{}
	for _, s := range []string{"/bin/dash", "/bin/bash", "/bin/zsh", "/bin/ksh"} {
		if _, err := os.Stat(s); err == nil {
			shells = append(shells, s)
		}
	}
	if len(shells) == 0 || os.Getenv("TKBOX_REAL_SHELLS") == "" {
		t.Skip("set TKBOX_REAL_SHELLS=1 (needs /bin/dash, /bin/bash or /bin/zsh)")
	}
	var cases [][]string
	if dir, err := os.ReadDir("testdata/fuzz/FuzzShellQuote"); err == nil {
		for _, e := range dir {
			b, _ := os.ReadFile("testdata/fuzz/FuzzShellQuote/" + e.Name())
			if v, ok := corpusBytes(b); ok {
				cases = append(cases, splitArgv(v))
			}
		}
	}
	if extra := os.Getenv("TKBOX_SHELL_CORPUS"); extra != "" {
		dir, _ := os.ReadDir(extra)
		for _, e := range dir {
			b, _ := os.ReadFile(extra + "/" + e.Name())
			if v, ok := corpusBytes(b); ok {
				cases = append(cases, splitArgv(v))
			}
		}
	}
	alphabet := []byte("aZ09 \t'\"\\$`*?[]{}~#!=%@+,:./-_;&|<>()\n\xc3\xa9")
	seed := uint32(1)
	for n := 0; n < 3000; n++ {
		var argv []string
		for w := 0; w <= int(seed%4); w++ {
			var b []byte
			for k := 0; k < int(seed>>8%7); k++ {
				seed = seed*1664525 + 1013904223
				b = append(b, alphabet[seed>>16%uint32(len(alphabet))])
			}
			argv = append(argv, string(b))
			seed = seed*1664525 + 1013904223
		}
		cases = append(cases, argv)
	}
	bad := 0
	for _, argv := range cases {
		if len(argv) == 0 || refusedArgv0(argv[0]) || strings.ContainsRune(strings.Join(argv, ""), 0) {
			continue
		}
		line := ShellQuote(argv)
		want := strings.Join(argv, "\x00") + "\x00"
		for _, sh := range shells {
			script := "set -- " + line + "\nfor a in \"$@\"; do printf '%s\\0' \"$a\"; done"
			args := []string{"-c", script}
			if strings.HasSuffix(sh, "zsh") {
				args = []string{"--emulate", "sh", "-c", script}
			}
			out, err := exec.Command(sh, args...).Output()
			if err != nil || string(out) != want {
				bad++
				t.Errorf("%s: set -- %s gave %q (%v), want %q", sh, line, out, err, want)
			}
		}
		if strings.ContainsRune(argv[0], '/') {
			continue
		}
		// zsh (POSIX sh emulation) calls command_not_found_handler with the words of a command it cannot find
		// (macOS /bin/bash 3.2 has no command_not_found_handle)
		probe := exec.Command("/bin/zsh", "--emulate", "sh", "-c", `whence -w -- "$1" 2>/dev/null`, "zsh", argv[0])
		if kind, _ := probe.Output(); !strings.HasSuffix(strings.TrimSpace(string(kind)), ": none") {
			continue // a builtin, reserved word or function: a different program by design
		}
		script := "command_not_found_handler() { for a in \"$@\"; do printf '%s\\0' \"$a\"; done; return 0; }\nPATH=/nonexistent-tkbox\n" + line
		out, _ := exec.Command("/bin/zsh", "--emulate", "sh", "-c", script).Output()
		if !bytes.Equal(out, []byte(want)) {
			bad++
			t.Errorf("zsh runs %q as %q, want %q", line, out, want)
		}
		if bad > 20 {
			t.Fatal("too many failures")
		}
	}
}

// corpusBytes reads a one-[]byte go test fuzz v1 corpus file.
func corpusBytes(b []byte) ([]byte, bool) {
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[1], "[]byte(") {
		return nil, false
	}
	s := strings.TrimSuffix(strings.TrimPrefix(lines[1], "[]byte("), ")")
	var out string
	if _, err := fmt.Sscanf(s, "%q", &out); err != nil {
		return nil, false
	}
	return []byte(out), true
}
