package tracekit

import "testing"

func TestShellQuote(t *testing.T) {
	for _, c := range []struct {
		argv []string
		want string
	}{
		{[]string{"python", "-c", "print(1+1)"}, "python -c 'print(1+1)'"},
		{[]string{"ls", "-la", "/workspace"}, "ls -la /workspace"},
		{[]string{"echo", "it's"}, `echo 'it'\''s'`},
		{[]string{"sh", "-c", "echo $HOME > x"}, `sh -c 'echo $HOME > x'`},
		{[]string{"printf", ""}, "printf ''"},
		// the first word must stay the program: an assignment or a reserved word there is quoted
		{[]string{"X=1", "echo", "hi"}, "'X=1' echo hi"},
		{[]string{"then", "status"}, "'then' status"},
		{[]string{"for", "x"}, "'for' x"},
		{[]string{"env", "X=1", "then"}, "env X=1 then"},
	} {
		if got := ShellQuote(c.argv); got != c.want {
			t.Errorf("ShellQuote(%q) = %s, want %s", c.argv, got, c.want)
		}
	}
}

// Every word a POSIX shell or bash reads as syntax in command position is quoted as argv[0], so the signer's parser
// sees it as the program; the list is pinned here, not taken from the implementation's set.
func TestShellQuoteReservedWords(t *testing.T) {
	for _, w := range []string{"case", "coproc", "do", "done", "elif", "else", "esac", "fi", "for", "function", "if",
		"in", "select", "then", "time", "until", "while"} {
		if got, want := ShellQuote([]string{w, "x"}), "'"+w+"' x"; got != want {
			t.Errorf("ShellQuote([%q x]) = %s, want %s", w, got, want)
		}
		if got := ShellQuote([]string{"echo", w}); got != "echo "+w {
			t.Errorf("a reserved word after the program must stay bare: %s", got)
		}
	}
}
