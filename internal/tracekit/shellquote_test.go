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
	} {
		if got := ShellQuote(c.argv); got != c.want {
			t.Errorf("ShellQuote(%q) = %s, want %s", c.argv, got, c.want)
		}
	}
}
