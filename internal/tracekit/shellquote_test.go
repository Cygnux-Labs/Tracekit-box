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
