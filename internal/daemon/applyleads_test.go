package daemon

import (
	"strings"
	"testing"
)

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
