package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// R3 (verify5): no tracked text file holds a bidi control (U+202A–U+202E, U+2066–U+2069), which can make source or
// docs read differently from what a compiler or shell sees. Write one as an escape (‮) instead.
func TestNoBidiControlsInTrackedFiles(t *testing.T) {
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not in a git checkout: %v", err)
	}
	root := strings.TrimSpace(string(top))
	list, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range strings.Split(strings.TrimRight(string(list), "\x00"), "\x00") {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0 {
			continue // gone from the work tree, or binary
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.ContainsFunc(line, func(r rune) bool { return r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 }) {
				t.Errorf("%s:%d holds a bidi control character; write it as an escape", name, i+1)
			}
		}
	}
}
