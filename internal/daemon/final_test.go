package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/image"
)

// B1 (final check): the workspace build gets the box's secret values, and a workspace file that holds one refuses
// the box (the from_file next to tkbox.yaml under `workspace: .`): the value never enters the VM.
func TestFinalSecretInWorkspaceRefusesBox(t *testing.T) {
	const val = "ghp_finalcheck0123456789"
	e := newTestEnv(t, nil)
	ws := t.TempDir()
	os.WriteFile(filepath.Join(ws, "key.txt"), []byte(val), 0o600)
	e.builder.WorkspaceErr = &image.SecretInWorkspaceError{Path: "key.txt", Secret: "GH"}
	_, err := e.d.Create(context.Background(), api.CreateBoxRequest{Name: "ws", Image: "python:3.12-slim", Workspace: ws,
		Secrets: map[string]api.SecretSpec{"GH": {Value: val, Hosts: []string{"api.github.com"}}}})
	if errCode(err) != api.CodeBadRequest || !strings.Contains(err.Error(), "workspace file key.txt holds the value of secret GH, so the box was not started") ||
		strings.Contains(err.Error(), val) {
		t.Fatalf("a workspace holding a secret's value: %v", err)
	}
	if got := e.builder.WorkspaceSecrets; len(got) != 1 || !slices.Contains(got[0], image.SecretValue{Name: "GH", Value: val}) {
		t.Fatalf("the workspace build was given %v", got)
	}
	if len(e.launcher.Machines) != 0 {
		t.Fatal("a VM was started")
	}
}

// L8 (final check): the sensitive names SECURITY.md lists, which only `--allow-sensitive` applies, at any depth.
func TestFinalSensitiveNames(t *testing.T) {
	for _, p := range []string{".gitattributes", ".gitmodules", "tkbox.yaml", "tkbox.yml", ".envrc", ".pre-commit-config.yaml",
		".husky/pre-commit", "sub/.gitattributes", "svc/tkbox.yaml", "app/.envrc", "web/.husky/_/husky.sh", "lib/.gitmodules"} {
		if !isSensitive(p) {
			t.Errorf("isSensitive(%q) = false", p)
		}
	}
	for _, p := range []string{"gitattributes.md", "tkbox.yaml.example", "husky/pre-commit", "envrc"} {
		if isSensitive(p) {
			t.Errorf("isSensitive(%q) = true", p)
		}
	}
}

// L8 (final check): a deletion removes only a file or a symlink. A directory that took the deleted file's place
// stays (with what is in it), and a symlink goes as a link: its target is left alone.
func TestFinalDeletionRemovesOnlyAFileOrSymlink(t *testing.T) {
	dir, scratch := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(dir, "d", "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "d", "sub", "keep.txt"), []byte("keep"), 0o644)
	target := t.TempDir()
	os.WriteFile(filepath.Join(target, "t.txt"), []byte("target"), 0o644)
	os.Symlink(target, filepath.Join(dir, "link"))
	os.WriteFile(filepath.Join(dir, "f.txt"), []byte("gone"), 0o644)

	if err := writeResult(dir, scratch, "d", fileState{deleted: true}); err == nil || !strings.Contains(err.Error(), "is not a file or a symlink, so it is not deleted") {
		t.Fatalf("deleting a directory: %v", err)
	}
	if readFile(t, filepath.Join(dir, "d", "sub", "keep.txt")) != "keep" {
		t.Fatal("the directory's content went")
	}
	os.Mkdir(filepath.Join(dir, "empty"), 0o755) // os.Remove alone would take this one
	if err := writeResult(dir, scratch, "empty", fileState{deleted: true}); err == nil {
		t.Fatal("an empty directory was deleted")
	}
	if fi, err := os.Lstat(filepath.Join(dir, "empty")); err != nil || !fi.IsDir() {
		t.Fatalf("the empty directory: %v", err)
	}
	for _, p := range []string{"link", "f.txt"} {
		if err := writeResult(dir, scratch, p, fileState{deleted: true}); err != nil {
			t.Fatalf("deleting %s: %v", p, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, p)); err == nil {
			t.Fatalf("%s is still there", p)
		}
	}
	if readFile(t, filepath.Join(target, "t.txt")) != "target" {
		t.Fatal("a symlink's target went with it")
	}
}

// Info (final check): when the secrets' values together hold every printable ASCII character JSON writes as it is
// (several strong random passwords can), the filler that keeps a rebuilt value out of a record is a non-ASCII
// character none of whose bytes a value holds, not a control byte JSON would write as \u00XX.
func TestFinalScrubberFillStaysPlainInJSON(t *testing.T) {
	var all strings.Builder
	for c := byte('!'); c <= '~'; c++ {
		all.WriteByte(c)
	}
	ph, _ := egress.NewPlaceholder("S")
	// every printable character, starting with ]; then also the first non-ASCII filler
	for _, value := range []string{"]" + all.String(), "]" + all.String() + "·"} {
		secrets := []egress.Secret{{Name: "S", Placeholder: ph, Value: value}}
		b := &box{secrets: secrets}
		text := value + value[1:] // the tag's "]" and the rest rebuild the value
		for what, out := range map[string]string{"scrubber": newScrubber(secrets).str(text), "decision": b.redactor()(text)} {
			js, _ := json.Marshal(out)
			if strings.Contains(out, value) || strings.Contains(string(js), `\u00`) || !utf8.ValidString(out) {
				t.Errorf("%s: %q, as JSON %s", what, out, js)
			}
		}
	}
}
