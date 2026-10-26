package daemon

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
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
