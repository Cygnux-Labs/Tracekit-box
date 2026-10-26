package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/config"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// N3: a command stopped because it did not take its stdin is a tkbox error (125) with a message, never a success.
func TestStdinTruncatedExit(t *testing.T) {
	var b strings.Builder
	code := execExitCode(proto.ExitStatus{Code: -1, Signal: "SIGKILL", StdinTruncated: true, StdinDroppedBytes: 1234}, nil, &cliEnv{stderr: &b})
	if code != exitTkbox || !strings.Contains(b.String(), "tkbox: stdin was not consumed fast enough (1234 bytes dropped); the command was stopped: write large input to a file in /workspace and read it from there") {
		t.Fatalf("exit %d, stderr %q", code, b.String())
	}
}

// S3: a limit the operator's config leaves unset is the daemon's default for tkbox_run and tkbox_exec, never the
// global maximum; a set one caps them.
func TestMCPLimitsNarrowOnly(t *testing.T) {
	s := &mcpServer{c: newClient(filepath.Join(t.TempDir(), "none.sock")), images: []string{"alpine:3"}}
	for _, c := range []struct {
		base *config.File
		args mcpRunArgs
		want string // "" = allowed
	}{
		{nil, mcpRunArgs{CPUs: 3}, "cpus 3 is over the operator's 2"},
		{&config.File{}, mcpRunArgs{CPUs: 32}, "cpus 32 is over the operator's 2"},
		{&config.File{}, mcpRunArgs{Memory: "4GiB"}, "memory 4GiB is over the operator's 2048MiB"},
		{&config.File{}, mcpRunArgs{Timeout: "2h"}, "timeout 2h is over the operator's 1h0m0s"},
		{&config.File{}, mcpRunArgs{CPUs: 2, Memory: "1GiB", Timeout: "30m"}, ""},
		{&config.File{Limits: config.Limits{CPUs: 4, Timeout: config.Duration(3 * time.Hour)}}, mcpRunArgs{CPUs: 4, Timeout: "3h"}, ""},
		{&config.File{Limits: config.Limits{CPUs: 4}}, mcpRunArgs{CPUs: 5}, "cpus 5 is over the operator's 4"},
	} {
		s.base = c.base
		_, err := s.runRequest(c.args)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%+v: refused: %v", c.args, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%+v: want %q, got %v", c.args, c.want, err)
		}
	}
	execArgs := func(timeout string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"box": "b", "argv": []string{"true"}, "timeout": timeout})
		return b
	}
	s.base = &config.File{}
	s.owned = map[string]string{"tkb-00000000000b": "b"} // as if this session's tkbox_run had created box b
	if _, _, err := s.call(context.Background(), "tkbox_exec", execArgs("1h")); err == nil || !strings.Contains(err.Error(), "over the operator's exec timeout 30m0s") {
		t.Fatalf("exec timeout over the default: %v", err)
	}
	s.base = &config.File{Limits: config.Limits{ExecTimeout: config.Duration(2 * time.Hour)}}
	if _, _, err := s.call(context.Background(), "tkbox_exec", execArgs("1h")); err != nil {
		t.Fatalf("exec timeout under the config's: refused: %v", err)
	}
	if _, _, err := s.call(context.Background(), "tkbox_exec", execArgs("3h")); err == nil || !strings.Contains(err.Error(), "exec timeout 2h0m0s") {
		t.Fatalf("exec timeout over the config's: %v", err)
	}
}

// S3: the workspace a box gets is the resolved path that was checked against the roots, never the symlink.
func TestMCPWorkspaceResolved(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	outside, _ := filepath.EvalSymlinks(t.TempDir())
	real := filepath.Join(root, "proj")
	os.Mkdir(real, 0o755)
	links := t.TempDir()
	in := filepath.Join(links, "in")  // outside the root, pointing in
	out := filepath.Join(root, "out") // inside the root, pointing out
	os.Symlink(real, in)
	os.Symlink(outside, out)
	s := &mcpServer{images: []string{"alpine:3"}, roots: []string{root}, base: &config.File{}}
	req, err := s.runRequest(mcpRunArgs{Workspace: in})
	if err != nil || req.Workspace != real {
		t.Fatalf("symlink into the root: workspace %q, %v", req.Workspace, err)
	}
	if _, err := s.runRequest(mcpRunArgs{Workspace: out}); err == nil || !strings.Contains(err.Error(), "outside the dirs the operator allows") {
		t.Fatalf("symlink out of the root: %v", err)
	}
	if _, err := s.runRequest(mcpRunArgs{Workspace: outside}); err == nil {
		t.Fatal("a dir outside the roots was allowed")
	}
}
