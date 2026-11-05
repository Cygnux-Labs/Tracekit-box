// Package claudecode tests the Claude Code image's managed settings.
package claudecode

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

type settings struct {
	Env   map[string]string `json:"env"`
	Hooks map[string][]struct {
		Hooks []struct {
			Command string `json:"command"`
		} `json:"hooks"`
	} `json:"hooks"`
}

// The managed hooks run what the image installed, whatever a project's or the user's settings put on PATH: a stub
// python3 or grep that exits 0 would let every call through unrecorded.
func TestHooksRunWhatTheImageInstalled(t *testing.T) {
	data, err := os.ReadFile("managed-settings.json")
	if err != nil {
		t.Fatal(err)
	}
	var s settings
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	// what the hooks, sh and the dynamic loader read from the environment: a project's or the user's settings could
	// otherwise load code into them (LD_*, GCONV_PATH), point them at other files (LOCPATH, NLSPATH), move the hook's
	// state (TRACEKIT_RUNTIME_DIR) or make it wait (TRACEKIT_APPROVAL_WAIT); and what Claude Code runs every hook and
	// command through (CLAUDE_CODE_SHELL_PREFIX: empty is none; CLAUDE_CODE_SHELL: the image's bash, so no stub is picked
	// up from SHELL either)
	want := map[string]string{"TRACEKIT_SIGNER": "/run/tkbox/signer.sock",
		"PATH":       "/opt/tracekit/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LD_PRELOAD": "", "LD_LIBRARY_PATH": "", "LD_AUDIT": "", "GCONV_PATH": "", "LOCPATH": "", "NLSPATH": "",
		"TRACEKIT_RUNTIME_DIR": "/home/agent/.tracekit/run", "TRACEKIT_APPROVAL_WAIT": "0",
		"CLAUDE_CODE_SHELL_PREFIX": "", "CLAUDE_CODE_SHELL": "/bin/bash"}
	for k, v := range want {
		if got, ok := s.Env[k]; !ok || got != v {
			t.Errorf("managed env %s = %q, want %q", k, got, v)
		}
	}
	bare := regexp.MustCompile(`(^|[^/\w])(python3?|grep)\b`)
	commands := map[string]string{}
	for event, groups := range s.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if bare.MatchString(h.Command) {
					t.Errorf("%s runs a program by name, not by path: %s", event, h.Command)
				}
				commands[event] = h.Command
			}
		}
	}
	if len(commands) != 9 {
		t.Fatalf("%d hook events, want 9", len(commands))
	}

	if _, err := os.Stat("/opt/tracekit/bin/python3"); err == nil {
		t.Skip("this host has /opt/tracekit/bin/python3: the hooks would run it")
	}
	stubs, ran := t.TempDir(), filepath.Join(t.TempDir(), "ran")
	for _, name := range []string{"python3", "grep"} {
		if err := os.WriteFile(filepath.Join(stubs, name), []byte("#!/bin/sh\ntouch "+ran+"\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for event, command := range commands {
		c := exec.Command("/bin/sh", "-c", command)
		c.Env = []string{"PATH=" + stubs}
		err := c.Run()
		if _, serr := os.Stat(ran); serr == nil {
			t.Fatalf("%s ran a program from PATH", event)
		}
		if ee, ok := err.(*exec.ExitError); event == "PreToolUse" && (!ok || ee.ExitCode() != 2) {
			t.Fatalf("PreToolUse with no hook client: %v, want exit 2 (blocked)", err)
		}
	}
}
