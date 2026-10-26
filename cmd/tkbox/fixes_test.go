package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// C8: every Linux signal maps to 128+n.
func TestSignalExitCodes(t *testing.T) {
	env := &cliEnv{stderr: io.Discard}
	for name, want := range map[string]int{"SIGHUP": 129, "SIGKILL": 137, "SIGTERM": 143, "SIGCHLD": 145, "SIGWINCH": 156,
		"SIGSYS": 159, "SIGRTMIN": 162, "SIGRTMIN+3": 165, "SIGRTMAX": 192, "SIGRTMAX-2": 190, "signal 40": 168} {
		if got := execExitCode(proto.ExitStatus{Code: -1, Signal: name}, nil, env); got != want {
			t.Errorf("%s: exit %d, want %d", name, got, want)
		}
	}
	notFound := &api.ErrorDetail{Code: api.CodeNotFound, Message: "start nope: executable not found in PATH"}
	if got := execExitCode(proto.ExitStatus{}, notFound, env); got != exitNotFound {
		t.Errorf("not found: %d", got)
	}
	if got := execExitCode(proto.ExitStatus{}, &api.ErrorDetail{Code: api.CodeCancelled, Message: "cancelled"}, env); got != exitTkbox {
		t.Errorf("cancelled: %d", got)
	}
	if got := execExitCode(proto.ExitStatus{}, errors.New("boom"), env); got != exitTkbox {
		t.Errorf("error: %d", got)
	}
}

// S10: control characters from the box never reach a terminal raw.
func TestSanitize(t *testing.T) {
	in := "ok\tline\n\x1b[2J\x1b]0;evil\x07\rgone \u202e\u0085"
	out := sanitize(in)
	if strings.ContainsAny(out, "\x1b\x07\r\u202e\u0085") || !strings.Contains(out, "ok\tline\n") || !strings.Contains(out, `\x1b[2J`) {
		t.Fatalf("sanitize: %q", out)
	}
}

// The denial line names its rules once.
func TestPrintErrRulesOnce(t *testing.T) {
	var b strings.Builder
	printErr(&b, &api.ErrorDetail{Code: api.CodeDenied, Message: "denied by Tracekit policy [TK-D002]: destructive", RuleIDs: []string{"TK-D002"}})
	if strings.Count(b.String(), "TK-D002") != 1 {
		t.Fatalf("%q", b.String())
	}
}

// P2: an auto-loaded tkbox.yaml is announced, --no-config skips it, and run validates before creating.
func TestRunConfigNotice(t *testing.T) {
	sock, fd := startFakeDaemon(t)
	dir := t.TempDir()
	t.Chdir(dir)
	os.WriteFile(filepath.Join(dir, "tkbox.yaml"), []byte("image: python:3.12-slim\n"), 0o600)
	code, _, errs := run(t, "", "run", "--socket", sock)
	if code != 0 || !strings.Contains(errs, "reading settings from ./tkbox.yaml") {
		t.Fatalf("auto-load: %d %q", code, errs)
	}
	if n := len(fd.created); n != 2 || !fd.created[0].ValidateOnly || fd.created[1].ValidateOnly {
		t.Fatalf("want a validate-only request first: %+v", fd.created)
	}
	code, _, errs = run(t, "", "run", "--socket", sock, "--no-config")
	if code == 0 || strings.Contains(errs, "reading settings") || !strings.Contains(errs, "no image") {
		t.Fatalf("--no-config: %d %q", code, errs)
	}
	if code, _, _ := run(t, "", "run", "--socket", sock, "--cpus", "x"); code != 2 {
		t.Fatalf("bad flag exit %d", code)
	}
}
