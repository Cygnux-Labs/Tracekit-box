//go:build image

package claudecode

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// The image's own Claude Code, run with a project whose settings try every way to keep the managed hooks from running
// (a shell prefix and a shell that are stubs, a PATH of stubs, BASH_ENV and ENV, bare mode, disableAllHooks, its own
// TRACEKIT_SIGNER and runtime dir, a hook of its own), still runs the managed hooks: SessionStart registers the hook's
// run with the signer on the pinned socket and keeps its state in the pinned runtime dir, and SessionEnd closes it.
// It runs with no API key and no network, so it makes no model call: Claude Code fires SessionStart, then stops at "Not
// logged in". It builds the image, so it needs docker (DOCKER_CONTEXT names the engine) and network for the build:
//
//	DOCKER_CONTEXT=colima-tkbox go test -tags image ./images/claude-code
func TestClaudeCodeRunsTheManagedHooksInAHostileProject(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found")
	}
	docker := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	const tag = "tkbox-claude-code:test"
	docker("build", "-q", "-t", tag, ".")
	id := strings.TrimSpace(docker("create", "--network", "none", "--user", "root", "--entrypoint", "/bin/sh", tag,
		"/check/sessionstart.sh"))
	defer exec.Command("docker", "rm", "-f", id).Run()
	docker("cp", "testdata/.", id+":/check")
	out := docker("start", "-a", id)
	t.Logf("%s", out)
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`check: claude said: Not logged in`), // it never reached the model
		regexp.MustCompile(`check: signer saw, in order: .*register_run .*close_run`),
		regexp.MustCompile(`check: the pinned runtime dir was made`),
		regexp.MustCompile(`check: /tmp/stub-ran absent`),
		regexp.MustCompile(`check: /tmp/project-hook-ran absent`),
		regexp.MustCompile(`check: /tmp/elsewhere absent`),
	} {
		if !want.MatchString(out) {
			t.Errorf("want %q", want)
		}
	}
}
