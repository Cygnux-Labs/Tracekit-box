package tracekit

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestRealSigner runs against a real Tracekit 1.4.2 signer: TKBOX_SIGNER_TESTS=1, with a dev signer up
// (`tracekit init --dev --v2 --no-hooks && tracekit up`) or TRACEKIT_SIGNER naming one, and `tracekit` in PATH.
// Every complete must be accepted (no args_mismatch): that proves the Go JCS args digest.
func TestRealSigner(t *testing.T) {
	if os.Getenv("TKBOX_SIGNER_TESTS") != "1" {
		t.Skip("set TKBOX_SIGNER_TESTS=1 with a Tracekit 1.4.2 signer running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c, err := Dial(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("signer %s %s at %s, identity %s, protocol %d", st.SignerName, st.SignerVersion, c.Where(), st.Identity,
		st.RPCVersion)
	r, err := c.NewRun(ctx, Agent{Name: "tkbox-test", Version: "0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("run %s", r.ID())
	if err := r.Observe(ctx, SourceTask, "trusted", map[string]any{"task": "integration test", "emoji": "✓🎉"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Observe(ctx, SourceBox, "trusted", map[string]any{"box_id": "b-test", "limits": map[string]any{
		"cpus": 2, "memory_mib": 2048, "ratio": 0.5}}); err != nil {
		t.Fatal(err)
	}

	gate := func(call Call, hooks GateHooks) Outcome {
		t.Helper()
		out, err := Gate(ctx, r, call, hooks)
		if err != nil {
			t.Fatalf("gate %s %v: %v", call.Tool, call.Args, err)
		}
		t.Logf("%s %v: %s allowed=%v rules=%v reason=%q", call.Tool, call.Args, out.Decision.Decision, out.Allowed,
			out.Decision.RuleIDs, out.Reason)
		return out
	}
	complete := func(call Call, out Outcome, result any) {
		t.Helper()
		if err := r.Complete(ctx, call, out.Decision, "ok", result); err != nil {
			t.Fatalf("complete %s: %v", call.ID, err) // args_mismatch here means the JCS digest is wrong
		}
	}

	ls := Call{ID: "call-ls", Tool: ToolBash, Args: BashArgs([]string{"ls", "-la", "/workspace"})}
	out := gate(ls, GateHooks{})
	if !out.Allowed {
		t.Fatalf("ls refused: %+v", out)
	}
	complete(ls, out, map[string]any{"exit_code": 0, "stdout_bytes": 120, "note": "naïve ✓   <tag>"})

	kill := Call{ID: "call-kill", Tool: ToolBash, Args: BashArgs([]string{"pkill", "tracekitd"})}
	out = gate(kill, GateHooks{})
	if out.Allowed || !slices.Contains(out.RuleIDs, "TK-D007") ||
		!strings.HasPrefix(out.Reason, "blocked by Tracekit policy: ") {
		t.Fatalf("pkill tracekitd: %+v", out)
	}

	fetch := Call{ID: "call-pypi", Tool: ToolWebFetch, Args: WebFetchArgs("https://pypi.org:443")}
	out = gate(fetch, GateHooks{})
	if !out.Allowed {
		t.Fatalf("pypi refused: %+v", out)
	}
	complete(fetch, out, map[string]any{"status": 200, "bytes": 5120})

	// a command the shell parser can't read is an ask; the test answers it as the person would
	odd := Call{ID: "call-ask", Tool: ToolBash, Args: map[string]any{"command": `echo "unterminated`}}
	bin := os.Getenv("TRACEKIT_BIN")
	if bin == "" {
		bin = "tracekit"
	}
	approved := make(chan error, 1)
	out = gate(odd, GateHooks{OnAsk: func(id string) {
		t.Logf("approval %s pending: tracekit approvals --signer %s approve %s", id, c.Where(), id)
		go func() {
			b, err := exec.CommandContext(ctx, bin, "approvals", "--signer", c.Where(), "approve", id).CombinedOutput()
			if err != nil {
				err = errors.New(err.Error() + ": " + string(b))
			}
			t.Logf("approve: %s", strings.TrimSpace(string(b)))
			approved <- err
		}()
	}})
	if out.Decision.Decision != "ask" {
		t.Fatalf("unparseable command: %+v (want an ask)", out)
	}
	if err := <-approved; err != nil {
		t.Fatal(err)
	}
	if !out.Allowed || out.ApprovalID == "" {
		t.Fatalf("approved ask refused: %+v", out)
	}
	complete(odd, out, map[string]any{"exit_code": 2})

	cont, err := r.Contained(ctx)
	if err != nil || cont.Contained || r.(*run).readFrom < 10 {
		t.Fatalf("contained %+v %v (read up to run_seq %d)", cont, err, r.(*run).readFrom)
	}
	if err := r.Observe(ctx, SourceApproval, "trusted", map[string]any{"approval_id": out.ApprovalID,
		"target": "Bash", "decision": "approve", "approver": st.Identity}); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(ctx, "box stopped"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	bundle, trust := filepath.Join(dir, "run.tkb"), filepath.Join(dir, "run.trust.json")
	start := time.Now()
	if err := c.Export(ctx, r.ID(), bundle, trust); err != nil {
		t.Fatal(err)
	}
	t.Logf("exported in %s: tracekit verify %s --trust %s", time.Since(start).Round(time.Millisecond), bundle, trust)
	b, err := exec.CommandContext(ctx, bin, "verify", bundle, "--trust", trust).CombinedOutput()
	t.Logf("verify:\n%s", b)
	if err != nil || !strings.Contains(string(b), "Integrity: VERIFIED.") {
		t.Fatalf("verify: %v", err)
	}
}
