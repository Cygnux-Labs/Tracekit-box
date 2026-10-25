package tracekit

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func gateFake(t *testing.T) (*fakeSigner, *run) {
	t.Helper()
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 0)
	return f, newFakeRun(t, c)
}

func methods(f *fakeSigner) []string {
	var out []string
	for _, g := range f.all() {
		if g.method != "register_run" && g.method != "status" {
			out = append(out, g.method)
		}
	}
	return out
}

func sameMethods(t *testing.T, f *fakeSigner, want ...string) {
	t.Helper()
	if got := methods(f); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("methods %v, want %v", got, want)
	}
}

var lsCall = Call{ID: "c1", Tool: ToolBash, Args: BashArgs([]string{"ls"})}

func TestGateAllow(t *testing.T) {
	f, r := gateFake(t)
	out, err := Gate(context.Background(), r, lsCall, GateHooks{})
	if err != nil || !out.Allowed || out.Decision.DecisionID != "d-c1" {
		t.Fatalf("%+v %v", out, err)
	}
	sameMethods(t, f, "decide", "approval_consume")
	if _, ok := f.received("approval_consume")[0].req["approval_id_hint"]; ok {
		t.Fatal("hint without an approval")
	}
}

func TestGateDeny(t *testing.T) {
	f, r := gateFake(t)
	f.handle = func(conn int, req map[string]any) any {
		if req["method"] == "decide" {
			return map[string]any{"decision": "deny", "decision_id": "d1", "rule_ids": []any{"TK-UNKNOWN-TOOL",
				"TK-D007"}, "reason": "touching Tracekit", "run_seq": 3}
		}
		return f.standard(conn, req)
	}
	out, err := Gate(context.Background(), r, lsCall, GateHooks{})
	if err != nil || out.Allowed || out.Reason != "blocked by Tracekit policy: TK-D007" ||
		strings.Join(out.RuleIDs, ",") != "TK-UNKNOWN-TOOL,TK-D007" {
		t.Fatalf("%+v %v", out, err)
	}
	sameMethods(t, f, "decide")
}

func askHandler(f *fakeSigner, states []string, consume map[string]any) func(int, map[string]any) any {
	var waits atomic.Int32
	return func(conn int, req map[string]any) any {
		switch req["method"] {
		case "decide":
			return map[string]any{"decision": "ask", "decision_id": "d1", "rule_ids": []any{"TK-A001"},
				"run_seq": 3}
		case "approval_wait":
			n := int(waits.Add(1)) - 1
			if n >= len(states) {
				n = len(states) - 1
			}
			if states[n] == "hang" {
				return hangConn{}
			}
			return map[string]any{"approval_id": req["approval_id"], "state": states[n]}
		case "approval_consume":
			if consume != nil {
				return consume
			}
		}
		return f.standard(conn, req)
	}
}

func TestGateAskApproved(t *testing.T) {
	f, r := gateFake(t)
	f.handle = askHandler(f, []string{"requested", "requested", "approved"}, nil)
	var asked string
	out, err := Gate(context.Background(), r, lsCall, GateHooks{OnAsk: func(id string) { asked = id }})
	if err != nil || !out.Allowed || out.ApprovalID != "appr-1" || asked != "appr-1" {
		t.Fatalf("%+v %v asked=%q", out, err, asked)
	}
	sameMethods(t, f, "decide", "approval_request", "approval_wait", "approval_wait", "approval_wait",
		"approval_consume")
	if f.received("approval_consume")[0].req["approval_id_hint"] != "appr-1" {
		t.Fatal("consume without the approval's hint")
	}
}

func TestGateAskRejected(t *testing.T) {
	f, r := gateFake(t)
	f.handle = askHandler(f, []string{"rejected"}, nil)
	out, err := Gate(context.Background(), r, lsCall, GateHooks{})
	if err != nil || out.Allowed || out.Reason != "held by Tracekit policy (TK-A001) and not approved: rejected" {
		t.Fatalf("%+v %v", out, err)
	}
	sameMethods(t, f, "decide", "approval_request", "approval_wait")
}

func TestGateAskAbandonedWhenCtxEnds(t *testing.T) {
	f, r := gateFake(t)
	f.handle = askHandler(f, []string{"hang"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	out, err := Gate(ctx, r, lsCall, GateHooks{})
	if err != nil || out.Allowed || !strings.HasSuffix(out.Reason, "not approved: requested") {
		t.Fatalf("%+v %v", out, err)
	}
	sameMethods(t, f, "decide", "approval_request", "approval_wait", "approval_abandon")
	if f.received("approval_abandon")[0].req["approval_id"] != "appr-1" {
		t.Fatal("abandoned another approval")
	}
}

func TestGateConsumeRefused(t *testing.T) {
	refused := map[string]any{"ok": false, "rule_ids": []any{"TK-HOLD"}, "reason": "held"}
	// an allowed call whose consume is refused is completed as error
	f, r := gateFake(t)
	f.handle = func(conn int, req map[string]any) any {
		if req["method"] == "approval_consume" {
			return refused
		}
		return f.standard(conn, req)
	}
	out, err := Gate(context.Background(), r, lsCall, GateHooks{})
	if err != nil || out.Allowed || out.Reason != "blocked by Tracekit policy: held" || out.RuleIDs[0] != "TK-HOLD" {
		t.Fatalf("%+v %v", out, err)
	}
	sameMethods(t, f, "decide", "approval_consume", "complete")
	cp := f.received("complete")[0].req
	if cp["status"] != "error" || cp["error"] != "not run: blocked by Tracekit policy: held" {
		t.Fatalf("complete %v", cp)
	}
	// an approved ask whose consume is refused stays open
	f, r = gateFake(t)
	f.handle = askHandler(f, []string{"approved"}, refused)
	out, err = Gate(context.Background(), r, lsCall, GateHooks{})
	if err != nil || out.Allowed {
		t.Fatalf("%+v %v", out, err)
	}
	sameMethods(t, f, "decide", "approval_request", "approval_wait", "approval_consume")
}

func TestGateArgsMismatch(t *testing.T) {
	f, r := gateFake(t)
	f.handle = askHandler(f, []string{"approved"}, map[string]any{"ok": true, "rule_ids": []any{},
		"approval_id": "appr-1", "args": map[string]any{"command": "rm -rf /"}})
	out, err := Gate(context.Background(), r, lsCall, GateHooks{})
	if err != nil || out.Allowed || !strings.Contains(out.Reason, "approved are not the call's") {
		t.Fatalf("%+v %v", out, err)
	}
	sameMethods(t, f, "decide", "approval_request", "approval_wait", "approval_consume", "complete")
	// the same args (another key order, 1 vs 1.0) are a match
	f, r = gateFake(t)
	call := Call{ID: "c1", Tool: "X", Args: map[string]any{"a": 1, "b": "x"}}
	f.handle = askHandler(f, []string{"approved"}, map[string]any{"ok": true, "rule_ids": []any{},
		"args": map[string]any{"b": "x", "a": 1.0}})
	if out, err := Gate(context.Background(), r, call, GateHooks{}); err != nil || !out.Allowed {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestGateUnavailableRefuses(t *testing.T) {
	f, r := gateFake(t)
	f.handle = func(conn int, req map[string]any) any { return dropConn{} }
	out, err := Gate(context.Background(), r, lsCall, GateHooks{})
	var u *Unavailable
	if out.Allowed || !errors.As(err, &u) || !strings.HasPrefix(out.Reason, "refused: Tracekit could not decide") {
		t.Fatalf("%+v %v", out, err)
	}
	// consume unreachable after an allow: refused, never allowed
	f, r = gateFake(t)
	f.handle = func(conn int, req map[string]any) any {
		if req["method"] == "approval_consume" {
			return dropConn{}
		}
		return f.standard(conn, req)
	}
	out, err = Gate(context.Background(), r, lsCall, GateHooks{})
	if out.Allowed || !strings.Contains(out.Reason, "approval_consume failed") {
		t.Fatalf("%+v %v", out, err)
	}
	// a wait that fails withdraws the approval
	f, r = gateFake(t)
	h := askHandler(f, []string{"approved"}, nil)
	f.handle = func(conn int, req map[string]any) any {
		if req["method"] == "approval_wait" {
			return dropConn{}
		}
		return h(conn, req)
	}
	out, err = Gate(context.Background(), r, lsCall, GateHooks{})
	if out.Allowed || !errors.As(err, &u) {
		t.Fatalf("%+v %v", out, err)
	}
	if len(f.received("approval_abandon")) != 1 || len(f.received("approval_consume")) != 0 {
		t.Fatalf("methods %v", methods(f))
	}
}
