package tracekit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// run is one registered run. Its run token is a capability: it never goes into an error, a log line or String().
type run struct {
	c     *client
	id    string
	token string

	// turn is held from taking a client_seq to that event's answer, so a run's events reach the signer in client_seq
	// order on every retry (sdk/client.py _turn). next and closed are guarded by it.
	turn   chan struct{}
	next   uint64
	closed bool

	cmu         sync.Mutex // containment state, read from the run's records
	readFrom    uint64
	held        []string
	quarantined string
	reason      string
}

func (r *run) ID() string       { return r.id }
func (r *run) String() string   { return "tracekit run " + r.id }
func (r *run) GoString() string { return r.String() }

func (r *run) takeTurn(ctx context.Context) error {
	t := time.NewTimer(r.c.t.timeout)
	defer t.Stop()
	select {
	case r.turn <- struct{}{}:
		return nil
	case <-ctx.Done():
		return &Unavailable{Err: fmt.Errorf("run %s: %w", r.id, ctx.Err())}
	case <-t.C:
		return &Unavailable{Err: fmt.Errorf("no answer from the signer in time: run %s's previous event is still "+
			"unanswered", r.id)}
	}
}

func (r *run) dropTurn() { <-r.turn }

// event sends an event call (decide, complete, observe) with this run's next client_seq.
func (r *run) event(ctx context.Context, method string, req map[string]any) (map[string]any, error) {
	if err := r.takeTurn(ctx); err != nil {
		return nil, err
	}
	defer r.dropTurn()
	req["request_id"] = newID()
	req["run_id"], req["run_token"] = r.id, r.token
	req["stream"], req["client_seq"] = r.c.stream, r.next
	frame, err := encodeFrame(method, req)
	if err != nil {
		return nil, err // refused before sending: no client_seq used
	}
	r.next++ // used even when no answer comes: the signer writes a gap for one it never received
	return r.c.t.send(ctx, method, frame, false, 0)
}

// perRun sends a per-run call that is not an event.
func (r *run) perRun(ctx context.Context, method string, req map[string]any, requestID, own bool, wait time.Duration) (map[string]any, error) {
	if requestID {
		req["request_id"] = newID()
	}
	req["run_id"], req["run_token"] = r.id, r.token
	frame, err := encodeFrame(method, req)
	if err != nil {
		return nil, err
	}
	return r.c.t.send(ctx, method, frame, own, wait)
}

func checkCall(call Call) error {
	if err := checkID("tool_call_id", call.ID); err != nil {
		return err
	}
	if call.Attempt < 0 {
		return &RPCError{Code: "invalid_request", Message: "attempt must not be negative; it was not sent"}
	}
	return checkLen("tool", call.Tool, 1, maxToolLen)
}

func (r *run) Decide(ctx context.Context, call Call) (Decision, error) {
	if err := checkCall(call); err != nil {
		return Decision{}, err
	}
	m, err := r.event(ctx, "decide", map[string]any{"tool_call_id": call.ID, "attempt": call.Attempt,
		"tool": call.Tool, "args_source": "parsed", "args": argsValue(call.Args)})
	if err != nil {
		return Decision{}, err
	}
	var d Decision
	d.Decision, _ = m["decision"].(string)
	d.DecisionID, _ = m["decision_id"].(string)
	if (d.Decision != "allow" && d.Decision != "deny" && d.Decision != "ask") || d.DecisionID == "" {
		return Decision{}, badAnswer("decide")
	}
	d.RuleIDs = stringList(m["rule_ids"])
	d.Reason, _ = m["reason"].(string)
	if n, ok := intOf(m["run_seq"]); ok && n >= 0 {
		d.RunSeq = uint64(n)
	}
	d.IncidentID, _ = m["incident_id"].(string)
	d.SendResult, _ = m["send_result"].(bool)
	return d, nil
}

func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (r *run) RequestApproval(ctx context.Context, call Call, reason string) (string, error) {
	if err := checkCall(call); err != nil {
		return "", err
	}
	req := map[string]any{"tool_call_id": call.ID, "attempt": call.Attempt}
	if reason != "" {
		req["reason"] = truncate(reason, maxReasonLen)
	}
	m, err := r.perRun(ctx, "approval_request", req, true, false, 0)
	if err != nil {
		return "", err
	}
	id, _ := m["approval_id"].(string)
	if id == "" {
		return "", badAnswer("approval_request")
	}
	return id, nil
}

// WaitApproval does one approval_wait of up to timeout (capped at the signer's 300s), on a connection of its own.
func (r *run) WaitApproval(ctx context.Context, approvalID string, timeout time.Duration) (string, error) {
	if err := checkID("approval_id", approvalID); err != nil {
		return "", err
	}
	timeout = min(max(timeout, 0), maxWait)
	m, err := r.perRun(ctx, "approval_wait", map[string]any{"approval_id": approvalID,
		"timeout_ms": timeout.Milliseconds()}, false, true, timeout)
	if err != nil {
		return "", err
	}
	state, _ := m["state"].(string)
	switch state {
	case ApprovalRequested, ApprovalApproved, ApprovalRejected, ApprovalExpired, ApprovalConsumed:
		return state, nil
	}
	return "", badAnswer("approval_wait")
}

// Consume calls approval_consume. When the signer consumed the approval but approved other arguments than the call's
// (its own copy, a T2 approval), it returns the Consume (OK set) with *ArgsMismatch: the call must not run.
func (r *run) Consume(ctx context.Context, call Call, approvalHint string) (Consume, error) {
	if err := checkCall(call); err != nil {
		return Consume{}, err
	}
	args := argsValue(call.Args)
	req := map[string]any{"tool_call_id": call.ID, "attempt": call.Attempt, "tool": call.Tool,
		"args_source": "parsed", "args": args}
	if approvalHint != "" {
		if err := checkID("approval_id_hint", approvalHint); err != nil {
			return Consume{}, err
		}
		req["approval_id_hint"] = approvalHint
	}
	m, err := r.perRun(ctx, "approval_consume", req, true, false, 0)
	if err != nil {
		return Consume{}, err
	}
	ok, isBool := m["ok"].(bool)
	if !isBool {
		return Consume{}, badAnswer("approval_consume")
	}
	c := Consume{OK: ok, RuleIDs: stringList(m["rule_ids"])}
	c.ApprovalID, _ = m["approval_id"].(string)
	c.Reason, _ = m["reason"].(string)
	if approved, has := m["args"]; has && ok {
		a, err1 := Canonical(approved)
		b, err2 := Canonical(args)
		if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
			return c, &ArgsMismatch{}
		}
	}
	return c, nil
}

func (r *run) Abandon(ctx context.Context, approvalID, reason string) error {
	if err := checkID("approval_id", approvalID); err != nil {
		return err
	}
	req := map[string]any{"approval_id": approvalID}
	if reason != "" {
		req["reason"] = truncate(reason, maxReasonLen)
	}
	_, err := r.perRun(ctx, "approval_abandon", req, true, false, 0)
	return err
}

// Complete records the outcome of a call that ran. status is "ok" or "error"; with "error" a string result goes as
// complete's `error` text. Any other result goes as itself when the decision asked for it (SendResult) and its
// canonical JSON fits half a frame, else as its digest (sdk.client.result_field).
func (r *run) Complete(ctx context.Context, call Call, d Decision, status string, result any) error {
	if err := checkCall(call); err != nil {
		return err
	}
	if status != "ok" && status != "error" {
		return &RPCError{Code: "invalid_request", Message: fmt.Sprintf("status must be ok or error, not %q; it was "+
			"not sent", clip(status, 32))}
	}
	if err := checkID("decision_id", d.DecisionID); err != nil {
		return err
	}
	digest, err := ArgsDigest(call.Tool, call.Args)
	if err != nil {
		return &RPCError{Code: "invalid_request", Message: "args_digest: " + err.Error() + "; it was not sent"}
	}
	req := map[string]any{"tool_call_id": call.ID, "attempt": call.Attempt, "decision_id": d.DecisionID,
		"args_digest": digest, "status": status}
	if s, isStr := result.(string); isStr && status == "error" {
		req["error"] = truncate(strings.ToValidUTF8(s, "�"), maxErrorLen)
	} else if result != nil {
		req["result"] = resultField(d.SendResult, result)
	}
	_, err = r.event(ctx, "complete", req)
	return err
}

// resultField is what complete carries as `result`: the result itself when sent and it fits half a frame (room for
// the other fields), else its digest; a value JCS can't encode goes as the digest of its JSON text.
func resultField(send bool, out any) any {
	c, err := Canonical(out)
	if err != nil {
		raw, jerr := json.Marshal(out)
		text := string(raw)
		if jerr != nil {
			text = strings.ToValidUTF8(fmt.Sprintf("%v", out), "�")
		}
		h, _ := EventHash(text)
		return h
	}
	if send && len(c) <= maxLine/2 {
		if _, err := canonical(out, true); err == nil { // a frame carries it as the signer reads it back
			return json.RawMessage(c)
		}
	}
	sum := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *run) Observe(ctx context.Context, source, trust string, value any) error {
	if err := checkLen("observe source", source, 1, maxSourceLen); err != nil {
		return err
	}
	if trust != "trusted" && trust != "untrusted" {
		return &RPCError{Code: "invalid_request", Message: fmt.Sprintf("trust must be trusted or untrusted, not "+
			"%q; it was not sent", clip(trust, 32))}
	}
	_, err := r.event(ctx, "observe", map[string]any{"source": source, "trust": trust, "value": value})
	return err
}

// Contained reads the run's new records (`read`, a default grant of the run's owner, which writes nothing) and
// follows its containment: run.held adds a hold, run.resumed leaves the holds its held_by names, run.quarantined (or a
// run.closing with reason quarantine) is final. These records are written in the same signer step that contains the
// run, so a poll sees a hold or quarantine as soon as it is in force, including an operator's run_hold or
// run_quarantine, which no decision of the run would show until its next call.
func (r *run) Contained(ctx context.Context) (Containment, error) {
	r.cmu.Lock()
	defer r.cmu.Unlock()
	for {
		m, err := r.perRun(ctx, "read", map[string]any{"from_seq": r.readFrom, "limit": 1000}, false, false, 0)
		if err != nil {
			return Containment{}, err
		}
		events, ok := m["events"].([]any)
		if !ok {
			return Containment{}, badAnswer("read")
		}
		for _, x := range events {
			e, _ := x.(map[string]any)
			seq, ok := intOf(e["run_seq"])
			if !ok || seq < 0 {
				return Containment{}, badAnswer("read")
			}
			typ, _ := e["type"].(string)
			data, _ := e["data"].(map[string]any)
			iid, _ := data["incident_id"].(string)
			switch typ {
			case "run.held":
				if !containsStr(r.held, iid) {
					r.held = append(r.held, iid)
				}
				r.reason, _ = data["reason"].(string)
			case "run.resumed":
				r.held = stringList(data["held_by"])
			case "run.quarantined":
				if r.quarantined == "" {
					r.quarantined = iid
					r.reason, _ = data["reason"].(string)
				}
			case "run.closing":
				if why, _ := data["reason"].(string); why == "quarantine" && r.quarantined == "" {
					r.quarantined = "unknown"
				}
			}
			r.readFrom = uint64(seq) + 1
		}
		next, more := intOf(m["next_seq"])
		if !more {
			break
		}
		if next < 0 || uint64(next) < r.readFrom {
			return Containment{}, badAnswer("read")
		}
		r.readFrom = uint64(next)
	}
	switch {
	case r.quarantined != "":
		return Containment{Contained: true, State: "quarantined", IncidentID: r.quarantined, Reason: r.reason}, nil
	case len(r.held) > 0:
		return Containment{Contained: true, State: "held", IncidentID: r.held[0], Reason: r.reason}, nil
	}
	return Containment{}, nil
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Close calls close_run once every event of the run is answered, with the last client_seq this stream used (one the
// signer never received becomes its client_counter_gap). A run the signer closed already (a quarantine) is closed.
func (r *run) Close(ctx context.Context, reason string) error {
	if err := r.takeTurn(ctx); err != nil {
		return err
	}
	defer r.dropTurn()
	if r.closed {
		return nil
	}
	req := map[string]any{}
	if reason != "" {
		req["reason"] = truncate(reason, maxCloseReason)
	}
	if r.next > 0 {
		req["last_client_seq"] = []any{map[string]any{"stream": r.c.stream, "client_seq": r.next - 1}}
	}
	_, err := r.perRun(ctx, "close_run", req, true, false, 0)
	var rpc *RPCError
	if err == nil || errors.As(err, &rpc) && rpc.Code == "run_closed" {
		r.closed = true
		return nil
	}
	return err
}
