package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/config"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// execSession is one exec stream; it receives notices (egress refusals, approvals to give) for the person.
type execSession struct {
	notices chan string
}

// notice tells every exec stream of the box something the person should see on stderr.
func (b *box) notice(msg string) {
	msg = b.scrub().str(msg)
	b.mu.Lock()
	defer b.mu.Unlock()
	for s := range b.sessions {
		select {
		case s.notices <- msg:
		default: // a stuck client never blocks the proxy
		}
	}
}

var signalNames = map[string]bool{"SIGINT": true, "SIGTERM": true, "SIGKILL": true, "SIGHUP": true, "SIGQUIT": true}

// prepareExec checks an exec request before the connection is upgraded, so a refusal is a plain JSON error.
func (d *Daemon) prepareExec(ref string, req api.ExecRequest) (*box, *api.ErrorDetail) {
	b, err := d.lookup(ref)
	if err != nil {
		return nil, asAPIError(err)
	}
	switch st := b.state(); st {
	case api.StateRunning:
	case api.StatePaused:
		return nil, errf(api.CodeConflict, "the signer holds this run; ask whoever owns the incident in Tracekit", "box %s is paused", ref)
	default:
		return nil, errf(api.CodeConflict, "start a new box with `tkbox run`", "box %s is %s", ref, st)
	}
	if len(req.Argv) == 0 || req.Argv[0] == "" {
		return nil, errf(api.CodeBadRequest, "pass the command after --, e.g. `tkbox exec box -- ls -la`", "no command")
	}
	for _, a := range req.Argv {
		if strings.ContainsRune(a, 0) {
			return nil, errf(api.CodeBadRequest, "", "an argument has a NUL byte")
		}
	}
	for k, v := range req.Env {
		if !envNameRE.MatchString(k) || strings.ContainsRune(v, 0) {
			return nil, errf(api.CodeBadRequest, "", "env %q is not a valid KEY=VALUE", k)
		}
		if reservedEnv[k] {
			return nil, errf(api.CodeBadRequest, "every connection goes through the box's proxy", "env %s is set by the box and can't be overridden", k)
		}
	}
	if req.Cwd != "" && !strings.HasPrefix(req.Cwd, "/") {
		return nil, errf(api.CodeBadRequest, "", "cwd %q must be an absolute path in the box", req.Cwd)
	}
	if t := time.Duration(req.Timeout); t < 0 || t > config.MaxExecTimeout {
		return nil, limitErr("exec timeout %s is outside 1s..24h", "pass --timeout up to 24h", t)
	}
	return b, nil
}

// frameWriter serialises frames from several goroutines; each Write is one whole frame (proto.WriteFrame).
type frameWriter struct {
	mu  sync.Mutex
	w   io.Writer
	err error
}

func (f *frameWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	n, err := f.w.Write(p)
	if err != nil {
		f.err = err
	}
	return n, err
}

func (f *frameWriter) event(e api.ExecEvent) error { return proto.WriteJSON(f, proto.TypeJSON, e) }


// runExec runs one exec on an upgraded connection: decide (Bash) → maybe wait for a Tracekit approval → run in the
// guest, streaming stdio both ways → complete with the exit status.
func (b *box) runExec(parent context.Context, r io.Reader, w io.Writer, req api.ExecRequest) {
	fw := &frameWriter{w: w}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	go func() {
		select {
		case <-b.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	sess := &execSession{notices: make(chan string, 64)}
	b.mu.Lock()
	b.sessions[sess] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.sessions, sess)
		b.mu.Unlock()
	}()
	pumpCtx, stopPump := context.WithCancel(ctx)
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		for {
			select {
			case m := <-sess.notices:
				fw.event(api.ExecEvent{State: api.ExecNotice, Message: m})
			case <-pumpCtx.Done():
				return
			}
		}
	}()
	// final frames go out after the pump stops, so nothing follows TypeExit/TypeError
	final := func(typ byte, v any) {
		stopPump()
		<-pumpDone
		proto.WriteJSON(fw, typ, v)
	}

	// client → daemon: stdin, stdin EOF, signals; a closed connection cancels the exec
	stdinR, stdinW := io.Pipe()
	defer stdinR.Close()
	sigs := make(chan string, 8)
	go func() {
		for {
			f, err := proto.ReadFrame(r)
			if err != nil {
				stdinW.CloseWithError(io.ErrUnexpectedEOF)
				cancel()
				return
			}
			switch f.Type {
			case proto.TypeStdin:
				if req.Stdin {
					stdinW.Write(f.Payload) // an error means the process stopped reading; drop the rest
				}
			case proto.TypeStdinEOF:
				stdinW.Close()
			case proto.TypeSignal:
				var s proto.Signal
				if f.Decode(&s) == nil && signalNames[s.Signal] {
					select {
					case sigs <- s.Signal:
					default:
					}
				}
			}
		}
	}()

	b.mu.Lock()
	run, g := b.run, b.guest
	timeout := time.Duration(b.info.Limits.ExecTimeout)
	b.mu.Unlock()
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout)
	}
	line := tracekit.ShellQuote(req.Argv)
	fw.event(api.ExecEvent{State: api.ExecDeciding})
	var call tracekit.Call
	var dec tracekit.Decision
	if run != nil {
		call = tracekit.Call{ID: b.nextCallID("exec"), Tool: tracekit.ToolBash, Args: tracekit.BashArgs(req.Argv)}
		out, err := b.d.opts.Gate(ctx, run, call, tracekit.GateHooks{OnAsk: func(id string) {
			fw.event(api.ExecEvent{State: api.ExecWaitingApproval, Decision: "ask", ApprovalID: id, Approver: "tracekit",
				Message: "approve with: tracekit approvals approve " + id})
		}})
		if err != nil {
			b.event(api.EventExecDecided, "exec", "exec refused, the signer did not answer: "+line,
				map[string]any{"command": line, "decision": "deny", "reason": err.Error()})
			final(proto.TypeError, api.ErrorDetail{Code: api.CodeUnavailable,
				Message: "the Tracekit signer did not answer, so nothing runs (fail closed): " + err.Error(),
				Hint:    "check the signer with `tracekit status` (start it with `tracekit up`), then run the command again"})
			return
		}
		if !out.Allowed {
			reason := out.Reason
			if reason == "" {
				reason = "refused by the Tracekit signer"
			}
			b.event(api.EventExecDecided, "exec", "exec denied: "+line,
				map[string]any{"command": line, "decision": "deny", "rule_ids": out.RuleIDs, "reason": reason})
			fw.event(api.ExecEvent{State: api.ExecDeciding, Decision: "deny", RuleIDs: out.RuleIDs, Message: reason})
			hint := "the signer's policy refused this command; run something it allows, or change the policy in Tracekit"
			if out.ApprovalID != "" {
				hint = "the approval " + out.ApprovalID + " was not given; ask again and approve with `tracekit approvals approve <id>`"
			}
			final(proto.TypeError, api.ErrorDetail{Code: api.CodeDenied, Message: "denied: " + reason, RuleIDs: out.RuleIDs, Hint: hint})
			return
		}
		dec = out.Decision
	}
	b.event(api.EventExecDecided, "exec", "exec allowed: "+line,
		map[string]any{"command": line, "decision": "allow", "rule_ids": dec.RuleIDs, "decision_id": nonEmpty(dec.DecisionID)})
	if g == nil {
		final(proto.TypeError, api.ErrorDetail{Code: api.CodeConflict, Message: "the box is not running",
			Hint: "start a new box with `tkbox run`"})
		return
	}
	b.mu.Lock()
	b.info.Execs++
	b.mu.Unlock()
	b.persist()
	msg := ""
	if run == nil {
		msg = "unrecorded: this command is not recorded in Tracekit"
	}
	fw.event(api.ExecEvent{State: api.ExecRunning, Decision: "allow", RuleIDs: dec.RuleIDs, Message: msg})

	env := make([]string, 0, len(req.Env))
	for k, v := range req.Env {
		env = append(env, k+"="+v)
	}
	sort.Strings(env)
	preq := proto.ExecRequest{Op: proto.OpExec, Argv: req.Argv, Env: env, Cwd: req.Cwd,
		TimeoutMS: timeout.Milliseconds(), Stdin: req.Stdin}
	stdio := agentrpc.ExecIO{Stdout: proto.ChunkWriter{W: fw, Type: proto.TypeStdout},
		Stderr: proto.ChunkWriter{W: fw, Type: proto.TypeStderr}, Signals: sigs}
	if req.Stdin {
		stdio.Stdin = stdinR
	}
	ectx, ecancel := context.WithTimeout(ctx, timeout+30*time.Second) // host backstop; the guest enforces timeout
	st, err := g.Exec(ectx, preq, stdio)
	ecancel()
	complete := func(status string, result any) {
		if run == nil {
			return
		}
		cctx, cancel := context.WithTimeout(b.d.ctx, 30*time.Second)
		defer cancel()
		if err := run.Complete(cctx, call, dec, status, result); err != nil {
			b.event(api.EventSignerProblem, "exec", "complete failed: "+err.Error(), nil)
		}
	}
	if err != nil {
		code, m, hint := api.CodeInternal, err.Error(), "read the box's console.log and events (`tkbox ls` shows the box state)"
		var pe *proto.Error
		switch {
		case errors.As(err, &pe):
			code, m = pe.Code, pe.Message
			if pe.Code == proto.CodeBusy {
				hint = fmt.Sprintf("at most %d commands run at once in a box; wait for one to finish", proto.DefaultMaxProcs)
			}
		case isClosed(b.stopCh):
			code, m, hint = api.CodeConflict, "the box stopped while the command ran", "see why with `tkbox ls`; start a new box with `tkbox run`"
		case errors.Is(ectx.Err(), context.DeadlineExceeded):
			code, m, hint = api.CodeTimeout, fmt.Sprintf("the command did not finish within %s", timeout), "pass a longer --timeout (up to 24h)"
		}
		complete("error", map[string]any{"error": m})
		b.event(api.EventExecExited, "exec", "exec failed: "+m, map[string]any{"command": line, "error": m})
		final(proto.TypeError, api.ErrorDetail{Code: code, Message: m, Hint: hint})
		return
	}
	status := "ok"
	if st.Code != 0 {
		status = "error"
	}
	result := map[string]any{"exit_code": st.Code, "signal": st.Signal, "timed_out": st.TimedOut, "duration_ms": st.DurationMS}
	complete(status, result)
	b.event(api.EventExecExited, "exec", fmt.Sprintf("exec exited %d: %s", st.Code, line), map[string]any{"command": line,
		"exit_code": st.Code, "signal": st.Signal, "timed_out": st.TimedOut, "duration_ms": st.DurationMS})
	final(proto.TypeExit, st)
}

func nonEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
