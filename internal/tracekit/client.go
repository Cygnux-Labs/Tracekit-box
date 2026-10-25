package tracekit

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"unicode/utf8"
)

// Field limits of the 1.4.2 request schemas (tracekit/signer/rpc_schema.py); lengths are in characters.
const (
	maxIDLen       = 128  // ID
	maxToolLen     = 256  // decide.tool
	maxReasonLen   = 1024 // REASON
	maxCloseReason = 256  // close_run.reason
	maxErrorLen    = 4096 // complete.error
	maxSourceLen   = 256  // observe.source
	maxAgentName   = 128
	maxAgentVer    = 64
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

func checkID(what, id string) error {
	if id == "" || len(id) > maxIDLen || !idPattern.MatchString(id) {
		return &RPCError{Code: "invalid_request", Message: fmt.Sprintf("%s %q must be 1-%d characters of "+
			"A-Z a-z 0-9 . _ : -; it was not sent", what, clip(id, 160), maxIDLen)}
	}
	return nil
}

func checkLen(what, s string, lo, hi int) error {
	if n := utf8.RuneCountInString(s); n < lo || n > hi {
		return &RPCError{Code: "invalid_request", Message: fmt.Sprintf("%s must be %d-%d characters, not %d; it "+
			"was not sent", what, lo, hi, n)}
	}
	return nil
}

// truncate cuts free text to n characters, as the signer would refuse it longer.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// Dial connects to the signer, checks its hello (protocol range must hold 19) and its status. Any failure is an
// *Unavailable (or an *Incompatible naming both versions): the caller fails closed. It never starts a signer.
func Dial(ctx context.Context, opts Options) (Client, error) {
	d, err := discoverSigner(opts)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	c0, h, err := dialSigner(ctx, d.path)
	if err == nil && d.source == sourceDev && h.DataDir != "" {
		// the per-user runtime dir's signer serves another HOME's data dir: this HOME's runs in the sibling dir
		if data, derr := devDataDir(); derr == nil && realPath(h.DataDir) != realPath(data) {
			c0.close()
			if d.alt == "" || privateDir(filepath.Dir(d.alt)) != nil {
				return nil, &Unavailable{Err: fmt.Errorf("the dev signer at %s serves another data dir (%s), and "+
					"this HOME's dev signer is not running; start it with `tracekit up`", d.path, h.DataDir)}
			}
			d.path = d.alt
			c0, _, err = dialSigner(ctx, d.path)
		}
	}
	if err != nil {
		return nil, err
	}
	c := &client{t: &transport{where: d.path, timeout: timeout}, source: d.source, stream: newID(),
		bin: opts.TracekitBin}
	c.t.put(c0)
	st, err := c.Status(ctx)
	if err != nil {
		c.Close()
		return nil, err
	}
	if st.RPCVersion != rpcVersion {
		c.Close()
		return nil, &Incompatible{Where: d.path, SignerVersion: st.SignerVersion, Proto: []int{st.RPCVersion,
			st.RPCVersion}}
	}
	return c, nil
}

type client struct {
	t      *transport
	source signerSource
	stream string // this client's event stream (one per process in the SDK)
	bin    string
}

func (c *client) Where() string { return c.t.where }

func (c *client) Close() error {
	c.t.close()
	return nil
}

func (c *client) call(ctx context.Context, method string, req map[string]any) (map[string]any, error) {
	frame, err := encodeFrame(method, req)
	if err != nil {
		return nil, err
	}
	return c.t.send(ctx, method, frame, false, 0)
}

func (c *client) Status(ctx context.Context) (Status, error) {
	m, err := c.call(ctx, "status", map[string]any{})
	if err != nil {
		return Status{}, err
	}
	var st Status
	v, ok := intOf(m["rpc_version"])
	signer, ok2 := m["signer"].(map[string]any)
	id, ok3 := m["identity"].(map[string]any)
	if !ok || !ok2 || !ok3 {
		return Status{}, badAnswer("status")
	}
	st.RPCVersion = int(v)
	st.SignerName, _ = signer["name"].(string)
	st.SignerVersion, _ = signer["version"].(string)
	scheme, _ := id["scheme"].(string)
	subject, _ := id["subject"].(string)
	st.Identity = scheme + ":" + subject
	st.Where = c.t.where
	return st, nil
}

func badAnswer(method string) error {
	return &Unavailable{Err: fmt.Errorf("the signer's answer to %s is not what protocol %d says", method, rpcVersion)}
}

func (c *client) NewRun(ctx context.Context, agent Agent) (Run, error) {
	if err := checkLen("agent name", agent.Name, 1, maxAgentName); err != nil {
		return nil, err
	}
	if err := checkLen("agent version", agent.Version, 0, maxAgentVer); err != nil {
		return nil, err
	}
	a := map[string]any{"name": agent.Name}
	if agent.Version != "" {
		a["version"] = agent.Version
	}
	m, err := c.call(ctx, "register_run", map[string]any{"request_id": newID(), "agent": a})
	if err != nil {
		return nil, err
	}
	id, _ := m["run_id"].(string)
	token, _ := m["run_token"].(string)
	if id == "" || token == "" {
		return nil, badAnswer("register_run")
	}
	return &run{c: c, id: id, token: token, turn: make(chan struct{}, 1)}, nil
}

// Gate runs the decide → (ask: approval_request, approval_wait until ctx ends) → approval_consume sequence of the
// 1.4.2 integrations (tracekit/integrations/gate.py). The caller runs the action only when Outcome.Allowed, then calls
// Run.Complete with Outcome.Decision. A signer that can't be reached refuses (fail closed); an unanswered approval is
// abandoned when ctx ends. err is set when Tracekit could not decide the call (the signer is unreachable or refused a
// step); the Outcome then refuses it, with the reason.
func Gate(ctx context.Context, r Run, call Call, hooks GateHooks) (Outcome, error) {
	d, err := r.Decide(ctx, call)
	if err != nil {
		return couldNotDecide(Decision{}, "", err), err
	}
	rules := namedRules(d.RuleIDs)
	if rules == "" {
		rules = d.Reason
	}
	if rules == "" {
		rules = d.Decision
	}
	switch d.Decision {
	case "deny":
		return Outcome{Decision: d, Reason: "blocked by Tracekit policy: " + rules, RuleIDs: d.RuleIDs}, nil
	case "allow", "ask":
	default:
		err := badAnswer("decide")
		return couldNotDecide(d, "", err), err
	}
	hint := ""
	if d.Decision == "ask" {
		id, err := r.RequestApproval(ctx, call, "")
		if err != nil {
			return couldNotDecide(d, "", err), err
		}
		hint = id
		if hooks.OnAsk != nil {
			hooks.OnAsk(id)
		}
		state := ApprovalRequested
		for state == ApprovalRequested && ctx.Err() == nil {
			s, err := r.WaitApproval(ctx, id, maxWait)
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					break // ctx ended: the approval is withdrawn below
				}
				// the call won't run, so no one may approve it: withdraw it (gate.py leaves it to expire)
				abandon(ctx, r, id, "Tracekit Box could not wait for the answer")
				return couldNotDecide(d, id, err), err
			}
			state = s
		}
		if state != ApprovalApproved {
			if state == ApprovalRequested { // unanswered: withdrawn, so no one approves a call that is gone
				abandon(ctx, r, id, "the box stopped waiting for an answer")
			}
			return Outcome{Decision: d, ApprovalID: id, RuleIDs: d.RuleIDs,
				Reason: fmt.Sprintf("held by Tracekit policy (%s) and not approved: %s", rules, state)}, nil
		}
	}
	c, err := r.Consume(ctx, call, hint)
	var mismatch *ArgsMismatch
	why := ""
	switch {
	case errors.As(err, &mismatch):
		c.OK = true
		why = "blocked by Tracekit: the arguments the signer approved are not the call's"
	case err != nil: // as RunHandle.approval_consume: a consume that fails is a refused one
		c = Consume{Reason: truncate("approval_consume failed: "+err.Error(), maxReasonLen)}
	}
	if why == "" && !c.OK {
		reason := c.Reason
		if reason == "" {
			reason = rules
		}
		why = "blocked by Tracekit policy: " + reason
	}
	if why != "" {
		// an allowed call (or a consumed approval) left open would read as a result sent before it was recorded; an
		// ask whose consume was refused stays open: completing it would sign it as run without an approval
		if c.OK || d.Decision != "ask" {
			cctx, cancel := afterCtx(ctx)
			_ = r.Complete(cctx, call, d, "error", truncate("not run: "+why, maxErrorLen))
			cancel()
		}
		ids := c.RuleIDs
		if len(ids) == 0 {
			ids = d.RuleIDs
		}
		return Outcome{Decision: d, ApprovalID: hint, Reason: why, RuleIDs: ids}, nil
	}
	approval := c.ApprovalID
	if approval == "" {
		approval = hint
	}
	return Outcome{Allowed: true, Decision: d, ApprovalID: approval}, nil
}

func couldNotDecide(d Decision, approvalID string, err error) Outcome {
	return Outcome{Decision: d, ApprovalID: approvalID,
		Reason: truncate("refused: Tracekit could not decide it ("+err.Error()+")", maxErrorLen)}
}

// afterCtx is a context for the clean-up calls a gate makes after ctx may have ended.
func afterCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), defaultTimeout)
}

func abandon(ctx context.Context, r Run, id, reason string) {
	actx, cancel := afterCtx(ctx)
	defer cancel()
	_ = r.Abandon(actx, id, reason) // else it expires with the run
}

// namedRules is sdk.client.named_rules: TK-UNKNOWN-TOOL only flags a tool the policy doesn't name, it never refuses.
func namedRules(ids []string) string {
	out := ""
	for _, r := range ids {
		if r == "TK-UNKNOWN-TOOL" {
			continue
		}
		if out != "" {
			out += ", "
		}
		out += r
	}
	return out
}

// ArgsMismatch is Run.Consume's error when the signer consumed the approval but the arguments it approved (its own
// copy, a T2 approval) are not the call's: the call must not run. The Consume returned with it has OK set.
type ArgsMismatch struct{}

func (*ArgsMismatch) Error() string {
	return "the arguments the signer approved are not the call's"
}
