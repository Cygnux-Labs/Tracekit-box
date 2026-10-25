package daemon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// Approval states.
const (
	approvalPending   = "pending"
	approvalApproved  = "approved"
	approvalRejected  = "rejected"
	approvalExpired   = "expired"
	approvalWithdrawn = "withdrawn" // no connection waited on it any more
)

// maxPendingApprovals caps the Box approvals one box may hold open at once.
const maxPendingApprovals = 16

// approval is a Box approval: an egress host off the allowlist, held until a person answers on the host.
type approval struct {
	api.Approval // guarded by Daemon.mu
	box          *box
	hostPort     string
	scope        string
	decided      chan struct{}
	timer        *time.Timer
	recordErr    error // the decision could not be recorded in Tracekit: an approval then allows nothing
}

// boxDecider is the egress.Decider of one box.
type boxDecider box

// Decide asks the signer (WebFetch), then the allowlist, then a person. Every refusal says what to do.
func (bd *boxDecider) Decide(ctx context.Context, req egress.Request) (egress.Verdict, error) {
	b := (*box)(bd)
	b.calls.begin()
	defer b.calls.end()
	b.mu.Lock()
	run := b.run
	b.mu.Unlock()
	var call tracekit.Call
	var dec tracekit.Decision
	if run != nil {
		call = tracekit.Call{ID: b.nextCallID("egress"), Tool: tracekit.ToolWebFetch, Args: tracekit.WebFetchArgs(req.URL)}
		out, err := b.d.opts.Gate(ctx, run, call, tracekit.GateHooks{OnAsk: func(id string) {
			b.notice(fmt.Sprintf("egress to %s is waiting for a Tracekit approval: run `tracekit approvals approve %s` on the host", req.URL, id))
		}})
		if err != nil {
			return egress.Verdict{Reason: "the Tracekit signer did not answer, so nothing leaves the box (fail closed): " + err.Error()}, nil
		}
		if !out.Allowed {
			msg, _ := denial(out)
			return egress.Verdict{Reason: msg, RuleIDs: out.RuleIDs}, nil
		}
		dec = out.Decision
	}
	complete := func(status string, result map[string]any) {
		if run == nil {
			return
		}
		cctx, cancel := context.WithTimeout(b.d.ctx, 30*time.Second)
		defer cancel()
		if err := run.Complete(cctx, call, dec, status, result); err != nil {
			b.event(api.EventSignerProblem, "egress", "complete failed: "+err.Error(), nil)
		}
	}
	hostPort := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
	if req.OnAllowlist {
		complete("ok", map[string]any{"allowed": true, "via": "allowlist"})
		return egress.Verdict{Allow: true, Reason: "on the allowlist"}, nil
	}
	b.mu.Lock()
	ok := b.approvedHosts[hostPort]
	b.mu.Unlock()
	if ok {
		complete("ok", map[string]any{"allowed": true, "via": "approval", "scope": "box"})
		return egress.Verdict{Allow: true, Reason: "approved for this box"}, nil
	}
	allowHint := req.Host
	if req.Port != 80 && req.Port != 443 {
		allowHint = hostPort
	}
	state, id, recErr := b.d.awaitApproval(ctx, b, req, hostPort)
	switch {
	case state == approvalApproved && recErr != nil:
		complete("error", map[string]any{"allowed": false, "approval_id": id, "decision": "unrecorded"})
		return egress.Verdict{Reason: fmt.Sprintf("the approval %s could not be recorded in Tracekit, so egress to %s stays closed (fail closed): %v", id, req.URL, recErr)}, nil
	case state == approvalApproved:
		complete("ok", map[string]any{"allowed": true, "via": "approval", "approval_id": id})
		return egress.Verdict{Allow: true, Reason: "approved by a person (" + id + ")"}, nil
	case state == approvalRejected:
		complete("error", map[string]any{"allowed": false, "approval_id": id, "decision": approvalRejected})
		return egress.Verdict{Reason: fmt.Sprintf("a person rejected egress to %s (%s); to allow it next time start the box with `--allow %s`", req.URL, id, allowHint)}, nil
	case state == approvalLimit:
		complete("error", map[string]any{"allowed": false, "decision": "too many pending approvals"})
		return egress.Verdict{Reason: fmt.Sprintf("too many pending approvals in this box (%d): egress to %s refused at once; answer the pending ones with `tkbox approvals`, or start the box with `--allow %s`", maxPendingApprovals, req.URL, allowHint)}, nil
	default:
		complete("error", map[string]any{"allowed": false, "approval_id": id, "decision": state})
		return egress.Verdict{Reason: fmt.Sprintf("no one approved egress to %s within %s (%s): approve it for this box with `tkbox approve <id> --box`; next time start the box with `--allow %s`",
			req.URL, b.d.opts.ApprovalTimeout, id, allowHint)}, nil
	}
}

// approvalLimit is awaitApproval's answer when the box already holds maxPendingApprovals.
const approvalLimit = "limit"

// awaitApproval opens (or joins) the pending approval for req's target and waits for its answer. A connection that
// gives up first gets "expired"; when no connection waits on an approval any more it is withdrawn, so no one
// approves a connection that is gone. recErr is set when an approval could not be recorded in Tracekit.
func (d *Daemon) awaitApproval(ctx context.Context, b *box, req egress.Request, hostPort string) (string, string, error) {
	d.mu.Lock()
	var a *approval
	pending := 0
	for _, x := range d.approvals {
		if x.box == b && x.State == approvalPending {
			pending++
			if x.Target == req.URL {
				a = x
			}
		}
	}
	created := false
	if a == nil {
		select {
		case <-b.stopCh:
			d.mu.Unlock()
			return approvalExpired, "", nil
		default:
		}
		if pending >= maxPendingApprovals {
			d.mu.Unlock()
			return approvalLimit, "", nil
		}
		d.pruneApprovals()
		id := ""
		for id == "" || d.approvals[id] != nil {
			id = "apr-" + randHex(4)
		}
		now := d.now().UTC()
		a = &approval{Approval: api.Approval{ID: id, BoxID: b.id, BoxName: b.name(), Kind: "egress", Target: req.URL,
			State: approvalPending, CreatedAt: now, ExpiresAt: now.Add(d.opts.ApprovalTimeout)},
			box: b, hostPort: hostPort, decided: make(chan struct{})}
		a.timer = time.AfterFunc(d.opts.ApprovalTimeout, func() { d.finish(a, approvalExpired, "", "") })
		d.approvals[id] = a
		created = true
	}
	a.Waiters++
	id := a.ID
	d.mu.Unlock()
	if created {
		allowHint := req.Host
		if req.Port != 80 && req.Port != 443 {
			allowHint = hostPort
		}
		b.event(api.EventApproval, "egress", fmt.Sprintf("egress to %s is waiting for approval %s", req.URL, id),
			map[string]any{"approval_id": id, "target": req.URL, "state": approvalPending})
		b.notice(fmt.Sprintf("egress to %s is waiting for approval: run `tkbox approve %s` on the host (add --box to allow it for the rest of the box); next time start the box with `--allow %s`",
			req.URL, id, allowHint))
	}
	select {
	case <-a.decided:
		d.mu.Lock()
		a.Waiters--
		st, recErr := a.State, a.recordErr
		d.mu.Unlock()
		return st, id, recErr
	case <-ctx.Done():
		d.mu.Lock()
		a.Waiters--
		last := a.Waiters == 0 && a.State == approvalPending
		d.mu.Unlock()
		if last {
			d.finish(a, approvalWithdrawn, "", "")
		}
		return approvalExpired, id, nil
	}
}

// finish records an approval's answer once: approved, rejected, expired or withdrawn. An approval is recorded in
// Tracekit before any connection is let through on it; if that fails it allows nothing.
func (d *Daemon) finish(a *approval, state, by, scope string) bool {
	d.mu.Lock()
	if a.State != approvalPending {
		d.mu.Unlock()
		return false
	}
	a.State = state
	a.DecidedBy = by
	a.scope = scope
	if a.timer != nil {
		a.timer.Stop()
	}
	view := a.Approval
	d.mu.Unlock()
	b := a.box
	value := map[string]any{"approval_id": view.ID, "target": view.Target, "decision": state, "approver": by, "scope": scope}
	var recErr error
	if state == approvalApproved {
		b.mu.Lock()
		run := b.run
		b.mu.Unlock()
		if run != nil {
			ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
			recErr = run.Observe(ctx, tracekit.SourceApproval, trustedObs, b.scrub().value(value))
			cancel()
		}
		if recErr == nil && scope == "box" {
			b.mu.Lock()
			b.approvedHosts[a.hostPort] = true
			b.mu.Unlock()
		}
	} else {
		b.observe(tracekit.SourceApproval, trustedObs, value)
	}
	d.mu.Lock()
	a.recordErr = recErr
	close(a.decided)
	d.mu.Unlock()
	summary := fmt.Sprintf("approval %s for %s: %s", view.ID, view.Target, state)
	if by != "" {
		summary += " by " + by
	}
	data := map[string]any{"approval_id": view.ID, "target": view.Target, "state": state, "decided_by": by, "scope": scope}
	if recErr != nil {
		summary += " (NOT recorded in Tracekit, so it allows nothing: " + recErr.Error() + ")"
		data["record_error"] = recErr.Error()
	}
	b.event(api.EventApproval, "egress", summary, data)
	switch state {
	case approvalExpired:
		b.notice(fmt.Sprintf("approval %s for %s expired after %s", view.ID, view.Target, d.opts.ApprovalTimeout))
	case approvalWithdrawn:
		b.notice(fmt.Sprintf("approval %s for %s was withdrawn: no connection waits for it any more", view.ID, view.Target))
	}
	return true
}

// pruneApprovals drops answered approvals older than an hour (caller holds d.mu).
func (d *Daemon) pruneApprovals() {
	cut := d.now().Add(-time.Hour)
	for id, a := range d.approvals {
		if a.State != approvalPending && a.CreatedAt.Before(cut) {
			delete(d.approvals, id)
		}
	}
}

// expireApprovals ends a box's pending approvals (the box is going down).
func (d *Daemon) expireApprovals(boxID, reason string) {
	d.mu.Lock()
	var pend []*approval
	for _, a := range d.approvals {
		if a.BoxID == boxID && a.State == approvalPending {
			pend = append(pend, a)
		}
	}
	d.mu.Unlock()
	for _, a := range pend {
		d.finish(a, approvalExpired, "", "")
	}
}

// Approvals lists the pending Box approvals of every box, oldest first.
func (d *Daemon) Approvals() []api.Approval {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []api.Approval{}
	for _, a := range d.approvals {
		if a.State == approvalPending {
			out = append(out, a.Approval)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// DecideApproval answers a Box approval for the API caller uid.
func (d *Daemon) DecideApproval(id string, dec api.ApprovalDecision, uid int) (api.Approval, error) {
	d.mu.Lock()
	a := d.approvals[id]
	d.mu.Unlock()
	if a == nil {
		return api.Approval{}, errf(api.CodeNotFound, "list pending approvals with `tkbox approvals`", "no approval %q", id)
	}
	var state string
	switch strings.ToLower(dec.Decision) {
	case "approve", "approved", "allow":
		state = approvalApproved
	case "reject", "rejected", "deny":
		state = approvalRejected
	default:
		return api.Approval{}, errf(api.CodeBadRequest, "use `tkbox approve <id>` or `tkbox reject <id>`", "decision %q: use \"approve\" or \"reject\"", dec.Decision)
	}
	scope := dec.Scope
	switch scope {
	case "", "once":
		scope = "once"
	case "box":
		if state != approvalApproved {
			return api.Approval{}, errf(api.CodeBadRequest, "drop --box when rejecting", "scope \"box\" only applies to approve")
		}
	default:
		return api.Approval{}, errf(api.CodeBadRequest, "approve once (default) or for the rest of the box with --box", "scope %q: use \"once\" or \"box\"", dec.Scope)
	}
	if !d.finish(a, state, "uid:"+strconv.Itoa(uid), scope) {
		d.mu.Lock()
		st := a.State
		d.mu.Unlock()
		return api.Approval{}, errf(api.CodeConflict, "list what is still pending with `tkbox approvals`", "approval %s is already %s", id, st)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if a.recordErr != nil {
		return api.Approval{}, errf(api.CodeUnavailable, "check the signer (`tracekit status`); the connection stays closed",
			"approval %s could not be recorded in Tracekit, so it allows nothing: %v", id, a.recordErr)
	}
	return a.Approval, nil
}

// boxSink is the egress.Sink of one box: events.ndjson, Tracekit observes and notices to running execs.
type boxSink box

func (s *boxSink) Emit(e egress.Event) {
	b := (*box)(s)
	target := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	data := map[string]any{"host": e.Host, "port": e.Port}
	if e.Method != "" {
		data["method"] = e.Method
	}
	if e.Path != "" {
		data["path"] = e.Path
	}
	if e.Status != 0 {
		data["status"] = e.Status
	}
	if e.BytesIn != 0 || e.BytesOut != 0 {
		data["bytes_in"], data["bytes_out"] = e.BytesIn, e.BytesOut
	}
	if e.Secret != "" {
		data["secret"] = e.Secret
	}
	if e.Reason != "" {
		data["reason"] = e.Reason
	}
	if len(e.RuleIDs) > 0 {
		data["rule_ids"] = e.RuleIDs
	}
	switch e.Kind {
	case egress.EventAllowed:
		b.event(e.Kind, "egress", "egress to "+target+" allowed", data)
	case egress.EventClosed:
		b.event(e.Kind, "egress", fmt.Sprintf("egress to %s closed (%d bytes in, %d out)", target, e.BytesIn, e.BytesOut), data)
		if e.Reason != "" && e.BytesIn == 0 && e.BytesOut == 0 {
			b.notice("egress to " + target + " failed: " + e.Reason) // e.g. the host did not answer (502)
		}
	case egress.EventDenied:
		b.event(e.Kind, "egress", "egress to "+target+" refused: "+e.Reason, data)
		msg := "egress to " + target + " refused: " + e.Reason
		if len(e.RuleIDs) > 0 {
			if !strings.Contains(e.Reason, e.RuleIDs[0]) {
				msg += " [" + strings.Join(e.RuleIDs, ", ") + "]"
			}
		} else {
			// the signer recorded its own refusals; record the ones Box made itself
			b.observe(tracekit.SourceEgress, untrustedObs, map[string]any{"host": e.Host, "port": e.Port,
				"decision": "deny", "reason": e.Reason})
		}
		b.notice(msg)
	case egress.EventSecretUse:
		b.event(e.Kind, "secret", fmt.Sprintf("secret %s sent to %s", e.Secret, e.Host), data)
		b.observe(tracekit.SourceSecretUse, untrustedObs, map[string]any{"name": e.Secret, "host": e.Host})
	case egress.EventSecretLeak:
		b.event(e.Kind, "secret", fmt.Sprintf("blocked secret %s headed to %s: %s", e.Secret, e.Host, e.Reason), data)
		b.observe(tracekit.SourceSecretLeak, untrustedObs, map[string]any{"name": e.Secret, "host": e.Host, "reason": e.Reason})
		b.notice(fmt.Sprintf("blocked: secret %s was headed to %s (%s); it may only go to its bound hosts", e.Secret, e.Host, e.Reason))
	case egress.EventModelCall:
		b.event(e.Kind, "model", fmt.Sprintf("model call %s %s%s → %d", e.Method, e.Host, e.Path, e.Status), data)
		b.observe(tracekit.SourceModelCall, untrustedObs, map[string]any{"host": e.Host, "path": e.Path,
			"status": e.Status, "bytes": e.BytesIn + e.BytesOut})
	default:
		b.event(e.Kind, "egress", e.Kind+" "+target, data)
	}
}
