package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// waitPending waits until the daemon lists n pending approvals.
func waitPending(t *testing.T, d *Daemon, n int) []api.Approval {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a := d.Approvals(); len(a) == n {
			return a
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pending approvals: %v, want %d", d.Approvals(), n)
	return nil
}

func TestDecider(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.ApprovalTimeout = 2 * time.Second })
	e.create(api.CreateBoxRequest{Name: "eg", Allow: []string{"pypi.org"}})
	dec := e.proxy(0).cfg.Decider
	ctx := context.Background()
	r := egress.Request{Scheme: "https", Host: "pypi.org", Port: 443, URL: "https://pypi.org:443", OnAllowlist: true}

	// allowlisted: WebFetch decided, completed ok, no approval
	v, err := dec.Decide(ctx, r)
	if err != nil || !v.Allow {
		t.Fatalf("allowlisted %+v %v", v, err)
	}
	run := e.tk.Runs[0]
	m := run.Methods()
	if m[len(m)-2] != "decide" || m[len(m)-1] != "complete" {
		t.Fatalf("methods %v", m)
	}

	// signer refuses: denied with its rules, no approval opened
	e.tk.DecideFunc = func(c tracekit.Call) tracekit.Decision {
		if c.Tool == tracekit.ToolWebFetch && c.Args["url"] == "https://pypi.org:443" {
			return tracekit.Decision{Decision: "deny", RuleIDs: []string{"TK-N001"}, Reason: "no package installs"}
		}
		return tracekit.Decision{Decision: "allow"}
	}
	v, _ = dec.Decide(ctx, r)
	if v.Allow || v.RuleIDs[0] != "TK-N001" || v.Reason != "denied by Tracekit policy [TK-N001]: no package installs" || len(e.d.Approvals()) != 0 {
		t.Fatalf("signer deny %+v", v)
	}
	e.tk.DecideFunc = nil

	// off the allowlist: a Box approval, approved once by uid 501
	off := egress.Request{Scheme: "https", Host: "example.com", Port: 443, URL: "https://example.com:443"}
	got := make(chan egress.Verdict, 1)
	go func() { v, _ := dec.Decide(ctx, off); got <- v }()
	pend := waitPending(t, e.d, 1)
	a := pend[0]
	if a.Kind != "egress" || a.Target != off.URL || a.BoxName != "eg" || a.State != "pending" || !strings.HasPrefix(a.ID, "apr-") ||
		a.ExpiresAt.Sub(a.CreatedAt) != 2*time.Second {
		t.Fatalf("approval %+v", a)
	}
	done, err := e.d.DecideApproval(a.ID, api.ApprovalDecision{Decision: "approve"}, 501)
	if err != nil || done.State != "approved" || done.DecidedBy != "uid:501" {
		t.Fatalf("decide %+v %v", done, err)
	}
	if v := <-got; !v.Allow {
		t.Fatalf("approved verdict %+v", v)
	}
	if _, err := e.d.DecideApproval(a.ID, api.ApprovalDecision{Decision: "reject"}, 501); errCode(err) != api.CodeConflict {
		t.Fatalf("second answer: %v", err)
	}
	// "once": the next connection asks again; approve for the box this time
	go func() { v, _ := dec.Decide(ctx, off); got <- v }()
	a = waitPending(t, e.d, 1)[0]
	if _, err := e.d.DecideApproval(a.ID, api.ApprovalDecision{Decision: "approve", Scope: "box"}, 0); err != nil {
		t.Fatal(err)
	}
	<-got
	if v, _ := dec.Decide(ctx, off); !v.Allow || len(e.d.Approvals()) != 0 {
		t.Fatalf("scope box should allow without asking: %+v", v)
	}
	// another port of the same host is not covered
	other := egress.Request{Scheme: "https", Host: "example.com", Port: 8443, URL: "https://example.com:8443"}
	go func() { v, _ := dec.Decide(ctx, other); got <- v }()
	a = waitPending(t, e.d, 1)[0]
	e.d.DecideApproval(a.ID, api.ApprovalDecision{Decision: "reject"}, 0)
	if v := <-got; v.Allow || !strings.Contains(v.Reason, "rejected") || !strings.Contains(v.Reason, "--allow example.com:8443") {
		t.Fatalf("rejected %+v", v)
	}

	// expiry: nobody answers
	e.d.opts.ApprovalTimeout = 100 * time.Millisecond
	v, _ = dec.Decide(ctx, egress.Request{Scheme: "https", Host: "slow.example", Port: 443, URL: "https://slow.example:443"})
	if v.Allow || !strings.Contains(v.Reason, "no one approved") || !strings.Contains(v.Reason, "--allow slow.example") {
		t.Fatalf("expired %+v", v)
	}
	if _, err := e.d.DecideApproval("apr-nope", api.ApprovalDecision{Decision: "approve"}, 0); errCode(err) != api.CodeNotFound {
		t.Fatalf("unknown approval: %v", err)
	}

	e.d.Stop(ctx, "eg", api.StopRequest{})
	var approvals []map[string]any
	for _, rec := range run.Records {
		if rec.Method == "observe" && rec.Source == tracekit.SourceApproval {
			approvals = append(approvals, rec.Value.(map[string]any))
		}
	}
	if len(approvals) != 4 {
		t.Fatalf("approval observes %v", approvals)
	}
	if approvals[0]["decision"] != "approved" || approvals[0]["approver"] != "uid:501" || approvals[0]["target"] != off.URL ||
		approvals[1]["approver"] != "uid:0" || approvals[2]["decision"] != "rejected" || approvals[3]["decision"] != "expired" {
		t.Fatalf("approval observes %v", approvals)
	}
	for _, rec := range run.Records {
		if rec.Method == "observe" && rec.Trust != "trusted" && rec.Source == tracekit.SourceApproval {
			t.Fatal("approvals must be trusted observes")
		}
	}
}

func TestDeciderFailsClosedWithoutSigner(t *testing.T) {
	e := newTestEnv(t, func(o *Options) {
		o.Gate = func(context.Context, tracekit.Run, tracekit.Call, tracekit.GateHooks) (tracekit.Outcome, error) {
			return tracekit.Outcome{}, &tracekit.Unavailable{Err: context.DeadlineExceeded}
		}
	})
	// the box boots (no gate at create), but every door stays shut
	e.create(api.CreateBoxRequest{Name: "fc", Allow: []string{"pypi.org"}})
	v, err := e.proxy(0).cfg.Decider.Decide(context.Background(),
		egress.Request{Host: "pypi.org", Port: 443, URL: "https://pypi.org:443", OnAllowlist: true})
	if err != nil || v.Allow || !strings.Contains(v.Reason, "fail closed") {
		t.Fatalf("verdict %+v %v", v, err)
	}
	_, frames := execStream(t, e.serve(), "fc", api.ExecRequest{Argv: []string{"ls"}}, nil)
	if f := frames[len(frames)-1]; f.AsError().Code != api.CodeUnavailable {
		t.Fatalf("exec without signer: %s", f.Payload)
	}
	if len(e.guest.Execs) != 0 {
		t.Fatal("a command ran without the signer")
	}
}

func TestSinkNeverWritesSecretValues(t *testing.T) {
	e := newTestEnv(t, nil)
	b := e.create(api.CreateBoxRequest{Name: "s", Allow: []string{"anthropic"},
		Secrets: map[string]api.SecretSpec{"ANTHROPIC_API_KEY": {Value: secretValue, Hosts: []string{"api.anthropic.com"}, Header: "x-api-key"}}})
	cfg := e.proxy(0).cfg
	ph := cfg.Secrets[0].Placeholder
	if !strings.HasPrefix(ph, "tkbox_ANTHROPIC_API_KEY_") {
		t.Fatalf("placeholder %q", ph)
	}
	sink := cfg.Sink
	sink.Emit(egress.Event{Kind: egress.EventSecretUse, Host: "api.anthropic.com", Port: 443, Secret: "ANTHROPIC_API_KEY", Method: "POST", Path: "/v1/messages"})
	sink.Emit(egress.Event{Kind: egress.EventModelCall, Host: "api.anthropic.com", Port: 443, Method: "POST", Path: "/v1/messages", Status: 200, BytesIn: 900, BytesOut: 100})
	// even if a buggy caller slipped the value or the placeholder into an event, nothing lands on disk
	sink.Emit(egress.Event{Kind: egress.EventSecretLeak, Host: "evil.example", Port: 443, Secret: "ANTHROPIC_API_KEY",
		Reason: "placeholder " + ph + " in a request to an unbound host", Path: "/steal/" + secretValue})
	sink.Emit(egress.Event{Kind: egress.EventDenied, Host: "evil.example", Port: 443, Reason: "not on the allowlist " + secretValue})
	e.d.Stop(context.Background(), "s", api.StopRequest{})

	dir := e.d.boxDir(b.ID)
	for _, name := range []string{"events.ndjson", "box.json"} {
		data := readFile(t, filepath.Join(dir, name))
		if strings.Contains(data, secretValue) || strings.Contains(data, ph) {
			t.Fatalf("%s holds the secret value or its placeholder:\n%s", name, data)
		}
	}
	events := readFile(t, filepath.Join(dir, "events.ndjson"))
	for _, want := range []string{`"kind":"secret.use"`, `"kind":"model.call"`, `"kind":"secret.leak"`, "[secret ANTHROPIC_API_KEY]"} {
		if !strings.Contains(events, want) {
			t.Errorf("events.ndjson lacks %s", want)
		}
	}
	if fi, _ := os.Stat(filepath.Join(dir, "events.ndjson")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("events.ndjson mode %v", fi.Mode())
	}
	sources := map[string]map[string]any{}
	for _, rec := range e.tk.Runs[0].Records {
		if rec.Method != "observe" {
			continue
		}
		js, _ := json.Marshal(rec.Value)
		if strings.Contains(string(js), secretValue) || strings.Contains(string(js), ph) {
			t.Fatalf("observe %s holds the secret: %s", rec.Source, js)
		}
		if v, ok := rec.Value.(map[string]any); ok {
			sources[rec.Source] = v
		}
	}
	if u := sources[tracekit.SourceSecretUse]; u["name"] != "ANTHROPIC_API_KEY" || u["host"] != "api.anthropic.com" {
		t.Fatalf("secret use observe %v", u)
	}
	if mc := sources[tracekit.SourceModelCall]; mc["status"] != 200 || mc["bytes"] != int64(1000) || mc["path"] != "/v1/messages" {
		t.Fatalf("model call observe %v", mc)
	}
	if sources[tracekit.SourceSecretLeak]["host"] != "evil.example" || sources[tracekit.SourceEgress]["decision"] != "deny" {
		t.Fatalf("observes %v", sources)
	}
	// box API views never carry values either
	view, _ := e.d.Get("s")
	js, _ := json.Marshal(view)
	if strings.Contains(string(js), secretValue) {
		t.Fatal("Box view holds the secret value")
	}
}
