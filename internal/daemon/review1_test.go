package daemon

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// L10: a per-exec env may not set anything that changes which program runs or what it loads.
func TestReview1ExecEnvDenyList(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "env"})
	for _, k := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "BASH_ENV", "ENV", "PROMPT_COMMAND",
		"PATH", "NODE_OPTIONS", "PYTHONPATH", "PERL5OPT", "RUBYOPT", "JAVA_TOOL_OPTIONS", "GCONV_PATH",
		"GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_GLOBAL",
		"GIT_CONFIG_SYSTEM", "GIT_CONFIG_PARAMETERS"} {
		_, e2 := e.d.prepareExec("env", api.ExecRequest{Argv: []string{"ls"}, Env: map[string]string{k: "/x"}})
		if e2 == nil || e2.Code != api.CodeBadRequest || !strings.Contains(e2.Message, k) {
			t.Errorf("per-exec env %s: %v", k, e2)
		}
	}
	for _, k := range []string{"HOME", "LANG", "GIT_AUTHOR_NAME", "MY_PATH", "NODE_ENV"} {
		if _, e2 := e.d.prepareExec("env", api.ExecRequest{Argv: []string{"ls"}, Env: map[string]string{k: "x"}}); e2 != nil {
			t.Errorf("per-exec env %s refused: %v", k, e2)
		}
	}
}

// L2 (daemon part): inspect all with no allow entries and no secrets gives a CA that may impersonate nothing, never an
// unconstrained one (egress.CAOptions reads nil hosts as unconstrained).
func TestReview1CAHostsNeverUnconstrained(t *testing.T) {
	hosts := caHosts(nil, []string{}, egress.InspectAll)
	if hosts == nil || len(hosts) != 0 {
		t.Fatalf("caHosts = %#v, want an empty non-nil list", hosts)
	}
	ca, err := egress.NewCAWith("tkb-test", egress.CAOptions{Hosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"evil.example", "8.8.8.8", "api.github.com"} {
		if ca.Permits(h) {
			t.Errorf("the CA of a box with nothing to inspect may impersonate %s", h)
		}
	}
	// what it may impersonate is still exactly the bound and (inspect all) allowed hosts
	got := caHosts([]egress.Secret{{Name: "T", Hosts: []string{"api.example.com"}}}, []string{"pypi.org", "h.example:8443"}, egress.InspectAll)
	if strings.Join(got, ",") != "api.example.com,pypi.org,h.example" {
		t.Fatalf("caHosts = %v", got)
	}
}

// L1: the first records of a box (created, task) never carry a secret value or placeholder, and env values (the box's
// and a command's) that hold a secret's value are refused, naming the env key but never the value.
func TestReview1NoSecretValuesInFirstRecordsOrEnv(t *testing.T) {
	const val = "s3cret-value-1234"
	secrets := map[string]api.SecretSpec{"TOK": {Value: val, Hosts: []string{"api.example.com"}}}
	e := newTestEnv(t, nil)
	_, err := e.d.Create(context.Background(), api.CreateBoxRequest{Image: "x", Secrets: secrets, Env: map[string]string{"COPY": "Bearer " + val}})
	if errCode(err) != api.CodeBadRequest || !strings.Contains(err.Error(), "env COPY holds the value of secret TOK") || strings.Contains(err.Error(), val) {
		t.Fatalf("box env with a secret value: %v", err)
	}
	e.create(api.CreateBoxRequest{Name: "l1", Secrets: secrets, Env: map[string]string{"PLAIN": "1"},
		Task: "use the token " + val + " to call the API"})
	var ph string
	for _, s := range e.box("l1").secrets {
		ph = s.Placeholder
	}
	sawCreated, sawTask := false, false
	for _, r := range e.run(0).Records {
		if r.Method != "observe" {
			continue
		}
		js, _ := json.Marshal(r.Value)
		if strings.Contains(string(js), val) || strings.Contains(string(js), ph) {
			t.Fatalf("%s record carries a secret: %s", r.Source, js)
		}
		switch r.Source {
		case tracekit.SourceBox:
			sawCreated = sawCreated || strings.Contains(string(js), `"created"`)
		case tracekit.SourceTask:
			sawTask = strings.Contains(string(js), "use the token [secret TOK] to call the API")
		}
	}
	if !sawCreated || !sawTask {
		t.Fatalf("created %v, task scrubbed %v: %v", sawCreated, sawTask, e.run(0).Records)
	}
	_, e2 := e.d.prepareExec("l1", api.ExecRequest{Argv: []string{"env"}, Env: map[string]string{"AUTH": "x" + val + "y"}})
	if e2 == nil || e2.Code != api.CodeBadRequest || !strings.Contains(e2.Message, "env AUTH holds the value of secret TOK") ||
		strings.Contains(e2.Error(), val) {
		t.Fatalf("per-exec env with a secret value: %v", e2)
	}
	if _, e2 := e.d.prepareExec("l1", api.ExecRequest{Argv: []string{"env"}, Env: map[string]string{"AUTH": ph}}); e2 != nil {
		t.Fatalf("per-exec env with the placeholder: %v", e2)
	}
}

// flakyClient's runs refuse every complete (when failComplete is set) and the observes of the sources in failObserve.
type flakyClient struct {
	tracekit.Client
	mu           sync.Mutex
	failComplete bool
	failObserve  map[string]bool
	contained    int // Contained calls
}

func (c *flakyClient) set(failComplete bool) { c.mu.Lock(); c.failComplete = failComplete; c.mu.Unlock() }

func (c *flakyClient) NewRun(ctx context.Context, a tracekit.Agent) (tracekit.Run, error) {
	r, err := c.Client.NewRun(ctx, a)
	if err != nil {
		return nil, err
	}
	return &flakyRun{Run: r, c: c}, nil
}

type flakyRun struct {
	tracekit.Run
	c *flakyClient
}

func (r *flakyRun) Complete(ctx context.Context, call tracekit.Call, d tracekit.Decision, status string, result any) error {
	r.c.mu.Lock()
	fail := r.c.failComplete
	r.c.mu.Unlock()
	if fail {
		return &tracekit.RPCError{Code: "internal", Message: "complete refused"}
	}
	return r.Run.Complete(ctx, call, d, status, result)
}

func (r *flakyRun) Observe(ctx context.Context, source, trust string, value any) error {
	r.c.mu.Lock()
	fail := r.c.failObserve[source]
	r.c.mu.Unlock()
	if fail {
		return &tracekit.RPCError{Code: "internal", Message: "observe refused"}
	}
	return r.Run.Observe(ctx, source, trust, value)
}

func (r *flakyRun) Contained(ctx context.Context) (tracekit.Containment, error) {
	r.c.mu.Lock()
	r.c.contained++
	r.c.mu.Unlock()
	return r.Run.Contained(ctx)
}

func (c *flakyClient) containedCalls() int { c.mu.Lock(); defer c.mu.Unlock(); return c.contained }

// gapsOf sums the tkbox.gap records of kind in run i.
func gapsOf(e *testEnv, i int, kind string) int {
	n := 0
	for _, r := range e.run(i).Records {
		if r.Method == "observe" && r.Source == sourceGap {
			if m, _ := r.Value.(map[string]any); m["kind"] == kind {
				n += m["dropped"].(int)
			}
		}
	}
	return n
}

// L8: a complete the signer refuses is counted into tkbox.gap (kind "complete"), for execs and egress while the box
// runs (recorded when it stops) and for an apply of a stopped box (recorded at once).
func TestReview1FailedCompletesRecordedAsGap(t *testing.T) {
	e := newTestEnv(t, nil)
	fc := &flakyClient{Client: e.tk, failComplete: true}
	e.d.opts.Tracekit = fc
	ws := t.TempDir()
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "c", Workspace: ws, Allow: []string{"pypi.org"}})
	sock := e.serve()
	_, frames := execStream(t, sock, "c", api.ExecRequest{Argv: []string{"true"}}, nil)
	if frames[len(frames)-1].Type != proto.TypeExit {
		t.Fatalf("exec: %s", frames[len(frames)-1].Payload)
	}
	if v, _ := e.proxy(0).cfg.Decider.Decide(context.Background(), egress.Request{Host: "pypi.org", Port: 443, URL: "https://pypi.org:443", OnAllowlist: true}); !v.Allow {
		t.Fatalf("egress: %+v", v)
	}
	if n := gapsOf(e, 0, gapComplete); n != 0 {
		t.Fatalf("gap recorded before the stop: %d", n)
	}
	e.d.Stop(context.Background(), "c", api.StopRequest{})
	if n := gapsOf(e, 0, gapComplete); n != 2 {
		t.Fatalf("tkbox.gap complete = %d after the stop, want 2 (exec + egress): %v", n, e.run(0).Methods())
	}
	if _, err := e.d.Apply(context.Background(), "c", api.ApplyRequest{}); err != nil {
		t.Fatal(err)
	}
	if n := gapsOf(e, 0, gapComplete); n != 3 {
		t.Fatalf("tkbox.gap complete = %d after the apply, want 3", n)
	}
}

// L9: a daemon restarted with a signer applies nothing from a box that ran unrecorded (it has no run to decide the
// writes in); it names the saved patch to apply by hand. An unrecorded daemon still applies it.
func TestReview1RecordedDaemonRefusesUnrecordedPatch(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.Tracekit, o.Unrecorded = nil, true })
	ws := t.TempDir()
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "u", Workspace: ws})
	e.d.Stop(context.Background(), "u", api.StopRequest{})

	opts := e.opts
	opts.Tracekit, opts.Unrecorded = e.tk, false
	d2, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	d2.eg = fakeEgress()
	_, err = d2.Apply(context.Background(), "u", api.ApplyRequest{})
	if errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "ran unrecorded") ||
		!strings.Contains(err.Error(), filepath.Join(e.d.boxDir(e.box("u").id), "diff.patch")) || !strings.Contains(err.Error(), "by hand after review") {
		t.Fatalf("recorded daemon applying an unrecorded box: %v", err)
	}
	if readFile(t, filepath.Join(ws, "a.txt")) != "old\n" {
		t.Fatal("written with no decision")
	}
	if _, err := e.d.Apply(context.Background(), "u", api.ApplyRequest{}); err != nil {
		t.Fatalf("the unrecorded daemon itself: %v", err)
	}
}

// L14: an approval that could not be recorded in Tracekit allows nothing: the waiting connection is refused, the
// approver is told, and "approve for the rest of the box" opens nothing for later connections.
func TestReview1UnrecordedApprovalAllowsNothing(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.ApprovalTimeout = time.Minute })
	fc := &flakyClient{Client: e.tk, failObserve: map[string]bool{tracekit.SourceApproval: true}}
	e.d.opts.Tracekit = fc
	e.create(api.CreateBoxRequest{Name: "ap"})
	dec := e.proxy(0).cfg.Decider
	req := egress.Request{Host: "x.example", Port: 443, URL: "https://x.example:443"}
	got := make(chan egress.Verdict, 1)
	go func() {
		v, _ := dec.Decide(context.Background(), req)
		got <- v
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(e.d.Approvals()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	pend := e.d.Approvals()
	if len(pend) != 1 {
		t.Fatalf("approvals %+v", pend)
	}
	_, err := e.d.DecideApproval(pend[0].ID, api.ApprovalDecision{Decision: "approve", Scope: "box"}, 1000)
	if errCode(err) != api.CodeUnavailable || !strings.Contains(err.Error(), "allows nothing") {
		t.Fatalf("approving an approval that can't be recorded: %v", err)
	}
	select {
	case v := <-got:
		if v.Allow || !strings.Contains(v.Reason, "could not be recorded") {
			t.Fatalf("the waiting connection: %+v", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting connection got no answer")
	}
	b := e.box("ap")
	b.mu.Lock()
	open := b.approvedHosts["x.example:443"]
	b.mu.Unlock()
	if open {
		t.Fatal("an unrecorded box-scope approval opened the host for the rest of the box")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if v, _ := dec.Decide(ctx, req); v.Allow {
		t.Fatalf("a later connection was let through on the unrecorded approval: %+v", v)
	}
}

// L11: containment is polled every ContainmentPoll (2s) for the first minute, then every ContainmentSlowPoll (15s),
// and at once after a decision that named an incident.
func TestReview1ContainmentPollBacksOff(t *testing.T) {
	e0 := newTestEnv(t, func(o *Options) { o.ContainmentPoll = 0 })
	for _, c := range []struct{ elapsed, want time.Duration }{{0, 2 * time.Second}, {59 * time.Second, 2 * time.Second},
		{time.Minute, 15 * time.Second}, {3 * time.Hour, 15 * time.Second}} {
		if got := e0.d.containmentInterval(c.elapsed); got != c.want {
			t.Errorf("interval after %s = %s, want %s", c.elapsed, got, c.want)
		}
	}

	e := newTestEnv(t, func(o *Options) {
		o.ContainmentPoll, o.ContainmentFastFor, o.ContainmentSlowPoll = 20*time.Millisecond, 200*time.Millisecond, time.Hour
	})
	fc := &flakyClient{Client: e.tk}
	e.d.opts.Tracekit = fc
	e.create(api.CreateBoxRequest{Name: "cp"})
	time.Sleep(400 * time.Millisecond)
	fast := fc.containedCalls()
	if fast < 3 {
		t.Fatalf("%d containment checks in the first 200ms at a 20ms poll", fast)
	}
	time.Sleep(400 * time.Millisecond)
	if slow := fc.containedCalls(); slow != fast {
		t.Fatalf("containment still polled fast after ContainmentFastFor: %d checks, then %d", fast, slow)
	}
	e.tk.DecideFunc = func(c tracekit.Call) tracekit.Decision {
		return tracekit.Decision{Decision: "deny", IncidentID: "inc-1", Reason: "held"}
	}
	sock := e.serve()
	execStream(t, sock, "cp", api.ExecRequest{Argv: []string{"rm", "-rf", "/"}}, nil)
	deadline := time.Now().Add(2 * time.Second)
	for fc.containedCalls() == fast && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fc.containedCalls() == fast {
		t.Fatal("a decision that named an incident did not trigger a containment check")
	}
}

// L6: the daemon's extra block prefixes (--egress-block: e.g. a cloud VM's NAT'd public IP, which is on no interface)
// reach every box's proxy alongside the host's own addresses.
func TestReview1EgressBlockReachesEveryBox(t *testing.T) {
	pub := netip.MustParsePrefix("203.0.113.7/32")
	e := newTestEnv(t, func(o *Options) { o.EgressBlock = []netip.Prefix{pub, netip.MustParsePrefix("198.51.100.9/24")} })
	e.create(api.CreateBoxRequest{Name: "b1"})
	e.create(api.CreateBoxRequest{Name: "b2"})
	for i := range 2 {
		bp := e.proxy(i).cfg.BlockPrefixes
		if !slices.Contains(bp, pub) || !slices.Contains(bp, netip.MustParsePrefix("198.51.100.0/24")) {
			t.Fatalf("box %d BlockPrefixes %v", i, bp)
		}
	}
}
