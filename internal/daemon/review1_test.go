package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
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
	for _, k := range []string{"LANG", "GIT_AUTHOR_NAME", "MY_PATH", "NODE_ENV"} { // HOME is refused since verify3
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

// heldDiffGuest holds its diff answer until release is closed (a hostile guest stalling its stop).
type heldDiffGuest struct {
	agentrpc.Guest
	asked   chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *heldDiffGuest) DiffWith(ctx context.Context, req proto.DiffRequest, w io.Writer) (proto.DiffSummary, error) {
	g.once.Do(func() { close(g.asked) })
	select {
	case <-g.release:
	case <-ctx.Done():
		return proto.DiffSummary{}, ctx.Err()
	}
	return g.Guest.DiffWith(ctx, req, w)
}

// M1: once a box starts stopping (here: fail closed after a lost must-record observe) its egress is shut at once,
// while the guest still holds its diff: the proxy and the vsock egress listener are closed and every decision is
// refused, even for an allowlisted host.
func TestReview1StopClosesEgressFirst(t *testing.T) {
	e := newTestEnv(t, nil)
	fc := &flakyClient{Client: e.tk, failObserve: map[string]bool{tracekit.SourceSecretUse: true}}
	e.d.opts.Tracekit = fc
	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "fc", Allow: []string{"pypi.org"}})
	g := &heldDiffGuest{Guest: e.guest, asked: make(chan struct{}), release: make(chan struct{})}
	b := e.box("fc")
	b.mu.Lock()
	b.guest = g
	b.mu.Unlock()
	defer func() {
		select {
		case <-g.release:
		default:
			close(g.release)
		}
	}()
	dec := e.proxy(0).cfg.Decider
	allowed := egress.Request{Host: "pypi.org", Port: 443, URL: "https://pypi.org:443", OnAllowlist: true}
	if v, _ := dec.Decide(context.Background(), allowed); !v.Allow {
		t.Fatalf("before the stop: %+v", v)
	}

	e.proxy(0).cfg.Sink.Emit(egress.Event{Kind: egress.EventSecretUse, Host: "api.example.com", Port: 443, Secret: "T"})
	select {
	case <-g.asked:
	case <-time.After(10 * time.Second):
		t.Fatalf("the stop never asked for the diff (state %s)", b.state())
	}
	// the guest holds its diff: the box is stopping and egress must already be shut
	if st := b.state(); st != api.StateStopping {
		t.Fatalf("state %s", st)
	}
	p := e.proxy(0)
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if !closed {
		t.Fatal("the egress proxy is still open while the guest holds its diff")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := e.machine(0).GuestDial(ctx, proto.PortEgress); err == nil {
		c.Close()
		t.Fatal("the vsock egress listener still accepts while the guest holds its diff")
	}
	start := time.Now()
	for _, r := range []egress.Request{allowed, {Host: "x.example", Port: 443, URL: "https://x.example:443"}} {
		v, _ := dec.Decide(context.Background(), r)
		if v.Allow || !strings.Contains(v.Reason, "going down") {
			t.Fatalf("decision for %s while stopping: %+v", r.URL, v)
		}
	}
	if time.Since(start) > time.Second || len(e.d.Approvals()) != 0 {
		t.Fatalf("refusals took %s, approvals %v", time.Since(start), e.d.Approvals())
	}
	close(g.release)
	deadline := time.Now().Add(10 * time.Second)
	for b.state() != api.StateStopped && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if v := b.view(); v.State != api.StateStopped || !v.DiffSaved {
		t.Fatalf("box after the stop: %+v", v)
	}
}

// catGuest's execs copy their stdin to stdout.
func catGuest(ctx context.Context, req proto.ExecRequest, xio agentrpc.ExecIO) (proto.ExitStatus, error) {
	if xio.Stdin != nil {
		io.Copy(xio.Stdout, xio.Stdin)
	}
	return proto.ExitStatus{}, nil
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// lastBash is the args of the last Bash decision and the result of the last exec complete in run 0.
func lastBash(e *testEnv) (args map[string]any, result map[string]any) {
	for _, r := range e.run(0).Records {
		if r.Call.Tool != tracekit.ToolBash {
			continue
		}
		switch r.Method {
		case "decide":
			args = r.Call.Args
		case "complete":
			result, _ = r.Value.(map[string]any)
		}
	}
	return args, result
}

// M4: stdin known up front (stdin_data) is decided with the command (its sha256 and size, and its text when short
// UTF-8, secrets redacted) and is exactly what the process reads; streamed stdin's digest is recorded in the complete.
func TestReview1StdinInTheDecision(t *testing.T) {
	e := newTestEnv(t, nil)
	e.guest.ExecFunc = catGuest
	e.create(api.CreateBoxRequest{Name: "in", Secrets: map[string]api.SecretSpec{"TOK": {Value: "s3cret-value-1234", Hosts: []string{"api.example.com"}}}})
	var ph string
	for _, s := range e.box("in").secrets {
		ph = s.Placeholder
	}
	sock := e.serve()

	script := []byte("import os\nprint(os.environ['TOK'] == '" + ph + "')\n")
	_, frames := execStream(t, sock, "in", api.ExecRequest{Argv: []string{"python3"}, StdinData: script}, nil)
	if frames[len(frames)-1].Type != proto.TypeExit || stdoutOf(frames) != string(script) {
		t.Fatalf("stdin_data exec: stdout %q, last %s", stdoutOf(frames), frames[len(frames)-1].Payload)
	}
	args, _ := lastBash(e)
	if args["stdin"] != true || args["stdin_sha256"] != sha(script) || args["stdin_bytes"] != len(script) ||
		args["stdin_text"] != "import os\nprint(os.environ['TOK'] == 'tkbox_TOK_…')\n" {
		t.Fatalf("decided args %v", args)
	}
	if g := e.guest.Execs[len(e.guest.Execs)-1]; !g.Stdin {
		t.Fatalf("guest exec %+v", g)
	}

	// long or binary stdin: only its digest is in the decision
	for _, data := range [][]byte{bytes.Repeat([]byte("a"), api.MaxStdinText+1), {0xff, 0xfe, 'x'}} {
		_, frames = execStream(t, sock, "in", api.ExecRequest{Argv: []string{"python3"}, StdinData: data}, nil)
		args, _ = lastBash(e)
		if stdoutOf(frames) != string(data) || args["stdin_sha256"] != sha(data) || args["stdin_bytes"] != len(data) {
			t.Fatalf("stdin_data of %d bytes: args %v", len(data), args)
		}
		if _, ok := args["stdin_text"]; ok {
			t.Fatalf("stdin_text for %d bytes (utf-8 %v)", len(data), utf8.Valid(data))
		}
	}

	// past the cap, and with both kinds of stdin: refused before anything is decided
	n := len(e.run(0).Records)
	resp, _ := execStream(t, sock, "in", api.ExecRequest{Argv: []string{"python3"}, StdinData: make([]byte, api.MaxStdinData+1)}, nil)
	var body api.ErrorBody
	json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusUnprocessableEntity || body.Error.Code != api.CodeLimit || !strings.Contains(body.Error.Message, "stdin_data") || body.Error.Hint == "" {
		t.Fatalf("stdin_data over the cap: %d %+v", resp.StatusCode, body)
	}
	resp, _ = execStream(t, sock, "in", api.ExecRequest{Argv: []string{"cat"}, Stdin: true, StdinData: []byte("x")}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("stdin and stdin_data: %d", resp.StatusCode)
	}
	if len(e.run(0).Records) != n {
		t.Fatal("a refused exec request was decided")
	}

	// streamed stdin: the digest of what the process was given goes into the complete
	streamed := []byte("streamed input\n")
	_, frames = execStream(t, sock, "in", api.ExecRequest{Argv: []string{"cat"}, Stdin: true}, streamed)
	args, result := lastBash(e)
	if stdoutOf(frames) != string(streamed) || args["stdin"] != true || args["stdin_sha256"] != nil {
		t.Fatalf("streamed: stdout %q args %v", stdoutOf(frames), args)
	}
	if result["stdin_sha256"] != sha(streamed) || result["stdin_bytes"] != int64(len(streamed)) {
		t.Fatalf("streamed complete %v", result)
	}
}

// L7: the diff summary never rides in an unbounded header: a summary over 8 KiB (thousands of long paths, which the
// guest controls) is left out of the diff response and served as JSON at /diff/summary; a small one stays a header.
func TestReview1DiffSummaryNotAHugeHeader(t *testing.T) {
	e := newTestEnv(t, nil)
	var patch strings.Builder
	long := strings.Repeat("p", 180)
	for i := range 3000 {
		p := fmt.Sprintf("d/%s/f%05d.txt", long, i)
		fmt.Fprintf(&patch, "diff --git a/%s b/%s\nnew file mode 100644\n--- /dev/null\n+++ b/%s\n@@ -0,0 +1 @@\n+x\n", p, p, p)
	}
	e.guest.Patch = patch.String()
	e.create(api.CreateBoxRequest{Name: "big"})
	e.d.Stop(context.Background(), "big", api.StopRequest{})
	hc := httpClient(e.serve())

	resp, err := hc.Get("http://tkbox/v1/boxes/big/diff")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != patch.String() {
		t.Fatalf("diff: %d, %d bytes", resp.StatusCode, len(body))
	}
	if h := resp.Header.Get(api.DiffSummaryHeader); len(h) > api.MaxDiffSummaryHeader || resp.Header.Get(api.DiffSummaryOmittedHeader) != "1" {
		t.Fatalf("diff response: a %d-byte summary header, omitted %q", len(h), resp.Header.Get(api.DiffSummaryOmittedHeader))
	}
	resp, err = hc.Get("http://tkbox/v1/boxes/big/diff/summary")
	if err != nil {
		t.Fatal(err)
	}
	var sum api.DiffSummary
	err = json.NewDecoder(resp.Body).Decode(&sum)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || len(sum.Files) != 3000 || sum.Bytes != int64(patch.Len()) ||
		sum.Files[2999].Path != fmt.Sprintf("d/%s/f%05d.txt", long, 2999) || sum.Files[0].Status != "added" {
		t.Fatalf("diff/summary: %d %v, %d files", resp.StatusCode, err, len(sum.Files))
	}

	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "small"})
	resp, err = hc.Get("http://tkbox/v1/boxes/small/diff")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if h := resp.Header.Get(api.DiffSummaryHeader); !strings.Contains(h, `"a.txt"`) || resp.Header.Get(api.DiffSummaryOmittedHeader) != "" {
		t.Fatalf("small diff: header %q", h)
	}
	resp, _ = hc.Get("http://tkbox/v1/boxes/nope/diff/summary")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("summary of an unknown box: %d", resp.StatusCode)
	}
	resp.Body.Close()
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
