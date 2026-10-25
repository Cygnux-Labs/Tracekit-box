package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// execConn opens an exec stream and returns the connection once it is upgraded.
func execConn(t *testing.T, sock, box string, req api.ExecRequest) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	body, _ := json.Marshal(req)
	hreq, _ := http.NewRequest("POST", "http://tkbox/v1/boxes/"+box+"/exec", bytes.NewReader(body))
	hreq.Header.Set("Connection", "Upgrade")
	hreq.Header.Set("Upgrade", api.ExecUpgrade)
	hreq.Header.Set("Content-Type", "application/json")
	if err := hreq.Write(c); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, hreq)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	return c, br
}

// lastFrame reads frames until TypeExit or TypeError.
func lastFrame(t *testing.T, c net.Conn, br *bufio.Reader) proto.Frame {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		f, err := proto.ReadFrame(br)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if f.Type == proto.TypeExit || f.Type == proto.TypeError {
			return f
		}
	}
}

func methodsOf(e *testEnv, i int) string { return strings.Join(e.run(i).Methods(), ",") }

// C2: a process that never reads its stdin can't stop signals from reaching it.
func TestStdinNeverBlocksSignals(t *testing.T) {
	e := newTestEnv(t, nil)
	e.guest.ExecFunc = func(ctx context.Context, req proto.ExecRequest, io agentrpc.ExecIO) (proto.ExitStatus, error) {
		select { // never reads stdin
		case s := <-io.Signals:
			return proto.ExitStatus{Code: -1, Signal: s}, nil
		case <-ctx.Done():
			return proto.ExitStatus{}, ctx.Err()
		}
	}
	e.create(api.CreateBoxRequest{Name: "in"})
	sock := e.serve()
	c, br := execConn(t, sock, "in", api.ExecRequest{Argv: []string{"sleep", "100"}, Stdin: true})
	// wait until it runs, then flood stdin far past any pipe buffer, then signal
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		f, err := proto.ReadFrame(br)
		if err != nil {
			t.Fatal(err)
		}
		var ev api.ExecEvent
		if f.Type == proto.TypeJSON && json.Unmarshal(f.Payload, &ev) == nil && ev.State == api.ExecRunning {
			break
		}
	}
	chunk := bytes.Repeat([]byte("x"), 512<<10)
	for range 6 { // 3 MiB: under the 4 MiB buffer
		if err := proto.WriteFrame(c, proto.TypeStdin, chunk); err != nil {
			t.Fatal(err)
		}
	}
	sig, _ := json.Marshal(proto.Signal{Signal: "SIGINT"})
	proto.WriteFrame(c, proto.TypeSignal, sig)
	f := lastFrame(t, c, br)
	var st proto.ExitStatus
	json.Unmarshal(f.Payload, &st)
	if f.Type != proto.TypeExit || st.Signal != "SIGINT" {
		t.Fatalf("the signal did not get through: %d %s", f.Type, f.Payload)
	}
}

// C13: a signal (Ctrl-C) while the command waits for a decision cancels it; it is never started later.
func TestSignalBeforeStartCancels(t *testing.T) {
	waiting := make(chan struct{})
	var once sync.Once
	e := newTestEnv(t, func(o *Options) {
		o.Gate = func(ctx context.Context, r tracekit.Run, call tracekit.Call, h tracekit.GateHooks) (tracekit.Outcome, error) {
			if call.Tool != tracekit.ToolBash {
				return fakeGate(ctx, r, call, h)
			}
			once.Do(func() { close(waiting) })
			<-ctx.Done() // an approval nobody answers
			return tracekit.Outcome{Reason: "held and not approved: requested"}, nil
		}
	})
	e.create(api.CreateBoxRequest{Name: "c"})
	sock := e.serve()
	c, br := execConn(t, sock, "c", api.ExecRequest{Argv: []string{"rm", "-rf", "/"}})
	<-waiting
	sig, _ := json.Marshal(proto.Signal{Signal: "SIGINT"})
	proto.WriteFrame(c, proto.TypeSignal, sig)
	f := lastFrame(t, c, br)
	var ed api.ErrorDetail
	json.Unmarshal(f.Payload, &ed)
	if f.Type != proto.TypeError || ed.Code != api.CodeCancelled {
		t.Fatalf("want cancelled, got %d %+v", f.Type, ed)
	}
	if len(e.guest.Execs) != 0 {
		t.Fatal("a cancelled command was started")
	}
}

// C3 + C10: stop signals running commands before the diff, a client that stopped reading can't hold the exec, and
// every exec is completed before the run is closed.
func TestStopEndsExecsBeforeDiffAndClose(t *testing.T) {
	oldTerm, oldKill := execTermGrace, execKillGrace
	execTermGrace, execKillGrace = 500*time.Millisecond, 200*time.Millisecond
	defer func() { execTermGrace, execKillGrace = oldTerm, oldKill }()
	e := newTestEnv(t, nil)
	var order []string
	var mu sync.Mutex
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }
	e.guest.ExecFunc = func(ctx context.Context, req proto.ExecRequest, xio agentrpc.ExecIO) (proto.ExitStatus, error) {
		if req.Argv[0] == "flood" { // writes until the (stalled) client is cut off
			buf := bytes.Repeat([]byte("y"), 64<<10)
			for {
				if _, err := xio.Stdout.Write(buf); err != nil {
					note("flood ended")
					return proto.ExitStatus{}, err
				}
				if ctx.Err() != nil {
					note("flood ended")
					return proto.ExitStatus{}, ctx.Err()
				}
			}
		}
		select {
		case s := <-xio.Signals:
			note("got " + s)
			return proto.ExitStatus{Code: -1, Signal: s}, nil
		case <-ctx.Done():
			return proto.ExitStatus{}, ctx.Err()
		}
	}
	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "s"})
	sock := e.serve()
	c1, br1 := execConn(t, sock, "s", api.ExecRequest{Argv: []string{"wait"}})
	c2, _ := execConn(t, sock, "s", api.ExecRequest{Argv: []string{"flood"}}) // never read
	_ = c2
	deadline := time.Now().Add(5 * time.Second)
	for e.box("s").view().Execs < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		e.d.Stop(context.Background(), "s", api.StopRequest{})
		close(done)
	}()
	f := lastFrame(t, c1, br1)
	if f.Type != proto.TypeExit {
		t.Fatalf("waiting exec: %d %s", f.Type, f.Payload)
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("stop hung on a stalled client")
	}
	mu.Lock()
	if len(order) == 0 || order[0] != "got SIGTERM" {
		t.Fatalf("order %v", order)
	}
	mu.Unlock()
	if v, _ := e.d.Get("s"); !v.DiffSaved {
		t.Fatalf("diff not saved: %+v", v)
	}
	out := filepath.Join(t.TempDir(), "s.tkb")
	if _, err := e.d.Export(context.Background(), "s", api.ExportRequest{Out: out}); err != nil {
		t.Fatal(err)
	}
	ms := e.run(0).Methods()
	closeAt := slices.Index(ms, "close")
	completes := 0
	for i, m := range ms {
		if m == "complete" {
			completes++
			if i > closeAt {
				t.Fatalf("complete after close_run: %v", ms)
			}
		}
	}
	if completes != 2 || closeAt < 0 {
		t.Fatalf("want 2 completes before close: %v", ms)
	}
}

// C6 + P3: a stop whose diff fails says so, and diff/apply give the real reason.
func TestDiffNotSavedSaysWhy(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "big"})
	e.guest.ExecFunc = nil
	tooBig := &bigGuest{e.guest}
	bx := e.box("big")
	bx.mu.Lock()
	bx.guest = tooBig
	bx.mu.Unlock()
	b, _ := e.d.Stop(context.Background(), "big", api.StopRequest{})
	if b.DiffSaved || !strings.Contains(b.DiffError, "over 64 MiB") {
		t.Fatalf("box %+v", b)
	}
	if _, _, err := e.d.Diff(context.Background(), "big"); errCode(err) != api.CodeNotFound || !strings.Contains(err.Error(), "over 64 MiB") {
		t.Fatalf("diff: %v", err)
	}
	e.create(api.CreateBoxRequest{Name: "k"})
	if b, _ := e.d.Stop(context.Background(), "k", api.StopRequest{Kill: true}); !strings.Contains(b.DiffError, "killed") {
		t.Fatalf("killed box %+v", b)
	}
	if len(e.guest.Diffs) == 0 || !slices.Contains(e.guest.Diffs[0].ExcludeDirs, "node_modules") {
		t.Fatalf("diff requests %+v", e.guest.Diffs)
	}
}

type bigGuest struct{ agentrpc.Guest }

func (g *bigGuest) DiffWith(ctx context.Context, req proto.DiffRequest, w io.Writer) (proto.DiffSummary, error) {
	g.Guest.DiffWith(ctx, req, io.Discard)
	return proto.DiffSummary{}, &proto.Error{Code: proto.CodeTooLarge, Message: "patch over 64 MiB"}
}

// C1 + C5: after a restart a recorded box applies nothing and a run left open is not exported; a clean shutdown's
// runs export.
func TestRestartNeverWritesUngated(t *testing.T) {
	e := newTestEnv(t, nil)
	ws := t.TempDir()
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "r", Workspace: ws})
	e.d.Stop(context.Background(), "r", api.StopRequest{})

	d2 := e.newDaemon() // the first daemon "crashed": its run token is gone
	_, err := d2.Apply(context.Background(), "r", api.ApplyRequest{})
	if errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "ended when the daemon restarted") || !strings.Contains(err.Error(), "diff.patch") {
		t.Fatalf("apply after restart: %v", err)
	}
	if readFile(t, filepath.Join(ws, "a.txt")) != "old\n" {
		t.Fatal("written without a decision")
	}
	start := time.Now()
	_, err = d2.Export(context.Background(), "r", api.ExportRequest{Out: filepath.Join(t.TempDir(), "r.tkb")})
	if errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "left open") || time.Since(start) > time.Second {
		t.Fatalf("export of a run left open: %v", err)
	}

	// an unrecorded daemon on the same state applies nothing for a recorded box
	opts := e.opts
	opts.Tracekit, opts.Unrecorded = nil, true
	d3, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d3.Apply(context.Background(), "r", api.ApplyRequest{}); errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "unrecorded") {
		t.Fatalf("unrecorded daemon: %v", err)
	}

	// a clean shutdown closes the run, so a restarted daemon can still export it
	e2 := newTestEnv(t, nil)
	e2.create(api.CreateBoxRequest{Name: "ok"})
	e2.d.Stop(context.Background(), "ok", api.StopRequest{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	e2.d.Shutdown(ctx)
	cancel()
	d4 := e2.newDaemon()
	if _, err := d4.Export(context.Background(), "ok", api.ExportRequest{Out: filepath.Join(t.TempDir(), "ok.tkb")}); err != nil {
		t.Fatalf("export after a clean shutdown: %v", err)
	}
}

// S4 + S5 + S6 + S10 + C4 + P3 + P5: what apply refuses, leaves out and records.
func TestApplyGuards(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	e := newTestEnv(t, nil)
	ws := t.TempDir()
	gitInit(t, ws)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", ws}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	marker := filepath.Join(t.TempDir(), "filter-ran")
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	os.WriteFile(filepath.Join(ws, ".gitignore"), []byte("build/\n.env\n"), 0o644)
	os.WriteFile(filepath.Join(ws, ".env"), []byte("old\n"), 0o600)
	os.WriteFile(filepath.Join(ws, ".gitattributes"), []byte("*.txt filter=evil\n"), 0o644)
	git("config", "filter.evil.smudge", "touch "+marker+"; cat")
	git("config", "filter.evil.clean", "touch "+marker+"; cat")
	git("config", "core.hooksPath", "githooks")
	newFile := func(name, content string) string {
		return "diff --git a/" + name + " b/" + name + "\nnew file mode 100755\nindex 0000000..1111111\n--- /dev/null\n+++ b/" + name +
			"\n@@ -0,0 +1 @@\n+" + content + "\n"
	}
	box := func(name, patch string) {
		t.Helper()
		e.guest.Patch = patch
		e.create(api.CreateBoxRequest{Name: name, Workspace: ws})
	}
	ctx := context.Background()

	// a running box applies nothing
	box("run1", modify("a.txt"))
	if _, err := e.d.Apply(ctx, "run1", api.ApplyRequest{}); errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "stop the box first") {
		t.Fatalf("apply while running: %v", err)
	}
	e.d.Stop(ctx, "run1", api.StopRequest{})

	refused := func(name, patch, want string) {
		t.Helper()
		box(name, patch)
		e.d.Stop(ctx, name, api.StopRequest{})
		if _, err := e.d.Apply(ctx, name, api.ApplyRequest{AllowSensitive: true}); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: want %q, got %v", name, want, err)
		}
	}
	refused("copy", "diff --git a/a.txt b/b.txt\nsimilarity index 100%\ncopy from a.txt\ncopy to b.txt\n", "copies or renames")
	refused("rename", "diff --git a/a.txt b/b.txt\nsimilarity index 100%\nrename from a.txt\nrename to b.txt\n", "copies or renames")
	refused("ignored", modify(".env"), "which the checkout ignores")
	refused("hooks", newFile("githooks/pre-commit", "evil"), "hooks dir")

	// sensitive files need --allow-sensitive
	box("sens", modify("a.txt")+"diff --git a/.gitignore b/.gitignore\nindex 1111111..2222222 100644\n--- a/.gitignore\n+++ b/.gitignore\n@@ -1,2 +1 @@\n-build/\n .env\n")
	e.d.Stop(ctx, "sens", api.StopRequest{})
	if _, err := e.d.Apply(ctx, "sens", api.ApplyRequest{}); errCode(err) != api.CodeBadRequest || !strings.Contains(err.Error(), ".gitignore") {
		t.Fatalf("sensitive without the flag: %v", err)
	}
	if readFile(t, filepath.Join(ws, "a.txt")) != "old\n" {
		t.Fatal("written although refused")
	}

	// check: decided, completed as not written, nothing written
	box("ok", modify("a.txt")+newFile("tool.sh", "echo hi")+newFile("build/out.o", "junk"))
	e.d.Stop(ctx, "ok", api.StopRequest{})
	ri := len(e.tk.Runs) - 1
	res, err := e.d.Apply(ctx, "ok", api.ApplyRequest{Check: true})
	if err != nil || !res.Checked || !slices.Equal(res.Applied, []string{"a.txt", "tool.sh"}) || !slices.Equal(res.Ignored, []string{"build/out.o"}) {
		t.Fatalf("check %+v %v", res, err)
	}
	checkCompletes := 0
	for _, r := range e.tk.Runs[ri].Records {
		if r.Method == "complete" && r.Call.Tool == tracekit.ToolWrite {
			checkCompletes++
			if v, _ := r.Value.(map[string]any); r.Status != "error" || v["reason"] != "check only" {
				t.Fatalf("check complete %+v", r)
			}
		}
	}
	if checkCompletes != 2 || readFile(t, filepath.Join(ws, "a.txt")) != "old\n" {
		t.Fatalf("check completes %d", checkCompletes)
	}

	// apply: no filter ran, the Write args name the new content, mode and the patch
	res, err = e.d.Apply(ctx, "ok", api.ApplyRequest{})
	if err != nil || !slices.Equal(res.Applied, []string{"a.txt", "tool.sh"}) || res.SHA256 == "" {
		t.Fatalf("apply %+v %v", res, err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a git filter driver from the checkout's config ran on the host")
	}
	if _, err := os.Stat(filepath.Join(ws, "build", "out.o")); err == nil {
		t.Fatal("an ignored new file was written")
	}
	newSum := sha256.Sum256([]byte("new\n"))
	var args map[string]any
	for _, r := range e.tk.Runs[ri].Records {
		if r.Method == "decide" && r.Call.Tool == tracekit.ToolWrite && r.Call.Args["file_path"] == filepath.Join(ws, "a.txt") {
			args = r.Call.Args
		}
	}
	if args["sha256"] != hex.EncodeToString(newSum[:]) || args["mode"] != "100644" || args["patch_sha256"] != res.SHA256 || args["symlink"] != false {
		t.Fatalf("write args %v", args)
	}
	if fi, err := os.Stat(filepath.Join(ws, "tool.sh")); err != nil || fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("tool.sh not executable: %v", err)
	}

	// after export the run is closed: say so, write nothing
	e.d.Export(ctx, "ok", api.ExportRequest{Out: filepath.Join(t.TempDir(), "ok.tkb")})
	if _, err := e.d.Apply(ctx, "ok", api.ApplyRequest{Dir: t.TempDir()}); errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "closed by `tkbox export`") {
		t.Fatalf("apply after export: %v", err)
	}
}

// S8: the decision covers cwd, env (placeholders redacted) and stdin; loader env is refused.
func TestBashArgsCoverEverythingThatRuns(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "a", Secrets: map[string]api.SecretSpec{"TOK": {Value: "s3cret-value", Hosts: []string{"api.example.com"}}}})
	ph := e.box("a").view().Secrets[0]
	_ = ph
	var placeholder string
	for _, s := range e.box("a").secrets {
		placeholder = s.Placeholder
	}
	sock := e.serve()
	execStream(t, sock, "a", api.ExecRequest{Argv: []string{"env"}, Cwd: "/workspace/sub", Env: map[string]string{"X": "1", "T": placeholder, "V": "s3cret-value"}}, nil)
	var args map[string]any
	for _, r := range e.run(0).Records {
		if r.Method == "decide" && r.Call.Tool == tracekit.ToolBash {
			args = r.Call.Args
		}
	}
	env, _ := args["env"].(map[string]any)
	if args["command"] != "env" || args["cwd"] != "/workspace/sub" || args["stdin"] != false || env["X"] != "1" ||
		env["T"] != "tkbox_TOK_…" || env["V"] != "[secret TOK]" {
		t.Fatalf("bash args %v", args)
	}
	if _, e2 := e.d.prepareExec("a", api.ExecRequest{Argv: []string{"ls"}, Env: map[string]string{"LD_PRELOAD": "/x.so"}}); e2 == nil || !strings.Contains(e2.Message, "LD_PRELOAD") {
		t.Fatalf("LD_PRELOAD: %v", e2)
	}
}

// S7: a must-record observe that the signer refuses stops the box; bulk refusals are rate-limited.
func TestMustRecordFailsClosed(t *testing.T) {
	e := newTestEnv(t, nil)
	fc := &failingClient{Client: e.tk, fail: map[string]bool{tracekit.SourceSecretUse: true}}
	e.opts.Tracekit = fc
	e.d.opts.Tracekit = fc
	e.create(api.CreateBoxRequest{Name: "m"})
	sink := e.proxy(0).cfg.Sink
	for range 200 {
		sink.Emit(egress.Event{Kind: egress.EventDenied, Host: "x.example", Port: 443, Reason: "off the allowlist"})
	}
	sink.Emit(egress.Event{Kind: egress.EventSecretUse, Host: "api.example.com", Port: 443, Secret: "T"})
	deadline := time.Now().Add(10 * time.Second)
	for alive(e.box("m").state()) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	v, _ := e.d.Get("m")
	if v.State != api.StateStopped || !strings.Contains(v.StopReason, "could not record tkbox.secret.use") {
		t.Fatalf("box %+v", v)
	}
	egressObs := 0
	for _, r := range e.run(0).Records {
		if r.Method == "observe" && r.Source == tracekit.SourceEgress {
			egressObs++
		}
	}
	if egressObs > bulkRate+2 || egressObs == 0 {
		t.Fatalf("%d egress observes for 200 refusals", egressObs)
	}
}

type failingClient struct {
	tracekit.Client
	fail map[string]bool
}

func (c *failingClient) NewRun(ctx context.Context, a tracekit.Agent) (tracekit.Run, error) {
	r, err := c.Client.NewRun(ctx, a)
	if err != nil {
		return nil, err
	}
	return &failingRun{Run: r, fail: c.fail}, nil
}

type failingRun struct {
	tracekit.Run
	fail map[string]bool
}

func (r *failingRun) Observe(ctx context.Context, source, trust string, value any) error {
	if r.fail[source] {
		return &tracekit.RPCError{Code: "internal", Message: "refused"}
	}
	return r.Run.Observe(ctx, source, trust, value)
}

// S9: pending approvals are capped per box and withdrawn when no connection waits.
func TestApprovalCapAndWithdraw(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.ApprovalTimeout = time.Minute })
	e.create(api.CreateBoxRequest{Name: "ap"})
	dec := e.proxy(0).cfg.Decider
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := range maxPendingApprovals {
		wg.Add(1)
		go func() {
			defer wg.Done()
			host := "h" + string(rune('a'+i)) + ".example"
			dec.Decide(ctx, egress.Request{Host: host, Port: 443, URL: "https://" + host + ":443"})
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(e.d.Approvals()) < maxPendingApprovals && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if a := e.d.Approvals(); len(a) != maxPendingApprovals || a[0].Waiters != 1 {
		t.Fatalf("approvals %+v", a)
	}
	v, _ := dec.Decide(context.Background(), egress.Request{Host: "one-more.example", Port: 443, URL: "https://one-more.example:443"})
	if v.Allow || !strings.Contains(v.Reason, "too many pending approvals") {
		t.Fatalf("over the cap: %+v", v)
	}
	cancel() // every waiting connection gives up
	wg.Wait()
	if a := e.d.Approvals(); len(a) != 0 {
		t.Fatalf("approvals not withdrawn: %+v", a)
	}
}

// S12: no host address list, no box.
func TestNoHostAddressesNoBox(t *testing.T) {
	e := newTestEnv(t, nil)
	old := hostPrefixes
	hostPrefixes = func() ([]netip.Prefix, error) { return nil, errors.New("netlink: permission denied") }
	defer func() { hostPrefixes = old }()
	if _, err := e.d.Create(context.Background(), api.CreateBoxRequest{Image: "x"}); err == nil || !strings.Contains(err.Error(), "addresses") {
		t.Fatalf("create without host addresses: %v", err)
	}
}

// S7: events.ndjson stops taking bulk lines at its cap but keeps must-record lines.
func TestEventLogCap(t *testing.T) {
	l := openEventLog(t.TempDir())
	l.max = 2000
	for range 50 {
		l.write(api.Event{Kind: api.EventEgressDenied, Summary: strings.Repeat("d", 50)})
	}
	l.write(api.Event{Kind: api.EventSecretLeak, Summary: "leak"})
	b, _ := os.ReadFile(l.path)
	s := string(b)
	if strings.Count(s, eventLogCapped) != 1 || !strings.Contains(s, "leak") || len(s) > 2600 {
		t.Fatalf("log %d bytes, cap lines %d", len(s), strings.Count(s, eventLogCapped))
	}
}

// S9: the boot config is served once.
func TestBootConfigServedOnce(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "bc"})
	b := e.box("bc")
	l := &chanListener{c: make(chan net.Conn, 2), closed: make(chan struct{})}
	go b.serveBootConfig(l)
	ask := func() error {
		c1, c2 := net.Pipe()
		l.c <- c2
		defer c1.Close()
		c1.SetDeadline(time.Now().Add(2 * time.Second))
		proto.WriteJSON(c1, proto.TypeJSON, proto.BootConfigRequest{Op: proto.OpBootConfig})
		f, err := proto.ReadFrame(c1)
		if err != nil {
			return err
		}
		if f.Type != proto.TypeJSON {
			return errors.New("not a config")
		}
		return nil
	}
	if err := ask(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the boot config port stayed open after the guest fetched it")
	}
}

type chanListener struct {
	c      chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.c:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *chanListener) Addr() net.Addr { return &net.UnixAddr{} }
