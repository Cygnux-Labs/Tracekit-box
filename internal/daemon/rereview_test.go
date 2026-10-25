package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
	"github.com/Cygnux-Labs/tracekit-box/internal/vmm"
	"github.com/Cygnux-Labs/tracekit-box/internal/vmm/vmmfake"
)

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func newFileSection(name, content string) string {
	return "diff --git a/" + name + " b/" + name + "\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/" + name +
		"\n@@ -0,0 +1 @@\n+" + content + "\n"
}

// N1: a section whose old and new names differ without a rename header is refused (git apply would delete the old
// file with no decision about it), and every path git apply touches is a decided target.
func TestRereviewPatchOldNewDiffer(t *testing.T) {
	dir := t.TempDir()
	differ := "diff --git a/.gitignore b/notes.txt\nindex 1111111..2222222 100644\n--- a/.gitignore\n+++ b/notes.txt\n@@ -1 +1 @@\n-build/\n+notes\n"
	files, err := parsePatch(differ)
	if err != nil {
		t.Fatal(err)
	}
	if _, problems := checkPatch(files, dir); len(problems) == 0 || !strings.Contains(strings.Join(problems, "; "), "without a rename or copy header") {
		t.Fatalf("problems %v", problems)
	}
	// a deletion without "deleted file mode" still deletes: its path is a target
	files, err = parsePatch("diff --git a/x b/x\nindex 1111111..0000000\n--- a/x\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n")
	if err != nil {
		t.Fatal(err)
	}
	if paths, problems := checkPatch(files, dir); len(problems) != 0 || !slices.Equal(paths, []string{"x"}) {
		t.Fatalf("deletion without its header: paths %v problems %v", paths, problems)
	}

	// end to end: nothing is applied and .gitignore stays
	needGit(t)
	e := newTestEnv(t, nil)
	ws := t.TempDir()
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, ".gitignore"), []byte("build/\n"), 0o644)
	e.guest.Patch = differ
	e.create(api.CreateBoxRequest{Name: "n1", Workspace: ws})
	e.d.Stop(context.Background(), "n1", api.StopRequest{})
	if _, err := e.d.Apply(context.Background(), "n1", api.ApplyRequest{AllowSensitive: true}); err == nil || !strings.Contains(err.Error(), "without a rename or copy header") {
		t.Fatalf("apply: %v", err)
	}
	if readFile(t, filepath.Join(ws, ".gitignore")) != "build/\n" {
		t.Fatal(".gitignore changed")
	}
	if _, err := os.Stat(filepath.Join(ws, "notes.txt")); err == nil {
		t.Fatal("notes.txt written")
	}
}

// N4: two applies of one box never run at once, and each has its own patch file.
func TestRereviewConcurrentApplies(t *testing.T) {
	needGit(t)
	var active, overlapped atomic.Int32
	e := newTestEnv(t, func(o *Options) {
		o.Gate = func(ctx context.Context, r tracekit.Run, call tracekit.Call, h tracekit.GateHooks) (tracekit.Outcome, error) {
			if call.Tool == tracekit.ToolWrite {
				if active.Add(1) > 1 {
					overlapped.Store(1)
				}
				time.Sleep(300 * time.Millisecond) // room for another apply to come in
				defer active.Add(-1)
			}
			return fakeGate(ctx, r, call, h)
		}
	})
	ws, other := t.TempDir(), t.TempDir()
	for _, d := range []string{ws, other} {
		gitInit(t, d)
		os.WriteFile(filepath.Join(d, "a.txt"), []byte("old\n"), 0o644)
	}
	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "n4", Workspace: ws})
	e.d.Stop(context.Background(), "n4", api.StopRequest{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, d := range []string{ws, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = e.d.Apply(context.Background(), "n4", api.ApplyRequest{Dir: d})
		}()
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("applies: %v / %v", errs[0], errs[1])
	}
	if overlapped.Load() != 0 {
		t.Fatal("two applies of one box ran at once")
	}
	for _, d := range []string{ws, other} {
		if readFile(t, filepath.Join(d, "a.txt")) != "new\n" {
			t.Fatalf("%s not applied", d)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(e.box("n4").dir, "*apply*.patch")); len(left) != 0 {
		t.Fatalf("patch files left: %v", left)
	}
}

// N5: the hooks dir is git's own answer (core.hooksPath from the global config counts), and writes into it are
// refused whatever their case.
func TestRereviewHooksDir(t *testing.T) {
	needGit(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	e := newTestEnv(t, nil)
	ctx := context.Background()

	// core.hooksPath in the global config only
	ws := t.TempDir()
	gitInit(t, ws)
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[core]\n\thooksPath = "+filepath.Join(ws, "myhooks")+"\n"), 0o644)
	e.guest.Patch = newFileSection("myhooks/pre-commit", "evil")
	e.create(api.CreateBoxRequest{Name: "glob", Workspace: ws})
	e.d.Stop(ctx, "glob", api.StopRequest{})
	if _, err := e.d.Apply(ctx, "glob", api.ApplyRequest{AllowSensitive: true}); err == nil || !strings.Contains(err.Error(), "hooks dir") {
		t.Fatalf("global core.hooksPath: %v", err)
	}
	os.Remove(filepath.Join(home, ".gitconfig"))

	// core.hooksPath in the repo, written in another case
	ws2 := t.TempDir()
	gitInit(t, ws2)
	gitIn(t, ws2, "config", "core.hooksPath", "githooks")
	os.Mkdir(filepath.Join(ws2, "githooks"), 0o755)
	e.guest.Patch = newFileSection("GitHooks/pre-commit", "evil")
	e.create(api.CreateBoxRequest{Name: "case", Workspace: ws2})
	e.d.Stop(ctx, "case", api.StopRequest{})
	if _, err := e.d.Apply(ctx, "case", api.ApplyRequest{AllowSensitive: true}); err == nil || !strings.Contains(err.Error(), "hooks dir") {
		t.Fatalf("hooks dir in another case: %v", err)
	}
	if ents, _ := os.ReadDir(filepath.Join(ws2, "githooks")); len(ents) != 0 {
		t.Fatalf("written into the hooks dir: %v", ents)
	}

	// .git look-alikes
	for _, p := range []string{".GIT/hooks/x", ".git‌/config", "GIT~1/config", "sub/.Git./x"} {
		if err := checkRelPath(p); err == nil || !strings.Contains(err.Error(), "touches .git") {
			t.Errorf("%q: %v", p, err)
		}
	}
}

// N7: once decided, git apply runs under the daemon's context (a client that goes away does not stop it half way),
// and a failed git apply says which files it wrote.
func TestRereviewApplyContextAndPartialWrite(t *testing.T) {
	needGit(t)
	reqCtx, cancelReq := context.WithCancel(context.Background())
	defer cancelReq()
	var hook atomic.Pointer[func()]
	e := newTestEnv(t, func(o *Options) {
		o.Gate = func(ctx context.Context, r tracekit.Run, call tracekit.Call, h tracekit.GateHooks) (tracekit.Outcome, error) {
			out, err := fakeGate(ctx, r, call, h)
			if f := hook.Load(); f != nil && call.Tool == tracekit.ToolWrite {
				(*f)()
			}
			return out, err
		}
	})
	ws := t.TempDir()
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "ctx", Workspace: ws})
	e.d.Stop(context.Background(), "ctx", api.StopRequest{})
	cancel := func() { cancelReq() }
	hook.Store(&cancel) // the client goes away right after the decision
	if _, err := e.d.Apply(reqCtx, "ctx", api.ApplyRequest{}); err != nil {
		t.Fatalf("apply after the client went away: %v", err)
	}
	if readFile(t, filepath.Join(ws, "a.txt")) != "new\n" {
		t.Fatal("not applied")
	}

	if os.Geteuid() == 0 {
		t.Skip("root writes into read-only dirs")
	}
	ws2 := t.TempDir()
	gitInit(t, ws2)
	os.WriteFile(filepath.Join(ws2, "a.txt"), []byte("old\n"), 0o644)
	sub := filepath.Join(ws2, "sub")
	os.Mkdir(sub, 0o755)
	defer os.Chmod(sub, 0o755)
	e.guest.Patch = modify("a.txt") + newFileSection("sub/new.txt", "x")
	e.create(api.CreateBoxRequest{Name: "part", Workspace: ws2})
	e.d.Stop(context.Background(), "part", api.StopRequest{})
	lock := func() { os.Chmod(sub, 0o555) } // git apply can write a.txt but not sub/new.txt
	hook.Store(&lock)
	_, err := e.d.Apply(context.Background(), "part", api.ApplyRequest{})
	if err == nil || !strings.Contains(err.Error(), "after writing 1 file: a.txt") {
		t.Fatalf("partial apply: %v", err)
	}
}

// N8: a checkout that is no longer a git work tree can't say what it ignores: refused when the box's workspace was
// one; a workspace that was never one ignores nothing and applies.
func TestRereviewIgnoredFailsClosed(t *testing.T) {
	needGit(t)
	e := newTestEnv(t, nil)
	ctx := context.Background()
	ws := t.TempDir()
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "wasgit", Workspace: ws})
	e.d.Stop(ctx, "wasgit", api.StopRequest{})
	os.RemoveAll(filepath.Join(ws, ".git"))
	if _, err := e.d.Apply(ctx, "wasgit", api.ApplyRequest{}); err == nil || !strings.Contains(err.Error(), "is not a git work tree") {
		t.Fatalf("apply to a checkout that lost its .git: %v", err)
	}
	if readFile(t, filepath.Join(ws, "a.txt")) != "old\n" {
		t.Fatal("applied")
	}

	plain := t.TempDir()
	os.WriteFile(filepath.Join(plain, "a.txt"), []byte("old\n"), 0o644)
	e.create(api.CreateBoxRequest{Name: "plain", Workspace: plain})
	e.d.Stop(ctx, "plain", api.StopRequest{})
	if _, err := e.d.Apply(ctx, "plain", api.ApplyRequest{}); err != nil {
		t.Fatalf("apply to a workspace that never was a git work tree: %v", err)
	}
	if readFile(t, filepath.Join(plain, "a.txt")) != "new\n" {
		t.Fatal("not applied")
	}
}

// N9: events.ndjson has a hard cap: past it nothing more is written (beyond the stop's reserve) and the box stops.
func TestRereviewEventLogHardCap(t *testing.T) {
	l := openEventLog(t.TempDir())
	l.max, l.hardMax = 1000, 3000
	var hits atomic.Int32
	l.onHardCap = func() { hits.Add(1) }
	for range 2000 {
		l.write(api.Event{Kind: api.EventSecretUse, Summary: strings.Repeat("s", 100)})
	}
	fi, _ := os.Stat(l.path)
	time.Sleep(50 * time.Millisecond)
	if fi.Size() > 3000+eventLogReserve || hits.Load() != 1 {
		t.Fatalf("log %d bytes, %d hard-cap calls", fi.Size(), hits.Load())
	}
	if !strings.Contains(readFile(t, l.path), "hard cap") {
		t.Fatal("no hard-cap line")
	}

	old := maxEventLogHard
	maxEventLogHard = 20000
	defer func() { maxEventLogHard = old }()
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "loud"})
	sink := e.proxy(0).cfg.Sink
	for range 500 {
		sink.Emit(egress.Event{Kind: egress.EventSecretUse, Host: "api.example.com", Port: 443, Secret: "T"})
	}
	deadline := time.Now().Add(10 * time.Second)
	for alive(e.box("loud").state()) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if v, _ := e.d.Get("loud"); v.State != api.StateStopped || v.StopReason != eventLogHardCapReason {
		t.Fatalf("box %s: %q", v.State, v.StopReason)
	}
}

// N6: a box may open at most maxNewApprovals approvals a minute; withdrawn ones leave the map at once.
func TestRereviewApprovalRate(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.ApprovalTimeout = time.Minute })
	e.create(api.CreateBoxRequest{Name: "churn"})
	dec := e.proxy(0).cfg.Decider
	open := func(i int) egress.Verdict {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		host := fmt.Sprintf("h%d.example", i)
		got := make(chan egress.Verdict, 1)
		go func() {
			v, _ := dec.Decide(ctx, egress.Request{Host: host, Port: 443, URL: "https://" + host + ":443"})
			got <- v
		}()
		deadline := time.Now().Add(5 * time.Second)
		for len(e.d.Approvals()) == 0 && time.Now().Before(deadline) {
			select {
			case v := <-got: // refused at once
				return v
			default:
			}
			time.Sleep(2 * time.Millisecond)
		}
		cancel() // the connection gives up: the approval is withdrawn
		return <-got
	}
	for i := range maxNewApprovals {
		if v := open(i); v.Allow || strings.Contains(v.Reason, "in the last") {
			t.Fatalf("approval %d: %+v", i, v)
		}
		e.d.mu.Lock()
		n := len(e.d.approvals)
		e.d.mu.Unlock()
		if n != 0 {
			t.Fatalf("withdrawn approval %d kept (%d in the map)", i, n)
		}
	}
	start := time.Now()
	if v := open(maxNewApprovals); v.Allow || !strings.Contains(v.Reason, "approvals in the last") {
		t.Fatalf("over the rate: %+v", v)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("over the rate was not refused at once")
	}
}

// C3: export and rm never close a run under an in-flight call (an apply waiting for approval), however short the
// waits are.
func TestRereviewExportRmWaitForCalls(t *testing.T) {
	needGit(t)
	oldWait, oldGrace := runCloseWait, inFlightGrace
	runCloseWait, inFlightGrace = 0, 0
	defer func() { runCloseWait, inFlightGrace = oldWait, oldGrace }()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e := newTestEnv(t, func(o *Options) {
		o.Gate = func(ctx context.Context, r tracekit.Run, call tracekit.Call, h tracekit.GateHooks) (tracekit.Outcome, error) {
			if call.Tool == tracekit.ToolWrite {
				once.Do(func() { close(entered) })
				<-release // waiting for a person
			}
			return fakeGate(ctx, r, call, h)
		}
	})
	ws := t.TempDir()
	gitInit(t, ws)
	os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "c3", Workspace: ws})
	e.d.Stop(context.Background(), "c3", api.StopRequest{})
	applied := make(chan error, 1)
	go func() {
		_, err := e.d.Apply(context.Background(), "c3", api.ApplyRequest{})
		applied <- err
	}()
	<-entered
	out := filepath.Join(t.TempDir(), "c3.tkb")
	if _, err := e.d.Export(context.Background(), "c3", api.ExportRequest{Out: out}); errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "1 call in flight") {
		t.Fatalf("export under an apply: %v", err)
	}
	if err := e.d.Remove(context.Background(), "c3"); errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "in flight") {
		t.Fatalf("rm under an apply: %v", err)
	}
	if slices.Contains(e.run(0).Methods(), "close") {
		t.Fatal("the run was closed under the apply")
	}
	close(release)
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	if _, err := e.d.Export(context.Background(), "c3", api.ExportRequest{Out: out}); err != nil {
		t.Fatalf("export after the apply: %v", err)
	}
}

// N2: a flush that gives up waits for the observer to stop counting before the gap is recorded, so every record is
// either in the run or in the tkbox.gap record.
func TestRereviewFlushGapCountsEverything(t *testing.T) {
	oldFlush := observerFlushWait
	observerFlushWait = 100 * time.Millisecond
	defer func() { observerFlushWait = oldFlush }()
	e := newTestEnv(t, nil)
	fc := &failingClient{Client: e.tk, slow: map[string]time.Duration{tracekit.SourceSecretUse: 300 * time.Millisecond}}
	e.d.opts.Tracekit = fc
	e.create(api.CreateBoxRequest{Name: "slow"})
	sink := e.proxy(0).cfg.Sink
	const n = 20
	for range n {
		sink.Emit(egress.Event{Kind: egress.EventSecretUse, Host: "api.example.com", Port: 443, Secret: "T"})
	}
	time.Sleep(50 * time.Millisecond)
	e.d.Stop(context.Background(), "slow", api.StopRequest{})
	uses, dropped := 0, 0
	for _, r := range e.run(0).Records {
		if r.Method != "observe" {
			continue
		}
		switch r.Source {
		case tracekit.SourceSecretUse:
			uses++
		case sourceGap:
			dropped += r.Value.(map[string]any)["dropped"].(int)
		}
	}
	if uses+dropped != n {
		t.Fatalf("%d recorded + %d in the gap, want %d accounted for", uses, dropped, n)
	}
	if slices.Contains(e.run(0).Methods(), "close") {
		t.Fatal("the run was closed although the gap record covers every loss")
	}
}

// N2: an observer that does not stop in time leaves the loss uncounted: the run is closed with "records lost".
func TestRereviewObserverNotStoppedClosesRun(t *testing.T) {
	oldFlush, oldStop := observerFlushWait, observerStopWait
	observerFlushWait, observerStopWait = 100*time.Millisecond, 200*time.Millisecond
	defer func() { observerFlushWait, observerStopWait = oldFlush, oldStop }()
	e := newTestEnv(t, nil)
	fc := &failingClient{Client: e.tk, slow: map[string]time.Duration{tracekit.SourceSecretUse: 2 * time.Second}}
	e.d.opts.Tracekit = fc
	e.guest.Patch = modify("a.txt")
	e.create(api.CreateBoxRequest{Name: "hung"})
	sink := e.proxy(0).cfg.Sink
	for range 5 {
		sink.Emit(egress.Event{Kind: egress.EventSecretUse, Host: "api.example.com", Port: 443, Secret: "T"})
	}
	time.Sleep(50 * time.Millisecond)
	e.d.Stop(context.Background(), "hung", api.StopRequest{})
	reason := ""
	for _, r := range e.run(0).Records {
		if r.Method == "close" {
			reason = r.Reason
		}
	}
	if !strings.Contains(reason, "records lost") {
		t.Fatalf("close reason %q", reason)
	}
	if _, err := e.d.Apply(context.Background(), "hung", api.ApplyRequest{Dir: t.TempDir()}); errCode(err) != api.CodeConflict || !strings.Contains(err.Error(), "records lost") {
		t.Fatalf("apply after lost records: %v", err)
	}
}

// N3: the daemon never hands a process a false EOF when its stdin overflows: it is killed and its exit status says
// so (StdinTruncated, the bytes dropped).
func TestRereviewStdinOverflowKills(t *testing.T) {
	e := newTestEnv(t, nil)
	e.guest.ExecFunc = func(ctx context.Context, req proto.ExecRequest, xio agentrpc.ExecIO) (proto.ExitStatus, error) {
		select { // never reads stdin
		case s := <-xio.Signals:
			return proto.ExitStatus{Code: -1, Signal: s}, nil
		case <-time.After(3 * time.Second):
			return proto.ExitStatus{Code: 0}, nil // as if it had read everything
		case <-ctx.Done():
			return proto.ExitStatus{}, ctx.Err()
		}
	}
	e.create(api.CreateBoxRequest{Name: "in"})
	sock := e.serve()
	c, br := execConn(t, sock, "in", api.ExecRequest{Argv: []string{"cat"}, Stdin: true})
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
	chunk := make([]byte, 512<<10)
	for range 10 { // 5 MiB: past the 4 MiB buffer
		if proto.WriteFrame(c, proto.TypeStdin, chunk) != nil {
			break // the command was already stopped and the stream closed
		}
	}
	proto.WriteFrame(c, proto.TypeStdinEOF, nil)
	f := lastFrame(t, c, br)
	var st proto.ExitStatus
	json.Unmarshal(f.Payload, &st)
	if f.Type != proto.TypeExit || !st.StdinTruncated || st.StdinDroppedBytes <= 0 || st.Signal != "SIGKILL" {
		t.Fatalf("overflowed stdin: %d %s", f.Type, f.Payload)
	}
	var complete map[string]any
	for _, r := range e.run(0).Records {
		if r.Method == "complete" && r.Call.Tool == tracekit.ToolBash {
			complete, _ = r.Value.(map[string]any)
			if r.Status != "error" {
				t.Fatalf("complete status %s", r.Status)
			}
		}
	}
	if complete["stdin_truncated"] != true {
		t.Fatalf("complete %v", complete)
	}
}

// S5: files that steer host automation, and credential files, need --allow-sensitive.
func TestRereviewSensitivePaths(t *testing.T) {
	for p, want := range map[string]bool{
		".github/actions/setup/action.yml": true, ".vscode/tasks.json": true, ".cargo/config.toml": true,
		".yarnrc.yml": true, "lefthook.yml": true, ".gitlab-ci.yml": true, ".circleci/config.yml": true,
		".devcontainer/devcontainer.json": true, "sub/.npmrc": true, ".netrc": true, ".pypirc": true, "deploy/key.pem": true,
		"certs/server.key": true, ".env": true, ".ssh/config": true, ".github/workflows/ci.yml": true,
		"src/main.go": false, ".vscode/settings.json": false, "docs/actions.md": false, "cargo/config.toml": false,
		".github/CODEOWNERS": false, "README.md": false,
	} {
		if got := isSensitive(p); got != want {
			t.Errorf("isSensitive(%q) = %v, want %v", p, got, want)
		}
	}
}

// markerLauncher's machines say the marker when asked why they exited (as a real VM's error carries console text).
type markerLauncher struct {
	*vmmfake.Launcher
	marker string
}

type markerMachine struct {
	vmm.Machine
	marker string
}

func (m markerMachine) Err() error { return errors.New("console: " + m.marker) }

func (l markerLauncher) New(spec vmm.Spec) (vmm.Machine, error) {
	m, err := l.Launcher.New(spec)
	if err != nil {
		return nil, err
	}
	return markerMachine{Machine: m, marker: l.marker}, nil
}

// S11: text from the guest or the VM's console never reaches a trusted observe or a close reason (only
// events.ndjson).
func TestRereviewNoGuestTextInTrustedRecords(t *testing.T) {
	const marker = "GUEST-SAYS-x9q"
	check := func(t *testing.T, e *testEnv, run int, boxID string) {
		t.Helper()
		for _, r := range e.run(run).Records {
			if r.Method == "observe" && r.Trust == trustedObs && strings.Contains(fmt.Sprint(r.Value), marker) {
				t.Fatalf("guest text in a trusted observe: %+v", r)
			}
			if r.Method == "close" && strings.Contains(r.Reason, marker) {
				t.Fatalf("guest text in the close reason: %q", r.Reason)
			}
		}
		if !strings.Contains(readFile(t, filepath.Join(e.d.boxDir(boxID), "events.ndjson")), marker) {
			t.Fatal("the guest's text is not even in events.ndjson (the test did not exercise it)")
		}
	}
	t.Run("never ready", func(t *testing.T) {
		e := newTestEnv(t, func(o *Options) { o.ReadyTimeout = 300 * time.Millisecond })
		e.guest.PingErr = errors.New(marker)
		b, err := e.d.Create(context.Background(), api.CreateBoxRequest{Image: "x", Name: "nr"})
		if err == nil || strings.Contains(err.Error(), marker) || strings.Contains(b.Error, marker) {
			t.Fatalf("create: %v (%q)", err, b.Error)
		}
		check(t, e, 0, b.ID)
	})
	t.Run("vm exits", func(t *testing.T) {
		var e *testEnv
		e = newTestEnv(t, func(o *Options) {
			o.Launcher = markerLauncher{Launcher: &vmmfake.Launcher{}, marker: marker}
		})
		b := e.create(api.CreateBoxRequest{Name: "ex"})
		e.box("ex").machine.Kill() // the VM dies on its own
		deadline := time.Now().Add(5 * time.Second)
		for alive(e.box("ex").state()) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if v, _ := e.d.Get("ex"); v.State != api.StateFailed || strings.Contains(v.Error, marker) {
			t.Fatalf("box %+v", v)
		}
		check(t, e, 0, b.ID)
	})
}
