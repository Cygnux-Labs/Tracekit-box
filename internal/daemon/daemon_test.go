package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentchannel"
	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit/tracekitfake"
)

const secretValue = "ghp_S3CRET-value-never-on-disk"

func TestCreateAbandonedByClient(t *testing.T) {
	e := newTestEnv(t, nil)
	e.guest.PingErr = errors.New("not yet") // booting forever
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err := e.d.Create(ctx, api.CreateBoxRequest{Name: "gone", Image: "x"})
	if err == nil || !strings.Contains(err.Error(), "the client went away") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := e.d.Get("gone"); b.State != api.StateFailed || e.machine(0).State != "stopped" || !e.run(0).Closed {
		t.Fatalf("box %+v machine %s", b, e.machine(0).State)
	}
}

func TestAgentChannelRequiresProtocol21(t *testing.T) {
	e := newTestEnv(t, nil)
	_, err := e.d.Create(context.Background(), api.CreateBoxRequest{Image: "x", AgentChannel: true})
	if err == nil || !strings.Contains(err.Error(), "Tracekit 1.6.0") || !strings.Contains(err.Error(), "RPC protocol 21") {
		t.Fatalf("protocol 19 signer accepted for --agent-channel: %v", err)
	}
	if len(e.launcher.Machines) != 0 {
		t.Fatal("box launched before protocol 21 check")
	}
}

func TestAgentChannelAllowLabelValidation(t *testing.T) {
	valid := []string{"example.com", "*.example.com:8443", "[2001:db8::1]", strings.Repeat("a", 261)}
	if err := validateBoxLabelAllow(valid); err != nil {
		t.Fatalf("valid label allow entries rejected: %v", err)
	}
	for _, name := range []string{"bad/name", strings.Repeat("a", 262)} {
		if err := validateBoxLabelAllow([]string{name}); err == nil {
			t.Errorf("invalid label entry accepted: %q", name)
		}
	}
	if err := validateBoxLabelAllow(make([]string, 257)); err == nil {
		t.Fatal("accepted more than 256 label entries")
	}
}

// What the agent channel refuses becomes the box's channel.refused events (kind, method, reason; never the frame),
// one per kind a second, the rest counted in: a refusal used to leave no trace on the host.
func TestAgentChannelRefusalsAreBoxEvents(t *testing.T) {
	e := newTestEnv(t, nil)
	e.tk.RPCVersion = 21
	e.tk.ChannelDial = func() (net.Conn, error) {
		a, z := net.Pipe()
		go io.Copy(io.Discard, z)
		return a, nil
	}
	v := e.create(api.CreateBoxRequest{Name: "refusals", Image: "x", AgentChannel: true})
	c, err := e.machine(0).GuestDial(context.Background(), proto.PortAgentChannel)
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	const body = "frame-content-never-on-disk"
	for _, frame := range []string{
		`{"method":"approval_decide","approval_id":"` + body + `"}`,
		`{"method":"approval_decide","approval_id":"` + body + `"}`,
		`{"method":"approval_decide","approval_id":"` + body + `"}`,
		`{"method":"close_run","run_id":"` + v.RunID + `","run_token":"` + body + `"}`,
	} {
		if _, err := c.Write([]byte(frame + "\n")); err != nil {
			t.Fatal(err)
		}
		if line, err := r.ReadBytes('\n'); err != nil || !strings.Contains(string(line), `"forbidden"`) {
			t.Fatalf("%s: %q %v", frame, line, err)
		}
	}
	c.Close()
	if _, err := e.d.Stop(context.Background(), "refusals", api.StopRequest{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(e.d.boxDir(v.ID), "events.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), body) {
		t.Fatal("events.ndjson holds the refused frame's content")
	}
	var got []string
	for _, ln := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var ev api.Event
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Kind == api.EventChannelRefused {
			got = append(got, ev.Door+" "+ev.Summary)
		}
	}
	want := []string{
		"agent_channel agent channel refused approval_decide (method): method not allowed",
		"agent_channel agent channel refused close_run (run): run is not owned by this box",
		"agent_channel agent channel refused 2 more frames (method) since its last event",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("channel.refused events\n%q\nwant\n%q", got, want)
	}
}

type stopOrderLog struct {
	mu      sync.Mutex
	entries []string
}

func (l *stopOrderLog) add(s string) { l.mu.Lock(); l.entries = append(l.entries, s); l.mu.Unlock() }
func (l *stopOrderLog) got() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.entries...)
}

type stopOrderConn struct {
	net.Conn
	log   *stopOrderLog
	label string
	once  sync.Once
}

func (c *stopOrderConn) Close() error {
	if c.label != "" {
		c.once.Do(func() { c.log.add(c.label) })
	}
	return c.Conn.Close()
}

type stopOrderListener struct {
	net.Listener
	log *stopOrderLog
}

func (l stopOrderListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &stopOrderConn{Conn: c, log: l.log, label: "guest_connection"}, nil
}
func (l stopOrderListener) Close() error { l.log.add("listener"); return l.Listener.Close() }

type stopOrderRun struct {
	tracekit.Run
	log *stopOrderLog
}

func (r stopOrderRun) Close(ctx context.Context, reason string) error {
	r.log.add("box_run")
	return r.Run.Close(ctx, reason)
}

func TestStopOrderListenerConnectionsChannelRunBoxRun(t *testing.T) {
	e := newTestEnv(t, nil)
	v := e.create(api.CreateBoxRequest{Name: "channel-order", Image: "x"})
	e.d.mu.Lock()
	b := e.d.boxes[v.ID]
	e.d.mu.Unlock()
	order := &stopOrderLog{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var dialMu sync.Mutex
	dials := 0
	ch := agentchannel.New(func(context.Context) (net.Conn, error) {
		dialMu.Lock()
		dials++
		call := dials
		dialMu.Unlock()
		a, z := net.Pipe()
		go func() {
			line, err := bufio.NewReader(z).ReadBytes('\n')
			if err != nil {
				_ = z.Close()
				return
			}
			var req map[string]any
			_ = json.Unmarshal(line, &req)
			if call == 1 {
				answer := `{"run_id":"channel-run","run_token":"channel-token"}`
				_, _ = z.Write([]byte(answer + "\n"))
				_, _ = bufio.NewReader(z).ReadBytes('\n')
			} else {
				order.add("channel_run")
				_, _ = z.Write([]byte(`{"ok":true}` + "\n"))
			}
			_ = z.Close()
		}()
		label := "signer_connection"
		if call > 1 {
			label = ""
		}
		return &stopOrderConn{Conn: a, log: order, label: label}, nil
	}, "box-run", "")
	serverL := stopOrderListener{Listener: l, log: order}
	go ch.Serve(serverL)
	run := stopOrderRun{Run: e.run(0), log: order}
	b.mu.Lock()
	b.info.AgentChannel = true
	b.channel = ch
	b.channelL = serverL
	b.run = run
	b.mu.Unlock()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte(`{"method":"register_run","request_id":"id","agent":{"name":"agent"}}` + "\n"))
	if _, err = bufio.NewReader(c).ReadBytes('\n'); err != nil {
		t.Fatal(err)
	}
	b.teardown(context.Background(), "test stop", "", false, false)
	_ = c.Close()
	want := []string{"listener", "guest_connection", "signer_connection", "channel_run", "box_run"}
	if got := order.got(); !slices.Equal(got, want) {
		t.Fatalf("stop order %v, want %v", got, want)
	}
}

func TestLifecycle(t *testing.T) {
	e := newTestEnv(t, nil)
	ws := t.TempDir()
	e.guest.Patch = "diff --git a/x b/x\n"
	e.guest.Summary = proto.DiffSummary{Files: []proto.DiffFile{{Path: "x", Status: "modified"}}}
	b := e.create(api.CreateBoxRequest{Name: "demo", Allow: []string{"pypi", "anthropic"}, Workspace: ws,
		Env:     map[string]string{"FOO": "bar"},
		Secrets: map[string]api.SecretSpec{"GH": {Value: secretValue, Hosts: []string{"api.github.com"}, Header: "authorization"}},
		Limits:  api.Limits{CPUs: 3, MemoryMiB: 1024}, Task: "fix the flaky test", Agent: "claude-code"})

	if !strings.HasPrefix(b.ID, "tkb-") || len(b.ID) != 16 || b.Name != "demo" || b.RunID == "" || b.Unrecorded {
		t.Fatalf("box %+v", b)
	}
	if !slices.Equal(b.Allow, []string{"pypi", "api.anthropic.com", "api.github.com"}) {
		t.Fatalf("allow %v (secret hosts join the allowlist)", b.Allow)
	}
	if !slices.Equal(b.Secrets, []string{"GH"}) || b.Limits.CPUs != 3 || b.Limits.DiskMiB != DefaultDiskMiB ||
		time.Duration(b.Limits.Timeout) != time.Hour || b.ExpiresAt.IsZero() {
		t.Fatalf("box %+v", b)
	}
	if fi, err := os.Stat(e.d.boxDir(b.ID)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("box dir %v %v", fi, err)
	}
	m := e.machine(0)
	if m.Spec.GuestCID < 3 || m.Spec.VCPUs != 3 || m.Spec.MemoryMiB != 1024 || len(m.Spec.Drives) != 2 ||
		!m.Spec.Drives[0].ReadOnly || m.Spec.Drives[1].ReadOnly || m.Spec.StateDir != e.d.boxDir(b.ID) {
		t.Fatalf("spec %+v", m.Spec)
	}
	if !slices.Equal(e.builder.Workspaces, []string{ws}) || len(e.builder.Scratches) != 1 {
		t.Fatalf("builder %v %v", e.builder.Workspaces, e.builder.Scratches)
	}
	cfg := e.proxy(0).cfg
	if len(cfg.Secrets) != 1 || cfg.Secrets[0].Value != secretValue || cfg.Secrets[0].Header != "Authorization" ||
		!slices.Equal(cfg.ModelHosts, []string{"api.anthropic.com"}) || cfg.Decider == nil || cfg.Sink == nil {
		t.Fatalf("proxy config %+v", cfg)
	}

	// the guest fetches its boot config over the config port
	c, err := m.GuestDial(context.Background(), proto.PortConfig)
	if err != nil {
		t.Fatal(err)
	}
	proto.WriteJSON(c, proto.TypeJSON, proto.BootConfigRequest{Op: proto.OpBootConfig})
	f, err := proto.ReadFrame(c)
	c.Close()
	if err != nil || f.Type != proto.TypeJSON {
		t.Fatalf("boot config %v %v", f, err)
	}
	var bc proto.BootConfig
	if err := f.Decode(&bc); err != nil {
		t.Fatal(err)
	}
	envs := strings.Join(bc.Env, "\n")
	for _, want := range []string{"PATH=/usr/local/bin", "FOO=bar", "GH=tkbox_GH_", "HTTPS_PROXY=http://127.0.0.1:3128",
		"http_proxy=http://127.0.0.1:3128", "NO_PROXY=", "SSL_CERT_FILE=/etc/tkbox/ca-bundle.pem",
		"CURL_CA_BUNDLE=/etc/tkbox/ca-bundle.pem", "NODE_EXTRA_CA_CERTS=/etc/tkbox/ca-bundle.pem"} {
		if !strings.Contains(envs, want) {
			t.Errorf("boot env lacks %q:\n%s", want, envs)
		}
	}
	if strings.Contains(string(f.Payload), secretValue) {
		t.Fatal("boot config holds the secret value")
	}
	if bc.BoxID != b.ID || bc.CACertPEM == "" || bc.Workspace == nil || bc.Workspace.UpperDevice != "/dev/vdc" ||
		bc.Limits.ExecTimeoutMS != DefaultExecTimeout.Milliseconds() || bc.UnixNano == 0 {
		t.Fatalf("boot config %+v", bc)
	}

	// by name or id
	if got, err := e.d.Get("demo"); err != nil || got.ID != b.ID {
		t.Fatalf("get by name %v %v", got, err)
	}
	if _, err := e.d.Create(context.Background(), api.CreateBoxRequest{Name: "demo", Image: "x"}); errCode(err) != api.CodeConflict {
		t.Fatalf("duplicate name: %v", err)
	}

	stopped, err := e.d.Stop(context.Background(), "demo", api.StopRequest{})
	if err != nil || stopped.State != api.StateStopped || stopped.StopReason != "stopped by the operator" {
		t.Fatalf("stop %+v %v", stopped, err)
	}
	if got := readFile(t, filepath.Join(e.d.boxDir(b.ID), "diff.patch")); got != e.guest.Patch {
		t.Fatalf("saved diff %q", got)
	}
	if e.guest.Shutdowns != 1 || m.State != "stopped" || !e.proxy(0).closed {
		t.Fatalf("shutdowns %d machine %s proxy closed %v", e.guest.Shutdowns, m.State, e.proxy(0).closed)
	}
	run := e.run(0)
	if run.Closed || run.Agent.Name != "claude-code" {
		t.Fatalf("a stopped box closed its run (apply could not record): %+v", run)
	}

	var sources []string
	for _, r := range run.Records {
		if r.Method == "observe" {
			sources = append(sources, r.Source+":"+r.Trust)
		}
		if r.Method == "close" && r.Reason != "stopped by the operator" {
			t.Fatalf("close reason %q", r.Reason)
		}
	}
	if !slices.Equal(sources, []string{"tkbox.box:trusted", "tkbox.task:trusted", "tkbox.box:trusted", "tkbox.box:trusted"}) {
		t.Fatalf("observes %v", sources)
	}
	// diff after stop comes from the saved patch
	patch, sum, err := e.d.Diff(context.Background(), "demo")
	if err != nil || string(patch) != e.guest.Patch || len(sum.Files) != 1 {
		t.Fatalf("diff after stop %q %+v %v", patch, sum, err)
	}
	for _, name := range []string{"box.json", "events.ndjson"} {
		if strings.Contains(readFile(t, filepath.Join(e.d.boxDir(b.ID), name)), secretValue) {
			t.Fatalf("%s holds the secret value", name)
		}
	}
	if err := e.d.Remove(context.Background(), "demo"); err != nil || !run.Closed {
		t.Fatalf("rm: %v (run closed %v)", err, run.Closed)
	}
	if _, err := os.Stat(e.d.boxDir(b.ID)); !os.IsNotExist(err) {
		t.Fatalf("box dir still there: %v", err)
	}
	if _, err := e.d.Get("demo"); errCode(err) != api.CodeNotFound {
		t.Fatalf("get after rm: %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.MaxBoxes = 1 })
	cases := map[string]struct {
		req  api.CreateBoxRequest
		code string
		want string
	}{
		"bad name":       {api.CreateBoxRequest{Name: "Bad_Name", Image: "x"}, api.CodeBadRequest, "name"},
		"no image":       {api.CreateBoxRequest{}, api.CodeBadRequest, "image"},
		"cpus":           {api.CreateBoxRequest{Image: "x", Limits: api.Limits{CPUs: 64}}, api.CodeLimit, "cpus 64"},
		"memory":         {api.CreateBoxRequest{Image: "x", Limits: api.Limits{MemoryMiB: 64}}, api.CodeLimit, "memory"},
		"disk":           {api.CreateBoxRequest{Image: "x", Limits: api.Limits{DiskMiB: 1}}, api.CodeLimit, "disk"},
		"timeout":        {api.CreateBoxRequest{Image: "x", Limits: api.Limits{Timeout: api.Duration(time.Second)}}, api.CodeLimit, "timeout"},
		"exec timeout":   {api.CreateBoxRequest{Image: "x", Limits: api.Limits{ExecTimeout: api.Duration(48 * time.Hour)}}, api.CodeLimit, "exec timeout"},
		"secret name":    {api.CreateBoxRequest{Image: "x", Secrets: map[string]api.SecretSpec{"gh": {Value: "v", Hosts: []string{"h"}}}}, api.CodeBadRequest, "secret"},
		"secret hosts":   {api.CreateBoxRequest{Image: "x", Secrets: map[string]api.SecretSpec{"GH": {Value: secretValue}}}, api.CodeBadRequest, "no hosts"},
		"secret newline": {api.CreateBoxRequest{Image: "x", Secrets: map[string]api.SecretSpec{"GH": {Value: "a\nb", Hosts: []string{"h"}}}}, api.CodeBadRequest, "line break"},
		"reserved env":   {api.CreateBoxRequest{Image: "x", Env: map[string]string{"HTTPS_PROXY": "x"}}, api.CodeBadRequest, "HTTPS_PROXY"},
		"relative ws":    {api.CreateBoxRequest{Image: "x", Workspace: "rel/dir"}, api.CodeBadRequest, "absolute"},
		"missing ws":     {api.CreateBoxRequest{Image: "x", Workspace: "/nonexistent/tkbox"}, api.CodeBadRequest, "not a directory"},
		"bad allow":      {api.CreateBoxRequest{Image: "x", Allow: []string{"bad entry"}}, api.CodeBadRequest, "bad entry"},
		"inspect":        {api.CreateBoxRequest{Image: "x", Inspect: "most"}, api.CodeBadRequest, "inspect"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := e.d.Create(context.Background(), c.req)
			var ae *api.ErrorDetail
			if !errors.As(err, &ae) || ae.Code != c.code || !strings.Contains(ae.Message, c.want) {
				t.Fatalf("err = %v, want %s mentioning %q", err, c.code, c.want)
			}
			if ae.Code == api.CodeLimit && ae.Hint == "" {
				t.Fatal("a limit error without a hint")
			}
			if strings.Contains(err.Error(), secretValue) {
				t.Fatal("error holds the secret value")
			}
		})
	}
	e.create(api.CreateBoxRequest{})
	_, err := e.d.Create(context.Background(), api.CreateBoxRequest{Image: "x"})
	var ae *api.ErrorDetail
	if !errors.As(err, &ae) || ae.Code != api.CodeLimit || !strings.Contains(ae.Message, "limit is 1") || !strings.Contains(ae.Hint, "--max-boxes") {
		t.Fatalf("max boxes: %v", err)
	}
}

func TestCreateFailureTearsDown(t *testing.T) {
	e := newTestEnv(t, nil)
	e.builder.Err = errors.New("registry said no")
	_, err := e.d.Create(context.Background(), api.CreateBoxRequest{Name: "broken", Image: "x"})
	if err == nil || !strings.Contains(err.Error(), "registry said no") {
		t.Fatalf("err = %v", err)
	}
	b, _ := e.d.Get("broken")
	if b.State != api.StateFailed || !strings.Contains(b.Error, "registry said no") {
		t.Fatalf("box %+v", b)
	}
	run := e.run(0)
	if !run.Closed {
		t.Fatal("run not closed")
	}
	if last := run.Records[len(run.Records)-1]; last.Method != "close" || !strings.Contains(last.Reason, "registry said no") {
		t.Fatalf("close %+v", last)
	}

	// a guest that never says ready: the error says where the console is
	e2 := newTestEnv(t, func(o *Options) { o.ReadyTimeout = 300 * time.Millisecond })
	e2.guest.PingErr = errors.New("connection refused")
	_, err = e2.d.Create(context.Background(), api.CreateBoxRequest{Image: "x"})
	if err == nil || !strings.Contains(err.Error(), "did not come up") || !strings.Contains(err.Error(), "console.log") {
		t.Fatalf("err = %v", err)
	}
	if m := e2.machine(0); m.State != "stopped" {
		t.Fatalf("machine left %s", m.State)
	}
}

func TestSignerDownAtCreate(t *testing.T) {
	e := newTestEnv(t, nil)
	e.tk.StatusErr = &tracekit.Unavailable{Err: errors.New("dial: no such file")}
	_, err := e.d.Create(context.Background(), api.CreateBoxRequest{Image: "x"})
	if errCode(err) != api.CodeUnavailable {
		t.Fatalf("err = %v, want unavailable", err)
	}
	if len(e.launcher.Machines) != 0 {
		t.Fatal("a VM started without a signer")
	}
}

func TestExecOverHTTP(t *testing.T) {
	e := newTestEnv(t, nil)
	b := e.create(api.CreateBoxRequest{Name: "ex"})
	sock := e.serve()

	// allowed
	_, frames := execStream(t, sock, "ex", api.ExecRequest{Argv: []string{"echo", "hi there"}}, nil)
	evs := execEvents(frames)
	if len(evs) != 2 || evs[0].State != api.ExecDeciding || evs[1].State != api.ExecRunning || evs[1].Decision != "allow" {
		t.Fatalf("events %+v", evs)
	}
	if stdoutOf(frames) != "echo hi there\n" || frames[len(frames)-1].Type != proto.TypeExit {
		t.Fatalf("frames %v", frames)
	}
	g := e.guest.Execs[0]
	if g.TimeoutMS != DefaultExecTimeout.Milliseconds() || g.Stdin {
		t.Fatalf("guest exec %+v", g)
	}
	run := e.run(0)
	var decided tracekit.Call
	for _, r := range run.Records {
		if r.Method == "decide" {
			decided = r.Call
		}
	}
	if decided.Tool != tracekit.ToolBash || decided.Args["command"] != "echo 'hi there'" {
		t.Fatalf("decide %+v", decided)
	}

	// stdin both ways, exit code passes through
	e.guest.ExecFunc = func(ctx context.Context, req proto.ExecRequest, stdio agentrpc.ExecIO) (proto.ExitStatus, error) {
		data, _ := io.ReadAll(stdio.Stdin)
		stdio.Stdout.Write([]byte(strings.ToUpper(string(data))))
		stdio.Stderr.Write([]byte("warn\n"))
		return proto.ExitStatus{Code: 3, DurationMS: 5}, nil
	}
	_, frames = execStream(t, sock, b.ID, api.ExecRequest{Argv: []string{"tr"}, Stdin: true, Timeout: api.Duration(time.Minute)}, []byte("abc"))
	last := frames[len(frames)-1]
	var st proto.ExitStatus
	json.Unmarshal(last.Payload, &st)
	if stdoutOf(frames) != "ABC" || last.Type != proto.TypeExit || st.Code != 3 {
		t.Fatalf("frames %v status %+v", frames, st)
	}
	if g := e.guest.Execs[1]; !g.Stdin || g.TimeoutMS != 60000 {
		t.Fatalf("guest exec %+v", g)
	}
	var completes []tracekitfake.Record
	for _, r := range e.run(0).Methods() {
		_ = r
	}
	e.guest.ExecFunc = nil

	// denied: an ExecEvent with the rules, then a TypeError in the ErrorDetail shape
	e.tk.DecideFunc = func(call tracekit.Call) tracekit.Decision {
		return tracekit.Decision{Decision: "deny", RuleIDs: []string{"TK-D002"}, Reason: "destructive command"}
	}
	_, frames = execStream(t, sock, "ex", api.ExecRequest{Argv: []string{"rm", "-rf", "/"}}, nil)
	last = frames[len(frames)-1]
	var ed api.ErrorDetail
	json.Unmarshal(last.Payload, &ed)
	evs = execEvents(frames)
	if last.Type != proto.TypeError || ed.Code != api.CodeDenied || !slices.Equal(ed.RuleIDs, []string{"TK-D002"}) || ed.Hint != "" ||
		ed.Message != "denied by Tracekit policy [TK-D002]: destructive command" || stdoutOf(frames) != "" {
		t.Fatalf("denied frames %v %+v", frames, ed)
	}
	if evs[len(evs)-1].Decision != "deny" || !slices.Equal(evs[len(evs)-1].RuleIDs, []string{"TK-D002"}) {
		t.Fatalf("deny event %+v", evs)
	}
	if pe := last.AsError(); pe.Code != api.CodeDenied {
		t.Fatalf("proto.AsError %+v", pe)
	}
	if len(e.guest.Execs) != 2 {
		t.Fatal("a denied command reached the guest")
	}

	// ask → waiting_approval names the approver and the command to approve
	e.tk.DecideFunc = func(call tracekit.Call) tracekit.Decision {
		return tracekit.Decision{Decision: "ask", Reason: "needs a person"}
	}
	_, frames = execStream(t, sock, "ex", api.ExecRequest{Argv: []string{"git", "push"}}, nil)
	evs = execEvents(frames)
	if len(evs) != 3 || evs[1].State != api.ExecWaitingApproval || evs[1].Approver != "tracekit" || evs[1].ApprovalID != "appr1" ||
		evs[1].Message != "approve with: tracekit approvals approve appr1" || evs[2].State != api.ExecRunning {
		t.Fatalf("ask events %+v", evs)
	}
	e.tk.ApprovalState = tracekit.ApprovalRejected
	_, frames = execStream(t, sock, "ex", api.ExecRequest{Argv: []string{"git", "push"}}, nil)
	if f := frames[len(frames)-1]; f.Type != proto.TypeError || f.AsError().Code != api.CodeDenied {
		t.Fatalf("rejected approval frames %v", frames)
	}
	e.tk.DecideFunc, e.tk.ApprovalState = nil, ""

	// refusals before the upgrade are plain JSON errors
	resp, _ := execStream(t, sock, "nope", api.ExecRequest{Argv: []string{"ls"}}, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown box: %d", resp.StatusCode)
	}
	resp, _ = execStream(t, sock, "ex", api.ExecRequest{}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("no argv: %d", resp.StatusCode)
	}
	resp, _ = execStream(t, sock, "ex", api.ExecRequest{Argv: []string{"ls"}, Timeout: api.Duration(48 * time.Hour)}, nil)
	var body api.ErrorBody
	json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusUnprocessableEntity || body.Error.Code != api.CodeLimit || body.Error.Hint == "" {
		t.Fatalf("exec timeout limit: %d %+v", resp.StatusCode, body)
	}

	// completes carry the exit status
	e.d.Stop(context.Background(), "ex", api.StopRequest{})
	for _, r := range e.run(0).Records {
		if r.Method == "complete" {
			completes = append(completes, r)
		}
	}
	if len(completes) != 3 || completes[0].Status != "ok" || completes[1].Status != "error" {
		t.Fatalf("completes %+v", completes)
	}
	if res, ok := completes[1].Value.(map[string]any); !ok || res["exit_code"] != 3 {
		t.Fatalf("complete result %+v", completes[1].Value)
	}
	if got, _ := e.d.Get("ex"); got.Execs != 3 {
		t.Fatalf("execs %d", got.Execs)
	}
}

func TestNoticesReachRunningExecs(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "n"})
	sock := e.serve()
	started := make(chan struct{})
	release := make(chan struct{})
	e.guest.ExecFunc = func(ctx context.Context, req proto.ExecRequest, stdio agentrpc.ExecIO) (proto.ExitStatus, error) {
		close(started)
		<-release
		return proto.ExitStatus{}, nil
	}
	b := e.box("n")
	go func() {
		<-started
		(*boxSink)(b).Emit(egress.Event{Kind: egress.EventDenied, Host: "evil.example", Port: 443, Reason: "resolves to a private address"})
		time.Sleep(100 * time.Millisecond)
		close(release)
	}()
	_, frames := execStream(t, sock, "n", api.ExecRequest{Argv: []string{"curl", "https://evil.example"}}, nil)
	var notice string
	for _, ev := range execEvents(frames) {
		if ev.State == api.ExecNotice {
			notice = ev.Message
		}
	}
	if !strings.Contains(notice, "egress to evil.example:443 refused: resolves to a private address") {
		t.Fatalf("notice %q in %v", notice, execEvents(frames))
	}
	if frames[len(frames)-1].Type != proto.TypeExit {
		t.Fatal("exit is not the last frame")
	}
}

func TestPeerUIDCheck(t *testing.T) {
	e := newTestEnv(t, nil)
	sock := e.serve()
	c := httpClient(sock)
	resp, err := c.Get("http://tkbox/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	var h api.Health
	json.NewDecoder(resp.Body).Decode(&h)
	resp.Body.Close()
	if resp.StatusCode != 200 || h.API != api.Version || !h.SignerOK || h.Signer != "fake" || h.Unrecorded {
		t.Fatalf("health %d %+v", resp.StatusCode, h)
	}
	fi, err := os.Stat(sock)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v %v", fi.Mode(), err)
	}
	if di, _ := os.Stat(filepath.Dir(sock)); di.Mode().Perm() != 0o700 {
		t.Fatalf("socket dir mode %v", di.Mode())
	}
	var seen int
	e.d.allowUID = func(uid int) bool { seen = uid; return false }
	resp, err = c.Get("http://tkbox/v1/boxes")
	if err != nil {
		t.Fatal(err)
	}
	var body api.ErrorBody
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || body.Error.Code != api.CodeForbidden || seen != os.Getuid() {
		t.Fatalf("forbidden: %d %+v (peer uid %d)", resp.StatusCode, body, seen)
	}
	e.d.allowUID = nil
	if !e.d.uidAllowed(os.Getuid()) || !e.d.uidAllowed(0) || e.d.uidAllowed(os.Getuid()+12345) {
		t.Fatal("uid rule")
	}
}

func TestListenSocket(t *testing.T) {
	dir := shortTempDir(t)
	sock := filepath.Join(dir, "run", "tkbox.sock")
	l, err := ListenSocket(sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ListenSocket(sock); err == nil || !strings.Contains(err.Error(), "already listening") {
		t.Fatalf("second daemon: %v", err)
	}
	// a stale socket (nobody listening) is replaced
	l.(interface{ SetUnlinkOnClose(bool) }).SetUnlinkOnClose(false)
	l.Close()
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("stale socket gone too early: %v", err)
	}
	l2, err := ListenSocket(sock)
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	l2.Close()
	// never removes something that is not a socket
	plain := filepath.Join(dir, "run", "notasocket")
	os.WriteFile(plain, []byte("x"), 0o600)
	if _, err := ListenSocket(plain); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("plain file: %v", err)
	}
	if _, err := os.Stat(plain); err != nil {
		t.Fatal("removed a plain file")
	}
}

func TestUnrecorded(t *testing.T) {
	e := newTestEnv(t, func(o *Options) {
		o.Tracekit = nil
		o.Unrecorded = true
		o.Gate = func(context.Context, tracekit.Run, tracekit.Call, tracekit.GateHooks) (tracekit.Outcome, error) {
			panic("gate called while unrecorded")
		}
		o.ApprovalTimeout = 100 * time.Millisecond
	})
	if h := e.d.Health(context.Background()); !h.Unrecorded || h.Signer != "" || h.SignerOK {
		t.Fatalf("health %+v", h)
	}
	b := e.create(api.CreateBoxRequest{Name: "u", Allow: []string{"pypi.org"}})
	if !b.Unrecorded || b.RunID != "" {
		t.Fatalf("box %+v", b)
	}
	sock := e.serve()
	_, frames := execStream(t, sock, "u", api.ExecRequest{Argv: []string{"true"}}, nil)
	evs := execEvents(frames)
	if frames[len(frames)-1].Type != proto.TypeExit || !strings.Contains(evs[len(evs)-1].Message, "unrecorded") {
		t.Fatalf("frames %v", evs)
	}
	dec := e.proxy(0).cfg.Decider
	v, err := dec.Decide(context.Background(), egress.Request{Host: "pypi.org", Port: 443, URL: "https://pypi.org:443", OnAllowlist: true})
	if err != nil || !v.Allow {
		t.Fatalf("allowlisted: %+v %v", v, err)
	}
	v, _ = dec.Decide(context.Background(), egress.Request{Host: "x.example", Port: 443, URL: "https://x.example:443"})
	if v.Allow || !strings.Contains(v.Reason, "no one approved") {
		t.Fatalf("off the allowlist must still need a person: %+v", v)
	}
	e.d.Stop(context.Background(), "u", api.StopRequest{})
	if _, err := e.d.Export(context.Background(), "u", api.ExportRequest{Out: "/tmp/x.tkb"}); errCode(err) != api.CodeNotSupported {
		t.Fatalf("export unrecorded: %v", err)
	}
	if _, err := New(Options{StateDir: t.TempDir(), Launcher: e.launcher, Builder: e.builder, KernelPath: "k"}); err == nil {
		t.Fatal("New without a signer and without Unrecorded must fail")
	}
}

func TestPersistenceAcrossRestart(t *testing.T) {
	e := newTestEnv(t, nil)
	e.guest.Patch = "diff --git a/f b/f\n"
	gone := e.create(api.CreateBoxRequest{Name: "stopped-one"})
	e.d.Stop(context.Background(), "stopped-one", api.StopRequest{})
	live := e.create(api.CreateBoxRequest{Name: "live-one"})

	// a second daemon on the same state dir (the first one "crashed")
	d2 := e.newDaemon()
	got := map[string]api.Box{}
	for _, b := range d2.List() {
		got[b.Name] = b
	}
	if got["stopped-one"].State != api.StateStopped || got["stopped-one"].ID != gone.ID {
		t.Fatalf("stopped box %+v", got["stopped-one"])
	}
	if b := got["live-one"]; b.State != api.StateFailed || b.Error != "daemon restarted; the VM was killed with it" || b.ID != live.ID {
		t.Fatalf("live box after restart %+v", b)
	}
	if patch, _, err := d2.Diff(context.Background(), "stopped-one"); err != nil || string(patch) != e.guest.Patch {
		t.Fatalf("diff after restart %q %v", patch, err)
	}
	if h := d2.Health(context.Background()); h.Boxes != 2 {
		t.Fatalf("health boxes %d", h.Boxes)
	}
}

func TestTimeoutStops(t *testing.T) {
	e := newTestEnv(t, nil)
	e.guest.Patch = "diff --git a/t b/t\n"
	b := e.create(api.CreateBoxRequest{Name: "t", Limits: api.Limits{Timeout: api.Duration(10 * time.Minute)}})
	if d := b.ExpiresAt.Sub(b.StartedAt); d != 10*time.Minute {
		t.Fatalf("expires after %s", d)
	}
	e.box("t").onTimeout() // what the box timer calls
	got, _ := e.d.Get("t")
	if got.State != api.StateStopped || !strings.Contains(got.StopReason, "timeout") || !strings.Contains(got.StopReason, "--timeout") {
		t.Fatalf("box %+v", got)
	}
	if _, err := os.Stat(filepath.Join(e.d.boxDir(b.ID), "diff.patch")); err != nil {
		t.Fatal("no diff saved at timeout")
	}
}

func TestContainment(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "c"})
	b := e.box("c")
	poll := func() {
		ack := make(chan struct{})
		b.pollNow <- ack
		<-ack
	}
	run := e.tk.Runs[0]
	run.Contain = tracekit.Containment{Contained: true, State: "held", IncidentID: "inc-1"}
	poll()
	if got, _ := e.d.Get("c"); got.State != api.StatePaused || e.machine(0).State != "paused" {
		t.Fatalf("held: box %s machine %s", got.State, e.machine(0).State)
	}
	run.Contain = tracekit.Containment{}
	poll()
	if got, _ := e.d.Get("c"); got.State != api.StateRunning || e.machine(0).State != "running" {
		t.Fatalf("released: box %s machine %s", got.State, e.machine(0).State)
	}
	run.Contain = tracekit.Containment{Contained: true, State: "quarantined", IncidentID: "inc-2"}
	poll()
	got, _ := e.d.Get("c")
	if got.State != api.StateStopped || !strings.Contains(got.StopReason, "quarantined") || e.machine(0).Err() == nil {
		t.Fatalf("quarantined: %+v (machine err %v)", got, e.machine(0).Err())
	}
	if e.guest.Shutdowns != 0 {
		t.Fatal("a quarantined box was shut down cleanly instead of killed")
	}
	var contained int
	for _, r := range run.Records {
		if r.Source == tracekit.SourceContained {
			contained++
		}
	}
	if contained != 3 || !run.Closed {
		t.Fatalf("contained observes %d closed %v", contained, run.Closed)
	}
}

func TestEventsEndpoint(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "ev"})
	sock := e.serve()
	e.d.Stop(context.Background(), "ev", api.StopRequest{})
	resp, err := httpClient(sock).Get("http://tkbox/v1/boxes/ev/events?follow=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var kinds []string
	for _, ln := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var ev api.Event
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatalf("line %q: %v", ln, err)
		}
		kinds = append(kinds, ev.Kind)
	}
	if !slices.Equal(kinds, []string{api.EventBoxCreated, api.EventBoxStarted, api.EventBoxStopped}) {
		t.Fatalf("kinds %v", kinds)
	}
	fi, _ := os.Stat(filepath.Join(e.d.boxDir(e.box("ev").id), "events.ndjson"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("events.ndjson mode %v", fi.Mode())
	}
}

func TestExport(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "x"})
	out := filepath.Join(t.TempDir(), "demo.tkb")
	if _, err := e.d.Export(context.Background(), "x", api.ExportRequest{Out: out}); errCode(err) != api.CodeConflict ||
		!strings.Contains(err.Error(), "stop it first") {
		t.Fatalf("export while running: %v", err)
	}
	e.d.Stop(context.Background(), "x", api.StopRequest{})
	res, err := e.d.Export(context.Background(), "x", api.ExportRequest{Out: out})
	if err != nil {
		t.Fatal(err)
	}
	wantTrust := strings.TrimSuffix(out, ".tkb") + ".trust.json"
	if res.Bundle != out || res.Trust != wantTrust || res.RunID != "run0001" || !strings.HasPrefix(res.Verify, "tracekit verify ") {
		t.Fatalf("export %+v", res)
	}
	if _, err := os.Stat(wantTrust); err != nil {
		t.Fatal(err)
	}
	if _, err := e.d.Export(context.Background(), "x", api.ExportRequest{Out: "rel.tkb"}); errCode(err) != api.CodeBadRequest {
		t.Fatalf("relative out: %v", err)
	}
}
