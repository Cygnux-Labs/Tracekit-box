package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc/agentrpcfake"
	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/image"
	"github.com/Cygnux-Labs/tracekit-box/internal/image/imagefake"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit/tracekitfake"
	"github.com/Cygnux-Labs/tracekit-box/internal/vmm"
	"github.com/Cygnux-Labs/tracekit-box/internal/vmm/vmmfake"
)

// fakeProxy records its config and accepts (and drops) connections until closed.
type fakeProxy struct {
	cfg    egress.Config
	mu     sync.Mutex
	closed bool
}

func (p *fakeProxy) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		c.Close()
	}
}

func (p *fakeProxy) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return nil
}

// fakeGate is tracekit.Gate's sequence over a fake run: decide → (ask: request, wait, consume).
func fakeGate(ctx context.Context, r tracekit.Run, call tracekit.Call, hooks tracekit.GateHooks) (tracekit.Outcome, error) {
	d, err := r.Decide(ctx, call)
	if err != nil {
		return tracekit.Outcome{}, err
	}
	switch d.Decision {
	case "allow":
		return tracekit.Outcome{Allowed: true, Decision: d}, nil
	case "ask":
		id, err := r.RequestApproval(ctx, call, d.Reason)
		if err != nil {
			return tracekit.Outcome{}, err
		}
		if hooks.OnAsk != nil {
			hooks.OnAsk(id)
		}
		st, err := r.WaitApproval(ctx, id, time.Minute)
		if err != nil {
			return tracekit.Outcome{}, err
		}
		if st != tracekit.ApprovalApproved {
			return tracekit.Outcome{Decision: d, ApprovalID: id, Reason: "approval " + st, RuleIDs: d.RuleIDs}, nil
		}
		c, err := r.Consume(ctx, call, id)
		if err != nil {
			return tracekit.Outcome{}, err
		}
		return tracekit.Outcome{Allowed: c.OK, Decision: d, ApprovalID: id}, nil
	default:
		return tracekit.Outcome{Decision: d, Reason: d.Reason, RuleIDs: d.RuleIDs}, nil
	}
}

type testEnv struct {
	t        *testing.T
	d        *Daemon
	opts     Options
	tk       *tracekitfake.Client
	launcher *vmmfake.Launcher
	guest    *agentrpcfake.Guest
	builder  *imagefake.Builder
	mu       sync.Mutex
	proxies  []*fakeProxy
}

// shortTempDir is a temp dir short enough for a unix socket path.
func shortTempDir(t *testing.T) string {
	dir, err := os.MkdirTemp("/tmp", "tkbt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func newTestEnv(t *testing.T, mod func(*Options)) *testEnv {
	t.Helper()
	e := &testEnv{t: t, tk: &tracekitfake.Client{}, launcher: &vmmfake.Launcher{}, guest: &agentrpcfake.Guest{}}
	state := filepath.Join(shortTempDir(t), "state")
	e.builder = &imagefake.Builder{Dir: shortTempDir(t), Config: image0Config()}
	opts := Options{
		StateDir: state, Launcher: e.launcher, Builder: e.builder, Tracekit: e.tk,
		GuestClient: func(vmm.Machine) agentrpc.Guest { return e.guest },
		NewProxy: func(cfg egress.Config) (Proxy, error) {
			p := &fakeProxy{cfg: cfg}
			e.mu.Lock()
			e.proxies = append(e.proxies, p)
			e.mu.Unlock()
			return p, nil
		},
		Gate: fakeGate, KernelPath: "/fake/vmlinux", Arch: "arm64", Version: "test",
		ContainmentPoll: time.Hour, Logger: log.New(io.Discard, "", 0),
	}
	if mod != nil {
		mod(&opts)
	}
	e.opts = opts
	e.d = e.newDaemon()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		e.d.Shutdown(ctx)
	})
	return e
}

func (e *testEnv) newDaemon() *Daemon {
	d, err := New(e.opts)
	if err != nil {
		e.t.Fatal(err)
	}
	d.eg = fakeEgress()
	return d
}

func image0Config() (c image.Config) {
	c.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	return c
}

// fakeEgress replaces the egress package functions (stubs until agent D lands, and real ones need no network
// here either).
func fakeEgress() egressHooks {
	return egressHooks{
		expand: func(entries []string) ([]string, []string, error) {
			var allow, model []string
			for _, e := range entries {
				switch e {
				case "anthropic":
					allow = append(allow, "api.anthropic.com")
					model = append(model, "api.anthropic.com")
				case "bad entry":
					return nil, nil, errors.New(`"bad entry" is neither a preset nor a host`)
				default:
					allow = append(allow, e)
				}
			}
			return allow, model, nil
		},
		placeholder: func(name string) (string, error) { return "tkbox_" + name + "_" + randHex(16), nil },
		newCA:       func(string) (*egress.CA, string, error) { return nil, "-----BEGIN CERTIFICATE-----\nfake\n", nil },
	}
}

func (e *testEnv) proxy(i int) *fakeProxy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.proxies[i]
}

func (e *testEnv) create(req api.CreateBoxRequest) api.Box {
	e.t.Helper()
	if req.Image == "" {
		req.Image = "python:3.12-slim"
	}
	b, err := e.d.Create(context.Background(), req)
	if err != nil {
		e.t.Fatalf("create: %v", err)
	}
	if b.State != api.StateRunning {
		e.t.Fatalf("state %s", b.State)
	}
	return b
}

func (e *testEnv) box(ref string) *box {
	e.t.Helper()
	b, err := e.d.lookup(ref)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func (e *testEnv) run(i int) *tracekitfake.Run {
	e.tk.Runs[i].Methods() // sync with the run's mutex
	return e.tk.Runs[i]
}

func (e *testEnv) machine(i int) *vmmfake.Machine {
	return e.launcher.Machines[i]
}

func errCode(err error) string {
	var ae *api.ErrorDetail
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// serve starts the API on a temp socket and returns its path.
func (e *testEnv) serve() string {
	e.t.Helper()
	sock := filepath.Join(shortTempDir(e.t), "tkbox.sock")
	l, err := ListenSocket(sock)
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.d.ServeListener(ctx, l); close(done) }()
	e.t.Cleanup(func() { cancel(); <-done })
	return sock
}

func httpClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
}

// execStream runs one exec over a real HTTP upgrade and returns every frame the daemon sent.
func execStream(t *testing.T, sock, box string, req api.ExecRequest, stdin []byte) (*http.Response, []proto.Frame) {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
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
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return resp, nil
	}
	if stdin != nil {
		proto.WriteFrame(c, proto.TypeStdin, stdin)
		proto.WriteFrame(c, proto.TypeStdinEOF, nil)
	}
	var frames []proto.Frame
	c.SetDeadline(time.Now().Add(10 * time.Second))
	for {
		f, err := proto.ReadFrame(br)
		if err != nil {
			t.Fatalf("read frame: %v (after %d frames)", err, len(frames))
		}
		frames = append(frames, f)
		if f.Type == proto.TypeExit || f.Type == proto.TypeError {
			return resp, frames
		}
	}
}

func execEvents(frames []proto.Frame) []api.ExecEvent {
	var out []api.ExecEvent
	for _, f := range frames {
		if f.Type == proto.TypeJSON {
			var e api.ExecEvent
			json.Unmarshal(f.Payload, &e)
			out = append(out, e)
		}
	}
	return out
}

func stdoutOf(frames []proto.Frame) string {
	var b strings.Builder
	for _, f := range frames {
		if f.Type == proto.TypeStdout {
			b.Write(f.Payload)
		}
	}
	return b.String()
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
