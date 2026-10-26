package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// R1 (verify5, L1): a secret value never reaches the decided command line. It joins argv with spaces, so a value
// with a space split over bare words (`echo correct horse battery`) is in it; and it names each per-exec env
// variable, so a value used as an env name (`env AKIA…=1 ls`) is too.
func TestVerify5SecretValueInDecidedCommandRefused(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "r1", Secrets: map[string]api.SecretSpec{
		"PW": {Value: "correct horse battery", Hosts: []string{"api.example.com"}},
		"K":  {Value: "AKIAPROBEVALUE1234", Hosts: []string{"api.example.com"}},
	}})
	for _, c := range []struct {
		req    api.ExecRequest
		secret string
	}{
		{api.ExecRequest{Argv: []string{"echo", "correct", "horse", "battery"}}, "PW"},
		{api.ExecRequest{Argv: []string{"ls"}, Env: map[string]string{"AKIAPROBEVALUE1234": "1"}}, "K"},
	} {
		_, e2 := e.d.prepareExec("r1", c.req)
		if e2 == nil || e2.Code != api.CodeBadRequest || !strings.Contains(e2.Message, "holds the value of secret "+c.secret) {
			t.Errorf("%+v: %v", c.req, e2)
		}
	}
	// the words on their own, and a value-free env, still run
	if _, e2 := e.d.prepareExec("r1", api.ExecRequest{Argv: []string{"echo", "correct", "horse"}, Env: map[string]string{"AKIA": "1"}}); e2 != nil {
		t.Fatalf("an exec without a value: %v", e2)
	}
}

// R4 (verify5, docs): the checkout's own .gitattributes reaches the scratch apply only when the patch changes it (it
// is then copied in with the other files it touches; changing it needs --allow-sensitive), and then its conversions
// apply: eol=crlf writes "new\r\n". The signer decides the converted bytes, so the record names what lands. A patch
// that leaves .gitattributes alone gets no conversion.
func TestVerify5RepoAttributesOnlyWhenThePatchChangesThem(t *testing.T) {
	needGit(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	attrs := "diff --git a/.gitattributes b/.gitattributes\nindex 1111111..2222222 100644\n--- a/.gitattributes\n" +
		"+++ b/.gitattributes\n@@ -1 +1,2 @@\n a.txt text eol=crlf\n+b.txt text eol=crlf\n"
	for _, c := range []struct{ name, patch, want string }{
		{"attrs", attrs + modify("a.txt"), "new\r\n"},
		{"plain", modify("a.txt"), "new\n"},
	} {
		e := newTestEnv(t, nil)
		ws, _ := filepath.EvalSymlinks(t.TempDir())
		gitInit(t, ws)
		os.WriteFile(filepath.Join(ws, ".gitattributes"), []byte("a.txt text eol=crlf\n"), 0o644)
		os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
		e.guest.Patch = c.patch
		e.create(api.CreateBoxRequest{Name: c.name, Workspace: ws})
		e.d.Stop(context.Background(), c.name, api.StopRequest{})
		if res, err := e.d.Apply(context.Background(), c.name, api.ApplyRequest{AllowSensitive: true}); err != nil {
			t.Fatalf("%s: apply %+v %v", c.name, res, err)
		}
		if got := readFile(t, filepath.Join(ws, "a.txt")); got != c.want {
			t.Errorf("%s: a.txt written as %q, want %q", c.name, got, c.want)
		}
		sum := sha256.Sum256([]byte(c.want))
		decided := false
		for _, r := range e.run(0).Records {
			if r.Method == "decide" && r.Call.Tool == tracekit.ToolWrite && r.Call.Args["file_path"] == filepath.Join(ws, "a.txt") {
				decided = r.Call.Args["sha256"] == hex.EncodeToString(sum[:])
			}
		}
		if !decided {
			t.Errorf("%s: the signer did not decide a.txt as the bytes written", c.name)
		}
	}
}

// lateApprovalClient holds every approval record until released, then fails it.
type lateApprovalClient struct {
	tracekit.Client
	entered chan struct{}
	release chan struct{}
}

func (c *lateApprovalClient) NewRun(ctx context.Context, a tracekit.Agent) (tracekit.Run, error) {
	r, err := c.Client.NewRun(ctx, a)
	if err != nil {
		return nil, err
	}
	return &lateApprovalRun{Run: r, c: c}, nil
}

type lateApprovalRun struct {
	tracekit.Run
	c *lateApprovalClient
}

func (r *lateApprovalRun) Observe(ctx context.Context, source, trust string, value any) error {
	if source == tracekit.SourceApproval {
		r.c.entered <- struct{}{}
		<-r.c.release
		return &tracekit.RPCError{Code: "internal", Message: "observe refused"}
	}
	return r.Run.Observe(ctx, source, trust, value)
}

// R5 (verify5): an approval whose record fails only after the stopping box wrote its tkbox.gap record is still
// recorded as a loss (sent on its own, as a late complete is), not counted into gaps nobody reads again.
func TestVerify5ApprovalLostAfterGapsTakenIsRecorded(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.ApprovalTimeout = time.Minute })
	lc := &lateApprovalClient{Client: e.tk, entered: make(chan struct{}, 1), release: make(chan struct{})}
	e.d.opts.Tracekit = lc
	e.create(api.CreateBoxRequest{Name: "ap"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.proxy(0).cfg.Decider.Decide(ctx, egress.Request{Host: "x.example", Port: 443, URL: "https://x.example:443"})
	deadline := time.Now().Add(5 * time.Second)
	for len(e.d.Approvals()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	pend := e.d.Approvals()
	if len(pend) != 1 {
		t.Fatalf("approvals %+v", pend)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.d.DecideApproval(pend[0].ID, api.ApprovalDecision{Decision: "approve"}, 1000)
	}()
	<-lc.entered // the approval's record is in flight
	cancel()     // the proxy closing at stop cancels the waiting connection
	e.d.Stop(context.Background(), "ap", api.StopRequest{})
	close(lc.release) // the record fails only now, after the box wrote its gap record
	wg.Wait()
	for deadline = time.Now().Add(5 * time.Second); gapsOf(e, 0, tracekit.SourceApproval) == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if n := gapsOf(e, 0, tracekit.SourceApproval); n != 1 {
		t.Errorf("tkbox.gap for %s = %d after the approval record failed late, want 1: %v", tracekit.SourceApproval, n, e.run(0).Methods())
	}
}
