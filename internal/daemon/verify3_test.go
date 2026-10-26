package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// waitCompletes waits until run 0 holds n complete records (synchronising with the run's mutex, so the records may
// be read afterwards while nothing else writes them).
func waitCompletes(t *testing.T, e *testEnv, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := 0
		for _, m := range e.run(0).Methods() {
			if m == "complete" {
				got++
			}
		}
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d completes, want %d: %v", got, n, e.run(0).Methods())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// M4 (verify3): streamed stdin the process read before its exec failed, was stopped or lost its client still has its
// digest in the complete, not only after a clean exit.
func TestVerify3StreamedStdinDigestOnError(t *testing.T) {
	e := newTestEnv(t, nil)
	consumed := make(chan struct{}, 1)
	e.guest.ExecFunc = func(ctx context.Context, req proto.ExecRequest, xio agentrpc.ExecIO) (proto.ExitStatus, error) {
		io.Copy(xio.Stdout, xio.Stdin)
		consumed <- struct{}{}
		if req.Argv[0] == "fail" {
			return proto.ExitStatus{}, &proto.Error{Code: proto.CodeInternal, Message: "the guest failed"}
		}
		<-ctx.Done()
		return proto.ExitStatus{}, ctx.Err()
	}
	e.create(api.CreateBoxRequest{Name: "m4"})
	sock := e.serve()

	// a guest error after the script was read
	script := []byte("import os\nos.system('echo harmless')\n")
	_, frames := execStream(t, sock, "m4", api.ExecRequest{Argv: []string{"fail"}, Stdin: true}, script)
	<-consumed
	if frames[len(frames)-1].Type != proto.TypeError {
		t.Fatalf("last frame %s", frames[len(frames)-1].Payload)
	}
	waitCompletes(t, e, 1)
	if _, res := lastBash(e); res["stdin_sha256"] != sha(script) || res["stdin_bytes"] != int64(len(script)) || res["error"] != "the guest failed" {
		t.Fatalf("complete of a failed exec that read streamed stdin: %v", res)
	}

	// the client hangs up while the process (which read its script) still runs
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(api.ExecRequest{Argv: []string{"python3"}, Stdin: true})
	hreq, _ := http.NewRequest("POST", "http://tkbox/v1/boxes/m4/exec", bytes.NewReader(body))
	hreq.Header.Set("Connection", "Upgrade")
	hreq.Header.Set("Upgrade", api.ExecUpgrade)
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Write(c)
	resp, err := http.ReadResponse(bufio.NewReader(c), hreq)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("%v %v", err, resp)
	}
	script2 := []byte("print('second')\n")
	proto.WriteFrame(c, proto.TypeStdin, script2)
	proto.WriteFrame(c, proto.TypeStdinEOF, nil)
	select {
	case <-consumed:
	case <-time.After(5 * time.Second):
		t.Fatal("the guest never read its stdin")
	}
	c.Close()
	waitCompletes(t, e, 2)
	_, res := lastBash(e)
	if res["stdin_sha256"] != sha(script2) || res["stdin_bytes"] != int64(len(script2)) {
		t.Fatalf("complete after the client hung up: %v", res)
	}
}

// L1 (verify3): a secret's real value in the command, its cwd or its stdin_data is refused before anything is decided
// or reaches the guest; the refusal names the secret, never the value. A value split across two arguments is not one.
func TestVerify3SecretValueInCommandCwdOrStdinRefused(t *testing.T) {
	const val = "s3cret-value-1234"
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "l1", Secrets: map[string]api.SecretSpec{"TOK": {Value: val, Hosts: []string{"api.example.com"}}}})
	var ph string
	for _, s := range e.box("l1").secrets {
		ph = s.Placeholder
	}
	sock := e.serve()
	records, execs := len(e.run(0).Methods()), len(e.guest.Execs)
	for _, req := range []api.ExecRequest{
		{Argv: []string{"curl", "-H", "Authorization: Bearer " + val, "https://api.example.com/"}},
		{Argv: []string{"ls"}, Cwd: "/workspace/" + val},
		{Argv: []string{"cat"}, StdinData: []byte("token=" + val + "\n")},
	} {
		resp, _ := execStream(t, sock, "l1", req, nil)
		var body api.ErrorBody
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		js, _ := json.Marshal(body)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body.Error.Message, "holds the value of secret TOK") ||
			strings.Contains(string(js), val) {
			t.Errorf("exec %+v: %d %s", req, resp.StatusCode, js)
		}
	}
	if n := len(e.run(0).Methods()); n != records || len(e.guest.Execs) != execs {
		t.Fatalf("a refused exec was decided (%d records, was %d) or run (%d guest execs, was %d)", n, records, len(e.guest.Execs), execs)
	}
	for _, req := range []api.ExecRequest{
		{Argv: []string{"curl", "-H", "Authorization: Bearer " + ph}, Cwd: "/workspace", StdinData: []byte(ph)},
		{Argv: []string{"echo", val[:6], val[6:]}},
	} {
		if _, e2 := e.d.prepareExec("l1", req); e2 != nil {
			t.Errorf("exec %+v refused: %v", req, e2)
		}
	}
}

// L10 (verify3): a per-exec env may not set names that change what runs (by prefix: LD_, DYLD_, GIT_, XDG_, PYTHON,
// PERL, RUBY, NODE_, JAVA_, JDK_, _JAVA_, LUA_, BASH_, npm config; and exact names such as SHELLOPTS, PS4, HOME,
// CLASSPATH, MAKEFILES, GOFLAGS, RUSTC_WRAPPER), while plain settings (DEBIAN_FRONTEND, PIP_ROOT_USER_ACTION, …) pass.
func TestVerify3ExecEnvDenyList(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "env"})
	for _, k := range []string{"LD_BIND_NOW", "LD_DEBUG", "GLIBC_TUNABLES", "DYLD_INSERT_LIBRARIES", "PYTHONHOME",
		"PYTHONUSERBASE", "PYTHONWARNINGS", "PYTHONPLATLIBDIR", "PYTHONSTARTUP", "PYTHONINSPECT", "PERL5LIB", "PERLLIB",
		"PERL5DB", "RUBYLIB", "GEM_PATH", "GEM_HOME", "BUNDLE_GEMFILE", "NODE_PATH", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
		"CLASSPATH", "SHELLOPTS", "BASHOPTS", "PS4", "IFS", "CDPATH", "GLOBIGNORE", "ZDOTDIR", "HOME", "XDG_CONFIG_HOME",
		"XDG_DATA_HOME", "GIT_SSH_COMMAND", "GIT_SSH", "GIT_EXEC_PATH", "GIT_DIR", "GIT_WORK_TREE", "GIT_TEMPLATE_DIR",
		"GIT_EXTERNAL_DIFF", "GIT_ASKPASS", "GIT_EDITOR", "GIT_PAGER", "GIT_PROXY_COMMAND", "SSH_ASKPASS", "EDITOR",
		"VISUAL", "PAGER", "LESSOPEN", "MAKEFILES", "MAKEFLAGS", "GOFLAGS", "GOTOOLCHAIN", "RUSTC_WRAPPER", "CC",
		"LUA_INIT", "LUA_INIT_5_4", "PHPRC", "PHP_INI_SCAN_DIR", "npm_config_script_shell", "NPM_CONFIG_USERCONFIG",
		"PIP_CONFIG_FILE", "BASH_ENV", "BASH_FUNC_x", "LD_PRELOAD", "PYTHONPATH", "NODE_OPTIONS", "JAVA_TOOL_OPTIONS",
		"GIT_CONFIG_COUNT", "PATH"} {
		_, e2 := e.d.prepareExec("env", api.ExecRequest{Argv: []string{"ls"}, Env: map[string]string{k: "/x"}})
		if e2 == nil || e2.Code != api.CodeBadRequest || !strings.Contains(e2.Message, "env "+k+" can't be set per command") {
			t.Errorf("per-exec env %s: %v", k, e2)
		}
	}
	for _, k := range []string{"DEBIAN_FRONTEND", "PIP_ROOT_USER_ACTION", "PIP_DISABLE_PIP_VERSION_CHECK", "LANG",
		"GIT_AUTHOR_NAME", "GIT_COMMITTER_EMAIL", "NODE_ENV", "PYTHONUNBUFFERED", "MY_PATH", "CI", "TERM"} {
		if _, e2 := e.d.prepareExec("env", api.ExecRequest{Argv: []string{"ls"}, Env: map[string]string{k: "x"}}); e2 != nil {
			t.Errorf("per-exec env %s refused: %v", k, e2)
		}
	}
}

// L10 (verify3): an exec's own env is in its decided command line as a leading `env K=V …` (sorted, placeholders
// redacted) as well as in the env argument; the guest runs the argv as given with that env, and the complete carries
// exactly the decided args (so their digests match). A program name with = can't take a per-command env.
func TestVerify3ExecEnvInTheDecidedCommand(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "a", Secrets: map[string]api.SecretSpec{"TOK": {Value: "s3cret-value", Hosts: []string{"api.example.com"}}}})
	var ph string
	for _, s := range e.box("a").secrets {
		ph = s.Placeholder
	}
	sock := e.serve()
	_, frames := execStream(t, sock, "a", api.ExecRequest{Argv: []string{"sh", "-c", "apt-get install -y curl"},
		Env: map[string]string{"DEBIAN_FRONTEND": "noninteractive", "T": ph, "Z": "a b"}}, nil)
	if frames[len(frames)-1].Type != proto.TypeExit {
		t.Fatalf("exec: %s", frames[len(frames)-1].Payload)
	}
	var decided, completed map[string]any
	for _, r := range e.run(0).Records {
		if r.Call.Tool != tracekit.ToolBash {
			continue
		}
		switch r.Method {
		case "decide":
			decided = r.Call.Args
		case "complete":
			completed = r.Call.Args
		}
	}
	want := "env DEBIAN_FRONTEND=noninteractive 'T=tkbox_TOK_…' 'Z=a b' sh -c 'apt-get install -y curl'"
	if decided["command"] != want {
		t.Fatalf("decided command %q, want %q", decided["command"], want)
	}
	if env, _ := decided["env"].(map[string]any); env["DEBIAN_FRONTEND"] != "noninteractive" || env["T"] != "tkbox_TOK_…" {
		t.Fatalf("decided env %v", decided["env"])
	}
	d1, err1 := tracekit.ArgsDigest(tracekit.ToolBash, decided)
	d2, err2 := tracekit.ArgsDigest(tracekit.ToolBash, completed)
	if err1 != nil || err2 != nil || d1 != d2 {
		t.Fatalf("complete args digest %s (%v), decided %s (%v)", d2, err2, d1, err1)
	}
	g := e.guest.Execs[len(e.guest.Execs)-1]
	if strings.Join(g.Argv, "|") != "sh|-c|apt-get install -y curl" || strings.Join(g.Env, "|") != "DEBIAN_FRONTEND=noninteractive|T="+ph+"|Z=a b" {
		t.Fatalf("guest exec %+v", g)
	}

	// no env: the command line is the argv alone
	execStream(t, sock, "a", api.ExecRequest{Argv: []string{"ls", "-la"}}, nil)
	if args, _ := lastBash(e); args["command"] != "ls -la" {
		t.Fatalf("command without env: %q", args["command"])
	}
	if _, e2 := e.d.prepareExec("a", api.ExecRequest{Argv: []string{"X=1", "echo"}, Env: map[string]string{"A": "b"}}); e2 == nil ||
		e2.Code != api.CodeBadRequest {
		t.Fatalf("a program name with = and a per-command env: %v", e2)
	}
}

// L1 coverage (verify3): the box's created record is scrubbed: a box named after a secret's value, with a workspace
// dir named after it, is recorded with [secret NAME] in both places, never the value.
func TestVerify3CreatedRecordScrubbed(t *testing.T) {
	const val = "s3cret-value-1234"
	e := newTestEnv(t, nil)
	ws := filepath.Join(t.TempDir(), val)
	if err := os.Mkdir(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	e.create(api.CreateBoxRequest{Name: val, Workspace: ws, Secrets: map[string]api.SecretSpec{"TOK": {Value: val, Hosts: []string{"api.example.com"}}}})
	var created map[string]any
	for _, r := range e.run(0).Records {
		if m, _ := r.Value.(map[string]any); r.Method == "observe" && r.Source == tracekit.SourceBox && m["event"] == "created" {
			created = m
		}
	}
	js, _ := json.Marshal(created)
	if created == nil || strings.Contains(string(js), val) || created["name"] != "[secret TOK]" ||
		created["workspace"] != filepath.Join(filepath.Dir(ws), "[secret TOK]") {
		t.Fatalf("created record: %s", js)
	}
}

// flipGuest answers each diff with the next patch in turn: a running box whose workspace changes between two asks.
type flipGuest struct {
	agentrpc.Guest
	mu      sync.Mutex
	patches []string
	n       int
}

func (g *flipGuest) DiffWith(ctx context.Context, req proto.DiffRequest, w io.Writer) (proto.DiffSummary, error) {
	g.mu.Lock()
	p := g.patches[g.n%len(g.patches)]
	g.n++
	g.mu.Unlock()
	_, err := io.WriteString(w, p)
	return proto.DiffSummary{}, err
}

// L7 (verify3): every summary names the sha256 of the patch it was built from, and the diff response names its body's
// sha256 in a header, so a client can tell a running box's separately read summary is of another patch.
func TestVerify3DiffSummaryNamesItsPatch(t *testing.T) {
	e := newTestEnv(t, nil)
	first, second := modify(".github/workflows/release.yml"), modify("docs/readme.md")
	e.create(api.CreateBoxRequest{Name: "run"})
	b := e.box("run")
	b.mu.Lock()
	b.guest = &flipGuest{Guest: e.guest, patches: []string{first, second}}
	b.mu.Unlock()
	hc := httpClient(e.serve())
	resp, err := hc.Get("http://tkbox/v1/boxes/run/diff")
	if err != nil {
		t.Fatal(err)
	}
	patch, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var hdr api.DiffSummary
	json.Unmarshal([]byte(resp.Header.Get(api.DiffSummaryHeader)), &hdr)
	if string(patch) != first || resp.Header.Get(api.DiffSHA256Header) != sha(patch) || hdr.PatchSHA256 != sha(patch) {
		t.Fatalf("diff: sha header %q, summary %+v, sha of body %s", resp.Header.Get(api.DiffSHA256Header), hdr, sha(patch))
	}
	resp, err = hc.Get("http://tkbox/v1/boxes/run/diff/summary")
	if err != nil {
		t.Fatal(err)
	}
	var sum api.DiffSummary
	json.NewDecoder(resp.Body).Decode(&sum)
	resp.Body.Close()
	if sum.PatchSHA256 != sha([]byte(second)) || len(sum.Files) != 1 || sum.Files[0].Path != "docs/readme.md" {
		t.Fatalf("a running box's /diff/summary (a second guest diff): %+v, want patch_sha256 %s", sum, sha([]byte(second)))
	}
	// the patch saved at stop: the same patch, the same sha256
	e.guest.Patch = second
	e.create(api.CreateBoxRequest{Name: "saved"})
	e.d.Stop(context.Background(), "saved", api.StopRequest{})
	p2, s2, err := e.d.Diff(context.Background(), "saved")
	if err != nil || s2.PatchSHA256 != sha(p2) || len(p2) == 0 {
		t.Fatalf("saved diff: %v %+v", err, s2)
	}
}
