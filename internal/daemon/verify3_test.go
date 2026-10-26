package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
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
