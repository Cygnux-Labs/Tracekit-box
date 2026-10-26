package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
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
