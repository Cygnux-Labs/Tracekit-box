package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/config"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

func hexSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// changingDiffDaemon answers like a daemon whose running box has a summary too large for a header: /diff has the
// patch, and /diff/summary (a second guest diff) is of another patch for its first `stale` answers.
type changingDiffDaemon struct {
	mu                  sync.Mutex
	stale               int
	diffCalls, sumCalls int
}

func (d *changingDiffDaemon) counts() [2]int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return [2]int{d.diffCalls, d.sumCalls}
}

func (d *changingDiffDaemon) start(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tkbv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "tkbox.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	const patch = "PATCH"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/boxes/{box}/diff", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.diffCalls++
		d.mu.Unlock()
		w.Header().Set(api.DiffSummaryOmittedHeader, "1")
		w.Header().Set(api.DiffSHA256Header, hexSHA([]byte(patch)))
		io.WriteString(w, patch)
	})
	mux.HandleFunc("GET /v1/boxes/{box}/diff/summary", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.sumCalls++
		of := patch
		if d.sumCalls <= d.stale {
			of = "ANOTHER PATCH"
		}
		d.mu.Unlock()
		json.NewEncoder(w).Encode(api.DiffSummary{Files: []proto.DiffFile{{Path: "a.txt", Status: "modified"}},
			Bytes: int64(len(of)), PatchSHA256: hexSHA([]byte(of))})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// L7 (verify3): a summary that is not of the patch read (its patch_sha256 differs) makes `tkbox diff` and MCP's
// tkbox_diff read both once more; a second mismatch is an error saying the workspace changed.
func TestVerify3DiffSummaryOfAnotherPatch(t *testing.T) {
	fd := &changingDiffDaemon{stale: 1}
	sock := fd.start(t)
	code, out, errs := run(t, "", "diff", "--socket", sock, "b1")
	if code != 0 || out != "PATCH" || !strings.Contains(errs, "1 file changed") || fd.counts() != [2]int{2, 2} {
		t.Fatalf("one stale summary: exit %d %q %q, %d diffs, %d summaries", code, out, errs, fd.counts()[0], fd.counts()[1])
	}

	fd = &changingDiffDaemon{stale: 100}
	sock = fd.start(t)
	code, out, errs = run(t, "", "diff", "--socket", sock, "b1")
	if code == 0 || out != "" || !strings.Contains(errs, api.DiffChangedMessage) || fd.counts()[0] != 2 {
		t.Fatalf("summaries of another patch: exit %d %q %q, %d diffs", code, out, errs, fd.counts()[0])
	}
	s := &mcpServer{c: newClient(sock), out: io.Discard, base: &config.File{}, owned: map[string]string{"b1": "b1"}}
	txt, isErr, err := s.call(context.Background(), "tkbox_diff", json.RawMessage(`{"box":"b1"}`))
	if !isErr || !strings.Contains(txt+errString(err), api.DiffChangedMessage) {
		t.Fatalf("tkbox_diff: %v %v %q", err, isErr, txt)
	}
}

// 9322e72 residual (verify3): a SIGTERM or SIGINT (the parent context cancelled) ends a `tkbox mcp` session and stops
// the boxes it created even while the client keeps stdin open; serve returns cleanly.
func TestVerify3MCPStopsItsBoxesOnSignal(t *testing.T) {
	sock, fd := startFakeDaemon(t)
	inR, inW := io.Pipe()
	defer inW.Close()
	s := &mcpServer{c: newClient(sock), out: io.Discard, images: []string{"alpine:3"}, base: &config.File{}}
	if txt, isErr, err := s.call(context.Background(), "tkbox_run", json.RawMessage(`{"image":"alpine:3"}`)); err != nil || isErr {
		t.Fatalf("run: %v %v %q", err, isErr, txt)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, inR) }()
	inW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"))
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after a signal: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after its context was cancelled (stdin still open)")
	}
	fd.mu.Lock()
	n := len(fd.stopped)
	fd.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d boxes stopped after the session was told to stop, want 1", n)
	}
}

// M4 coverage (verify3): an exec whose stdin is in the request (stdin_data) streams nothing, even when the caller
// also hands the client a stdin reader: the request says stdin false and the reader is never read.
func TestVerify3ExecStdinDataStreamsNothing(t *testing.T) {
	sock, fd := startFakeDaemon(t)
	read := false
	r := readFunc(func(p []byte) (int, error) { read = true; return 0, io.EOF })
	st, err := newClient(sock).exec(context.Background(), "b1", api.ExecRequest{Argv: []string{"echo"}, StdinData: []byte("x")},
		execIO{Stdin: r, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil || st.Code != 0 {
		t.Fatalf("exec: %+v %v", st, err)
	}
	fd.mu.Lock()
	req := fd.execs[len(fd.execs)-1]
	fd.mu.Unlock()
	if req.Stdin || string(req.StdinData) != "x" || read {
		t.Fatalf("exec request: stdin %v, stdin_data %q; the stdin reader was read: %v", req.Stdin, req.StdinData, read)
	}
}

type readFunc func([]byte) (int, error)

func (f readFunc) Read(p []byte) (int, error) { return f(p) }

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
