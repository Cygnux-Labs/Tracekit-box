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

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
