package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/config"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// M4: tkbox_exec has its stdin up front, so it sends it in the request (stdin_data) for the signer to decide with
// the command, and streams nothing.
func TestReview1MCPExecStdinIsDecided(t *testing.T) {
	sock, fd := startFakeDaemon(t)
	s := &mcpServer{c: newClient(sock), out: io.Discard, images: []string{"alpine:3"}, base: &config.File{}}
	ctx := context.Background()
	if out, isErr, err := s.call(ctx, "tkbox_run", json.RawMessage(`{"image":"alpine:3"}`)); err != nil || isErr {
		t.Fatalf("run: %v %v %q", err, isErr, out)
	}
	script := "import os\nos.system('id')\n"
	args, _ := json.Marshal(map[string]any{"box": "b1", "argv": []string{"python3"}, "stdin": script})
	out, isErr, err := s.call(ctx, "tkbox_exec", args)
	if err != nil || isErr || !strings.Contains(out, "exit code 0") {
		t.Fatalf("exec: %v %v %q", err, isErr, out)
	}
	fd.mu.Lock()
	req := fd.execs[len(fd.execs)-1]
	fd.mu.Unlock()
	if string(req.StdinData) != script || req.Stdin {
		t.Fatalf("exec request: stdin_data %q, streamed %v", req.StdinData, req.Stdin)
	}
}

// bigDiffDaemon answers like a daemon whose box changed thousands of files with long paths: the diff response leaves
// the summary out (DiffSummaryOmittedHeader) and /diff/summary has it.
func bigDiffDaemon(t *testing.T, files int) (string, api.DiffSummary) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tkbd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "tkbox.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	sum := api.DiffSummary{Bytes: 5}
	for i := range files {
		sum.Files = append(sum.Files, proto.DiffFile{Path: fmt.Sprintf("d/%s/f%05d.txt", strings.Repeat("x", 180), i), Status: "added"})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/boxes/{box}/diff", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(api.DiffSummaryOmittedHeader, "1")
		io.WriteString(w, "PATCH")
	})
	mux.HandleFunc("GET /v1/boxes/{box}/diff/summary", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(sum)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock, sum
}

// L7: a summary too large for a header (thousands of long paths) is read from /diff/summary by `tkbox diff --stat`,
// `tkbox diff` and MCP's tkbox_diff.
func TestReview1LargeDiffSummary(t *testing.T) {
	sock, sum := bigDiffDaemon(t, 3000)
	code, out, errs := run(t, "", "diff", "--stat", "--socket", sock, "big")
	if code != 0 || strings.Count(out, "\n") != 3000 || !strings.Contains(out, sum.Files[2999].Path) {
		t.Fatalf("diff --stat: exit %d, %d lines, %q", code, strings.Count(out, "\n"), errs)
	}
	code, out, errs = run(t, "", "diff", "--socket", sock, "big")
	if code != 0 || out != "PATCH" || !strings.Contains(errs, "3000 files changed") {
		t.Fatalf("diff: exit %d, %q, %q", code, out, errs)
	}
	s := &mcpServer{c: newClient(sock), out: io.Discard, base: &config.File{}, owned: map[string]string{"tkb-big": "big"}}
	txt, isErr, err := s.call(context.Background(), "tkbox_diff", json.RawMessage(`{"box":"big"}`))
	if err != nil || isErr || !strings.HasPrefix(txt, "3000 files changed") {
		t.Fatalf("tkbox_diff: %v %v %.80q", err, isErr, txt)
	}
}

// L6: --egress-block takes CIDRs and bare addresses (repeatable, comma-separated) and refuses anything else before the
// daemon starts.
func TestReview1EgressBlockFlag(t *testing.T) {
	got, err := parseEgressBlock([]string{"203.0.113.7", "198.51.100.0/24", "2001:db8::1", "10.1.2.3/8"})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8::1/128"), netip.MustParsePrefix("10.0.0.0/8")}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	code, _, errs := run(t, "", "daemon", "--state-dir", t.TempDir(), "--egress-block", "203.0.113.7,not-a-cidr")
	if code == 0 || !strings.Contains(errs, `--egress-block "not-a-cidr"`) {
		t.Fatalf("bad --egress-block: exit %d, %q", code, errs)
	}
}
