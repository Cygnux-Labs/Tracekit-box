package main

import (
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/config"
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
