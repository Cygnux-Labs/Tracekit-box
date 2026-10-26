package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/config"
)

// mcpSession runs an MCP server against a fake daemon and returns a call helper, the fake, and a func that ends the
// session (closes stdin) and waits for the server to exit.
func mcpSession(t *testing.T) (func(name string, args map[string]any) (string, bool), *fakeDaemon, func()) {
	t.Helper()
	sock, fd := startFakeDaemon(t)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &mcpServer{c: newClient(sock), out: outW, images: []string{"alpine:3"}, base: &config.File{Allow: []string{"pypi"}}}
	done := make(chan error, 1)
	go func() { done <- s.serve(context.Background(), inR); outW.Close() }()
	lines := bufio.NewScanner(outR)
	lines.Buffer(make([]byte, 1<<20), 1<<20)
	id := 0
	call := func(name string, args map[string]any) (string, bool) {
		t.Helper()
		id++
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call",
			"params": map[string]any{"name": name, "arguments": args}})
		inW.Write(append(b, '\n'))
		if !lines.Scan() {
			t.Fatalf("no answer to %s", name)
		}
		var resp struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
				IsError bool                    `json:"isError"`
			} `json:"result"`
		}
		if err := json.Unmarshal(lines.Bytes(), &resp); err != nil || len(resp.Result.Content) == 0 {
			t.Fatalf("answer %s: %v", lines.Text(), err)
		}
		return resp.Result.Content[0].Text, resp.Result.IsError
	}
	end := func() {
		inW.Close()
		go io.Copy(io.Discard, outR)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	return call, fd, end
}

// review-1 H1 follow-up: a ref by name reaches the daemon as the owned box's id, never as the name (a name could
// later belong to someone else's box), and a case-variant "BOX" key can't pick the box.
func TestMCPOwnedRefIsTheID(t *testing.T) {
	call, fd, end := mcpSession(t)
	defer end()
	if out, isErr := call("tkbox_run", map[string]any{"image": "alpine:3"}); isErr {
		t.Fatalf("run: %s", out)
	}
	call("tkbox_exec", map[string]any{"box": "b1", "argv": []string{"echo", "hi"}})
	fd.mu.Lock()
	refs := append([]string(nil), fd.refs...)
	fd.mu.Unlock()
	if len(refs) != 1 || refs[0] != "tkb-000000000001" {
		t.Fatalf("the daemon got box refs %q, want the owned id only", refs)
	}
	out, isErr := call("tkbox_exec", map[string]any{"box": "b1", "BOX": "prod", "argv": []string{"echo", "hi"}})
	if !isErr || !strings.Contains(out, `argument "BOX"`) {
		t.Fatalf("case-variant box key: %v %q", isErr, out)
	}
}

// review-1 M3 follow-up: the agent's chosen name would land in the run's trusted record of the box.
func TestMCPRunTakesNoName(t *testing.T) {
	call, fd, end := mcpSession(t)
	defer end()
	out, isErr := call("tkbox_run", map[string]any{"image": "alpine:3", "name": "operator-approved-prod-push"})
	if !isErr || !strings.Contains(out, "takes no name") || len(fd.created) != 0 {
		t.Fatalf("run with a name: %v %q (created %d)", isErr, out, len(fd.created))
	}
}

// review-1 H1 follow-up: when the session ends nothing can reach its boxes any more, so they are stopped (their
// patches saved, their runs left for the operator's apply and export) instead of holding a --max-boxes slot.
func TestMCPStopsItsBoxesWhenTheSessionEnds(t *testing.T) {
	call, fd, end := mcpSession(t)
	if out, isErr := call("tkbox_run", map[string]any{"image": "alpine:3"}); isErr {
		t.Fatalf("run: %s", out)
	}
	end()
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if len(fd.stopped) != 1 || fd.refs[len(fd.refs)-1] != "tkb-000000000001" || !strings.Contains(fd.stopped[0].Reason, "session") {
		t.Fatalf("boxes stopped at session end: %+v (refs %q)", fd.stopped, fd.refs)
	}
}
