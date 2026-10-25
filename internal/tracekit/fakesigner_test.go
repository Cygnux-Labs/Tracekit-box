package tracekit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeSigner is an NDJSON signer on a Unix socket that answers hello and then each frame with handle (default:
// a minimal 1.4.2 signer). It records every frame it received.

type (
	dropConn struct{} // close the connection without answering
	hangConn struct{} // never answer (until the client closes)
	rawLine  []byte   // answer with these bytes and a newline
)

type received struct {
	conn   int
	method string
	req    map[string]any
}

type fakeSigner struct {
	t      *testing.T
	path   string
	ln     net.Listener
	hello  map[string]any
	handle func(conn int, req map[string]any) any

	mu       sync.Mutex
	got      []received
	conns    int
	closed   map[int]bool
	runs     int
	inflight map[string]int // event calls in flight per run
	overlap  bool           // two event calls of one run were in flight at once
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "tkf") // t.TempDir is too long for a macOS socket path
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func newFakeSigner(t *testing.T) *fakeSigner {
	return newFakeSignerAt(t, filepath.Join(shortTempDir(t), "s.sock"))
}

func newFakeSignerAt(t *testing.T, path string) *fakeSigner {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSigner{t: t, path: path, ln: ln, closed: map[int]bool{}, inflight: map[string]int{},
		hello: map[string]any{"proto": []any{15, 19}, "version": "1.4.2", "pid": 1}}
	f.handle = f.standard
	t.Cleanup(func() { ln.Close() })
	go f.serve()
	return f
}

func (f *fakeSigner) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.conns++
		id := f.conns
		f.mu.Unlock()
		go f.conn(id, c)
	}
}

func (f *fakeSigner) conn(id int, c net.Conn) {
	defer func() {
		c.Close()
		f.mu.Lock()
		f.closed[id] = true
		f.mu.Unlock()
	}()
	r := bufio.NewReaderSize(c, 4<<20)
	first := true
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var req map[string]any
		d := json.NewDecoder(strings.NewReader(string(line)))
		d.UseNumber()
		if err := d.Decode(&req); err != nil {
			f.t.Errorf("fake signer: bad frame %q: %v", line, err)
			return
		}
		method, _ := req["method"].(string)
		if first != (method == "hello") {
			f.t.Errorf("fake signer: hello must come first, and once (got %s)", method)
			return
		}
		var out any
		if first {
			first, out = false, f.hello
		} else {
			f.mu.Lock()
			f.got = append(f.got, received{id, method, req})
			run, _ := req["run_id"].(string)
			_, event := req["client_seq"]
			if event {
				if f.inflight[run] > 0 {
					f.overlap = true
				}
				f.inflight[run]++
			}
			f.mu.Unlock()
			out = f.handle(id, req)
			if event {
				f.mu.Lock()
				f.inflight[run]--
				f.mu.Unlock()
			}
		}
		switch o := out.(type) {
		case dropConn:
			return
		case hangConn:
			_, _ = r.ReadBytes('\n') // until the client goes away
			return
		case rawLine:
			if _, err := c.Write(append(o, '\n')); err != nil {
				return
			}
		default:
			b, err := json.Marshal(o)
			if err != nil {
				f.t.Errorf("fake signer: %v", err)
				return
			}
			if _, err := c.Write(append(b, '\n')); err != nil {
				return
			}
		}
	}
}

// standard answers as a 1.4.2 signer that allows everything.
func (f *fakeSigner) standard(conn int, req map[string]any) any {
	switch req["method"] {
	case "status":
		return map[string]any{"rpc_version": 19, "signer": map[string]any{"name": "fake", "version": "1.4.2"},
			"identity": map[string]any{"scheme": "uid", "subject": "501", "attested": true}}
	case "register_run":
		f.mu.Lock()
		f.runs++
		n := f.runs
		f.mu.Unlock()
		return map[string]any{"run_id": fmt.Sprintf("run-%d", n), "run_token": "secret-token", "tenant": "default",
			"tenant_attested": true, "principal_attested": false}
	case "decide":
		return map[string]any{"decision": "allow", "decision_id": "d-" + req["tool_call_id"].(string),
			"rule_ids": []any{}, "run_seq": 1}
	case "complete", "observe":
		return map[string]any{"run_seq": 2}
	case "approval_request":
		return map[string]any{"approval_id": "appr-1", "state": "requested"}
	case "approval_wait":
		return map[string]any{"approval_id": req["approval_id"], "state": "approved"}
	case "approval_consume":
		return map[string]any{"ok": true, "rule_ids": []any{}}
	case "approval_abandon":
		return map[string]any{"approval_id": req["approval_id"], "state": "expired"}
	case "close_run":
		return map[string]any{"run_id": req["run_id"], "state": "closing", "run_seq": 9}
	case "read":
		return map[string]any{"events": []any{}, "next_seq": nil}
	}
	return map[string]any{"error": map[string]any{"code": "invalid_request", "message": "unknown method"}}
}

func (f *fakeSigner) received(method string) []received {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []received
	for _, r := range f.got {
		if r.method == method {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeSigner) all() []received {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]received(nil), f.got...)
}

func (f *fakeSigner) connClosed(id int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed[id]
}
