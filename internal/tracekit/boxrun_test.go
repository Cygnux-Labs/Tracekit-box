package tracekit

import (
	"context"
	"testing"
	"time"
)

// NewBoxRun registers the box run before it reads the fail modes: a run it refuses for an open one is closed, not
// left open in the signer with its token gone.
func TestNewBoxRunClosesARefusedRun(t *testing.T) {
	f := newFakeSigner(t)
	standard := f.handle
	f.handle = func(conn int, req map[string]any) any {
		out := standard(conn, req)
		if req["method"] == "register_run" {
			m := out.(map[string]any)
			m["fail_modes"] = map[string]any{"shell": "closed", "http": "open"}
		}
		return out
	}
	c := dialFake(t, f, 5*time.Second)
	if _, err := c.NewBoxRun(context.Background(), Agent{Name: "tkbox"}, BoxLabel{ID: "tkb-1", ImageDigest: "sha256:x", Channel: "agent"}); err == nil {
		t.Fatal("an open fail mode was accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var methods []string
	for _, g := range f.got {
		methods = append(methods, g.method)
	}
	for _, m := range methods {
		if m == "close_run" {
			return
		}
	}
	t.Fatalf("the refused box run was registered and left open: the signer saw %v", methods)
}
