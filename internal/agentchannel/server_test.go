package agentchannel

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"testing"
)

func TestProxyRegistersFreshAndScopesRuns(t *testing.T) {
	seen := make(chan map[string]any, 4)
	s := New(func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			r := bufio.NewReader(b)
			for {
				line, err := r.ReadBytes('\n')
				if err != nil {
					return
				}
				var m map[string]any
				_ = json.Unmarshal(line, &m)
				seen <- m
				var answer any = map[string]any{"ok": true}
				if m["method"] == "register_run" {
					answer = map[string]any{"run_id": "run-1", "run_token": "token-1"}
				}
				out, _ := json.Marshal(answer)
				_, _ = b.Write(append(out, '\n'))
			}
		}()
		return a, nil
	}, "box-run", "box-token")
	guest, client := net.Pipe()
	done := make(chan struct{})
	go func() { a := &activeConn{guest: guest}; s.handle(a); close(done) }()
	r := bufio.NewReader(client)
	_, _ = client.Write([]byte(`{"method":"register_run","request_id":"r1","agent":{"name":"agent"},"run_id":"attacker"}` + "\n"))
	var reg map[string]any
	if err := json.NewDecoder(r).Decode(&reg); err != nil {
		t.Fatal(err)
	}
	if reg["run_id"] != "run-1" {
		t.Fatalf("register response: %v", reg)
	}
	forwarded := <-seen
	if len(forwarded) != 3 || forwarded["method"] != "register_run" || forwarded["request_id"] != "r1" || forwarded["agent"] == nil {
		t.Fatalf("register_run was not rebuilt: %v", forwarded)
	}
	_, _ = client.Write([]byte(`{"method":"decide","run_id":"run-1","run_token":"token-1"}` + "\n"))
	var answer map[string]any
	if err := json.NewDecoder(r).Decode(&answer); err != nil {
		t.Fatal(err)
	}
	if <-seen == nil {
		t.Fatal("fake signer did not receive allowed frame")
	}
	_, _ = client.Write([]byte(`{"method":"approval_decide","run_id":"run-1"}` + "\n"))
	var refusal map[string]any
	if err := json.NewDecoder(r).Decode(&refusal); err != nil {
		t.Fatal(err)
	}
	if _, ok := refusal["error"]; !ok {
		t.Fatalf("expected refusal: %v", refusal)
	}
	client.Close()
	<-done
}
