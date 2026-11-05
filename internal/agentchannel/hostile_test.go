package agentchannel

import (
	"fmt"
	"testing"
)

// A refused frame must reach the signer under no spelling: JSON escapes in keys and method names, a second key of the
// same name, or the forbidden field nested under an escaped name.
func TestEscapedAndDuplicateSpellingsNeverReachSigner(t *testing.T) {
	for _, raw := range []string{
		`{"method":"approval_decide","approval_id":"approval-owned","decision":"approve","request_id":"r"}`,
		`{"method":"decide","method":"approval_decide","approval_id":"approval-owned","request_id":"r"}`,
		`{"method":"register_run","request_id":"r","agent":{"name":"a"},"parent":{"run_id":"x","run_token":"y"}}`,
		`{"method":"register_run","request_id":"r","agent":{"name":"a"},"box":{"id":"b"}}`,
		`{"method":"decide","run_id":"owned","run_token":"owned-token","caller":"uid:0"}`,
		`{"method":"decide","run_id":"owned","run_token":"owned-token","ext":{}}`,
		`{"method":"observe","run_id":"owned","run_token":"owned-token","source":"tkbox.box","trust":"trusted","value":1}`,
		`{"method":"decide","run_id":"owned","run_id":"box-run"}`,
		string([]byte{0xef, 0xbb, 0xbf}) + `{"method":"approval_decide"}`,
		`{"method":"approval_get","approval_id":"approval-other"}`,
		`{"method":"decide","run_id":"box-run","run_token":"t"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			f := &matrixSigner{seen: make(chan map[string]any, 4)}
			_, c, r, done := channelHarness(t, f)
			ans := frameExchange(t, c, r, raw)
			if _, refused := ans["error"]; !refused {
				t.Fatalf("not refused: %v", ans)
			}
			select {
			case m := <-f.seen:
				t.Fatalf("the signer saw %v", m)
			default:
			}
			c.Close()
			<-done
		})
	}
}

// Two frames in one write are answered in order, each checked on its own.
func TestPipelinedFramesAnsweredInOrder(t *testing.T) {
	f := &matrixSigner{seen: make(chan map[string]any, 4)}
	_, c, r, done := channelHarness(t, f)
	go func() {
		_, _ = c.Write([]byte(`{"method":"approval_decide"}` + "\n" + `{"method":"status"}` + "\n"))
	}()
	for i, want := range []bool{true, false} {
		line, err := r.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		if refused := len(line) > 9 && string(line[:9]) == `{"error":`; refused != want {
			t.Fatalf("frame %d: %s", i, line)
		}
	}
	if m := <-f.seen; m["method"] != "status" {
		t.Fatalf("the signer saw %v", m)
	}
	c.Close()
	<-done
}

// The run cap counts registrations still waiting for the signer's answer: with 250 runs and 16 connections each
// registering at once, at most 6 more may pass the check.
func TestRunCapCountsRegistrationsInFlight(t *testing.T) {
	s := New(nil, "box-run", "box-token")
	for i := 0; i < MaxRuns-6; i++ {
		s.runs[fmt.Sprintf("run-%d", i)] = runEntry{token: "t"}
	}
	passed := 0
	for i := 0; i < MaxConnections; i++ {
		if s.check("register_run", fieldsOf(t, `{"method":"register_run"}`), nil) == nil {
			passed++
		}
	}
	if passed > 6 {
		t.Fatalf("%d registrations passed the check with %d runs registered, cap %d", passed, MaxRuns-6, MaxRuns)
	}
}
