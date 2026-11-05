package agentchannel

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every refusal is reported (OnRefusal) by kind, with the channel's own reason and a plain method name only: never the
// frame's content. One per kind a second; the rest are folded into the kind's next report, and Close reports what is
// left.
func TestRefusalsAreReportedFoldedAndWithoutTheFrame(t *testing.T) {
	f := &matrixSigner{seen: make(chan map[string]any, 8)}
	s, c, r, done := channelHarness(t, f)
	var mu sync.Mutex
	var got []Refusal
	s.OnRefusal = func(e Refusal) { mu.Lock(); got = append(got, e); mu.Unlock() }
	var clockMu sync.Mutex
	now := time.Unix(1000, 0)
	s.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }

	const body = "frame-content-never-reported"
	for _, frame := range []string{
		`{"method":"approval_decide","approval_id":"` + body + `"}`,
		`{"method":"approval_decide","approval_id":"` + body + `"}`, // the same second: folded
		`{"method":"decide","run_id":"` + body + `"}`,
		`{"method":"register_run","request_id":"r","agent":{"name":"a"},"parent":{"run_id":"` + body + `"}}`,
		`{"method":"approval_get","approval_id":"` + body + `"}`,
		`{"method":"decide","run_id":"owned","caller":"` + body + `"}`, // a field again: folded
		`{"method":"` + body + `", "x": 1, "x": 2}`,
	} {
		if ans := frameExchange(t, c, r, frame); ans["error"] == nil {
			t.Fatalf("%s passed: %v", frame, ans)
		}
	}
	s.mu.Lock()
	s.frames, s.last = 0, time.Now() // the rate limiter's bucket is empty
	s.mu.Unlock()
	frameExchange(t, c, r, `{"method":"status"}`)
	s.mu.Lock()
	s.frames = RateBurst
	s.mu.Unlock()
	clockMu.Lock()
	now = now.Add(2 * time.Second)
	clockMu.Unlock()
	frameExchange(t, c, r, `{"method":"Approval-Decide `+body+`"}`) // a new second; no plain name
	_ = c.Close()
	<-done
	s.Close(nil)

	want := []Refusal{
		{Kind: RefusedMethod, Method: "approval_decide", Reason: "method not allowed"},
		{Kind: RefusedRun, Method: "decide", Reason: "run is not owned by this box"},
		{Kind: RefusedField, Method: "register_run", Reason: "register_run field parent is not passed"},
		{Kind: RefusedApproval, Method: "approval_get", Reason: "approval is not owned by this box"},
		{Kind: RefusedFrame, Reason: "not one strict JSON object"},
		{Kind: RefusedRate, Method: "status", Reason: fmt.Sprintf("over %d frames a second", RatePerSecond)},
		{Kind: RefusedMethod, Reason: "method not allowed", Folded: 1},
		{Kind: RefusedField, Folded: 1}, // at Close
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reports\n%+v\nwant\n%+v", got, want)
	}
	if strings.Contains(fmt.Sprint(got), body) {
		t.Fatal("a report carries the frame's content")
	}
}
