package tracekit

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func dialFake(t *testing.T, f *fakeSigner, timeout time.Duration) *client {
	t.Helper()
	c, err := Dial(context.Background(), Options{Signer: f.path, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c.(*client)
}

func newFakeRun(t *testing.T, c *client) *run {
	t.Helper()
	r, err := c.NewRun(context.Background(), Agent{Name: "tkbox", Version: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	return r.(*run)
}

func noSystemConfig(t *testing.T) {
	t.Helper()
	old := loadSystemConfig
	loadSystemConfig = func() (map[string]any, error) { return nil, nil }
	t.Cleanup(func() { loadSystemConfig = old })
}

func TestDialStatus(t *testing.T) {
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 0)
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.RPCVersion != 19 || st.SignerVersion != "1.4.2" || st.Identity != "uid:501" || st.Where != f.path {
		t.Fatalf("status %+v", st)
	}
	if c.Where() != f.path {
		t.Fatalf("Where = %s", c.Where())
	}
}

func TestDialHelloMismatch(t *testing.T) {
	noSystemConfig(t)
	for _, c := range []struct {
		proto []any
		want  []string
	}{
		{[]any{20, 22}, []string{"1.5.0", "20..22", "protocol 19", "no longer serves"}},
		{[]any{15, 18}, []string{"1.5.0", "15..18", "protocol 19", "upgrade it to Tracekit 1.4.2"}},
		{nil, []string{"(none named)"}},
	} {
		f := newFakeSigner(t)
		f.hello = map[string]any{"proto": c.proto, "version": "1.5.0", "pid": 7}
		_, err := Dial(context.Background(), Options{Signer: f.path})
		var inc *Incompatible
		if !errors.As(err, &inc) {
			t.Fatalf("proto %v: err %v, want *Incompatible", c.proto, err)
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("proto %v: %q lacks %q", c.proto, err, w)
			}
		}
	}
}

func TestDialNoSigner(t *testing.T) {
	noSystemConfig(t)
	_, err := Dial(context.Background(), Options{Signer: shortTempDir(t) + "/none.sock"})
	var u *Unavailable
	if !errors.As(err, &u) {
		t.Fatalf("err %v, want *Unavailable", err)
	}
}

func TestRPCError(t *testing.T) {
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 0)
	r := newFakeRun(t, c)
	f.handle = func(conn int, req map[string]any) any {
		return map[string]any{"error": map[string]any{"code": "quota_exceeded", "message": "slow down",
			"retry_after_ms": 250}}
	}
	_, err := r.Decide(context.Background(), Call{ID: "c1", Tool: ToolBash, Args: BashArgs([]string{"ls"})})
	var e *RPCError
	if !errors.As(err, &e) || e.Code != "quota_exceeded" || e.Message != "slow down" || e.RetryAfterMS != 250 {
		t.Fatalf("err %#v", err)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatal("run token in an error")
	}
}

func TestRetryKeepsRequestID(t *testing.T) {
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 0)
	r := newFakeRun(t, c)
	var decides atomic.Int32
	f.handle = func(conn int, req map[string]any) any {
		if req["method"] == "decide" && decides.Add(1) <= 2 {
			return dropConn{}
		}
		return f.standard(conn, req)
	}
	d, err := r.Decide(context.Background(), Call{ID: "c1", Tool: ToolBash, Args: BashArgs([]string{"ls"})})
	if err != nil || d.Decision != "allow" {
		t.Fatalf("%+v %v", d, err)
	}
	got := f.received("decide")
	if len(got) != 3 {
		t.Fatalf("%d decides", len(got))
	}
	for _, g := range got[1:] {
		if g.req["request_id"] != got[0].req["request_id"] || g.req["client_seq"] != got[0].req["client_seq"] ||
			g.conn == got[0].conn {
			t.Fatalf("retry changed request_id/client_seq or reused the connection: %v vs %v", g, got[0])
		}
	}

	// lost every time: unavailable after three sends, and the next event takes the next client_seq
	decides.Store(-100)
	_, err = r.Decide(context.Background(), Call{ID: "c2", Tool: ToolBash, Args: BashArgs([]string{"ls"})})
	var u *Unavailable
	if !errors.As(err, &u) || !strings.Contains(err.Error(), "3 times") {
		t.Fatalf("err %v", err)
	}
	if n := len(f.received("decide")); n != 6 {
		t.Fatalf("%d decides, want 6", n)
	}
	f.handle = f.standard
	if err := r.Observe(context.Background(), SourceBox, "trusted", map[string]any{"box_id": "b1"}); err != nil {
		t.Fatal(err)
	}
	obs := f.received("observe")
	if seq := obs[0].req["client_seq"]; seq != json.Number("2") {
		t.Fatalf("client_seq after a lost event = %v, want 2", seq)
	}
}

func TestSignerDropsEveryConnection(t *testing.T) {
	// the signer drops idle connections; each call still gets through on a fresh one
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 0)
	r := newFakeRun(t, c)
	var mu sync.Mutex
	answered := map[int]bool{}
	f.handle = func(conn int, req map[string]any) any {
		mu.Lock()
		defer mu.Unlock()
		if answered[conn] {
			return dropConn{}
		}
		answered[conn] = true
		return f.standard(conn, req)
	}
	for i := 0; i < 5; i++ {
		if err := r.Observe(context.Background(), SourceTask, "trusted", "do it"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEventsInClientSeqOrder(t *testing.T) {
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 0)
	r1, r2 := newFakeRun(t, c), newFakeRun(t, c)
	f.handle = func(conn int, req map[string]any) any {
		time.Sleep(time.Duration(rand.IntN(1500)) * time.Microsecond)
		return f.standard(conn, req)
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		for _, r := range []*run{r1, r2} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var err error
				if i%3 == 0 {
					_, err = r.Decide(context.Background(), Call{ID: "c" + string(rune('a'+i%26)), Tool: ToolBash,
						Args: BashArgs([]string{"ls"})})
				} else {
					err = r.Observe(context.Background(), SourceModelCall, "untrusted", map[string]any{"n": i})
				}
				if err != nil {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	if f.overlap {
		t.Fatal("two event calls of one run were in flight at once")
	}
	seqs := map[string][]int64{}
	streams := map[any]bool{}
	for _, g := range f.all() {
		if _, ok := g.req["client_seq"]; !ok {
			continue
		}
		n, _ := g.req["client_seq"].(json.Number).Int64()
		run := g.req["run_id"].(string)
		seqs[run] = append(seqs[run], n)
		streams[g.req["stream"]] = true
	}
	if len(streams) != 1 {
		t.Fatalf("streams %v", streams)
	}
	for run, s := range seqs {
		if len(s) != 40 {
			t.Fatalf("%s: %d events", run, len(s))
		}
		for i, n := range s {
			if n != int64(i) {
				t.Fatalf("%s: client_seq %v arrived out of order", run, s)
			}
		}
	}
}

func TestLongPollOnItsOwnConnection(t *testing.T) {
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 0)
	r := newFakeRun(t, c)
	release := make(chan struct{})
	waiting := make(chan struct{})
	f.handle = func(conn int, req map[string]any) any {
		if req["method"] == "approval_wait" && req["approval_id"] == "appr-1" {
			close(waiting)
			<-release
		}
		return f.standard(conn, req)
	}
	done := make(chan error, 1)
	go func() {
		state, err := r.WaitApproval(context.Background(), "appr-1", time.Minute)
		if err == nil && state != ApprovalApproved {
			err = errors.New("state " + state)
		}
		done <- err
	}()
	<-waiting
	// other calls, events of the same run included, are not held up by the wait
	if _, err := r.Decide(context.Background(), Call{ID: "c1", Tool: ToolBash, Args: BashArgs([]string{"ls"})}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	w := f.received("approval_wait")
	if len(w) != 1 || w[0].req["timeout_ms"] != json.Number("60000") {
		t.Fatalf("waits %v", w)
	}
	for _, g := range f.all() {
		if g.conn == w[0].conn && g.method != "approval_wait" {
			t.Fatalf("%s went on the long poll's connection", g.method)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for !f.connClosed(w[0].conn) {
		if time.Now().After(deadline) {
			t.Fatal("the long poll's connection was kept")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// capped at the signer's 300 s
	go func() { _, _ = r.WaitApproval(context.Background(), "appr-2", time.Hour) }()
	deadline = time.Now().Add(2 * time.Second)
	for len(f.received("approval_wait")) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if w := f.received("approval_wait"); len(w) != 2 || w[1].req["timeout_ms"] != json.Number("300000") {
		t.Fatalf("waits %v", w)
	}
}

func TestOversizeFrames(t *testing.T) {
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 0)
	r := newFakeRun(t, c)
	err := r.Observe(context.Background(), SourceTask, "trusted", strings.Repeat("x", maxLine))
	var e *RPCError
	if !errors.As(err, &e) || e.Code != "quota_exceeded" || !strings.Contains(e.Message, "not sent") {
		t.Fatalf("err %v", err)
	}
	if len(f.received("observe")) != 0 {
		t.Fatal("an oversize frame was sent")
	}
	// the client_seq was not used
	if err := r.Observe(context.Background(), SourceTask, "trusted", "ok"); err != nil {
		t.Fatal(err)
	}
	if seq := f.received("observe")[0].req["client_seq"]; seq != json.Number("0") {
		t.Fatalf("client_seq %v", seq)
	}
	// an answer over the limit
	f.handle = func(conn int, req map[string]any) any {
		return rawLine(`{"run_seq":1,"pad":"` + strings.Repeat("y", maxLine) + `"}`)
	}
	err = r.Observe(context.Background(), SourceTask, "trusted", "ok")
	var u *Unavailable
	if !errors.As(err, &u) || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("err %v", err)
	}
	// a bad identifier is refused before sending
	_, err = r.Decide(context.Background(), Call{ID: "bad id", Tool: ToolBash})
	if !errors.As(err, &e) || e.Code != "invalid_request" {
		t.Fatalf("err %v", err)
	}
}

func TestTimeoutIsUnavailable(t *testing.T) {
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 200*time.Millisecond)
	r := newFakeRun(t, c)
	f.handle = func(conn int, req map[string]any) any { return hangConn{} }
	start := time.Now()
	_, err := r.Decide(context.Background(), Call{ID: "c1", Tool: ToolBash, Args: BashArgs([]string{"ls"})})
	var u *Unavailable
	if !errors.As(err, &u) || time.Since(start) > 2*time.Second {
		t.Fatalf("err %v after %s", err, time.Since(start))
	}
	if n := len(f.received("decide")); n != 1 {
		t.Fatalf("a call with no answer was resent (%d sends)", n)
	}
	// ctx cancellation too
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c.t.timeout = time.Minute
	_, err = r.Decide(ctx, Call{ID: "c2", Tool: ToolBash, Args: BashArgs([]string{"ls"})})
	if !errors.As(err, &u) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
}

func TestCloseSendsLastClientSeq(t *testing.T) {
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 0)
	r := newFakeRun(t, c)
	for i := 0; i < 2; i++ {
		if err := r.Observe(context.Background(), SourceTask, "trusted", i); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(context.Background(), strings.Repeat("r", 300)); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(context.Background(), "again"); err != nil {
		t.Fatal(err)
	}
	cl := f.received("close_run")
	if len(cl) != 1 {
		t.Fatalf("%d close_run", len(cl))
	}
	last := cl[0].req["last_client_seq"].([]any)[0].(map[string]any)
	if last["client_seq"] != json.Number("1") || last["stream"] != c.stream {
		t.Fatalf("last_client_seq %v", last)
	}
	if len([]rune(cl[0].req["reason"].(string))) != maxCloseReason {
		t.Fatal("close reason not cut to 256 characters")
	}
	// a run with no events sends none; run_closed means closed
	r2 := newFakeRun(t, c)
	f.handle = func(conn int, req map[string]any) any {
		return map[string]any{"error": map[string]any{"code": "run_closed", "message": "closed"}}
	}
	if err := r2.Close(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.received("close_run")[1].req["last_client_seq"]; ok {
		t.Fatal("last_client_seq without events")
	}
}

func TestCompleteFields(t *testing.T) {
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 0)
	r := newFakeRun(t, c)
	call := Call{ID: "c1", Tool: ToolBash, Args: BashArgs([]string{"ls"}), Attempt: 1}
	d := Decision{Decision: "allow", DecisionID: "d1"}
	if err := r.Complete(context.Background(), call, d, "ok", map[string]any{"exit_code": 0}); err != nil {
		t.Fatal(err)
	}
	d.SendResult = true
	if err := r.Complete(context.Background(), call, d, "ok", map[string]any{"exit_code": 0}); err != nil {
		t.Fatal(err)
	}
	if err := r.Complete(context.Background(), call, d, "ok", strings.Repeat("z", maxLine/2)); err != nil {
		t.Fatal(err)
	}
	if err := r.Complete(context.Background(), call, d, "error", "not run: blocked"); err != nil {
		t.Fatal(err)
	}
	if err := r.Complete(context.Background(), call, d, "maybe", nil); err == nil {
		t.Fatal("status maybe accepted")
	}
	got := f.received("complete")
	if len(got) != 4 {
		t.Fatalf("%d completes", len(got))
	}
	want, _ := ArgsDigest(ToolBash, BashArgs([]string{"ls"}))
	digest, _ := EventHash(map[string]any{"exit_code": 0})
	for i, g := range got {
		if g.req["args_digest"] != want || g.req["decision_id"] != "d1" || g.req["attempt"] != json.Number("1") ||
			g.req["tool_call_id"] != "c1" {
			t.Fatalf("complete %d: %v", i, g.req)
		}
	}
	if got[0].req["result"] != digest {
		t.Fatalf("result not sent as its digest: %v", got[0].req["result"])
	}
	if m, ok := got[1].req["result"].(map[string]any); !ok || m["exit_code"] != json.Number("0") {
		t.Fatalf("result not sent as is: %v", got[1].req["result"])
	}
	if s, _ := got[2].req["result"].(string); !strings.HasPrefix(s, "sha256:") {
		t.Fatalf("a result over half a frame went as is")
	}
	if got[3].req["error"] != "not run: blocked" || got[3].req["status"] != "error" || got[3].req["result"] != nil {
		t.Fatalf("error complete: %v", got[3].req)
	}
}

func TestContained(t *testing.T) {
	noSystemConfig(t)
	f := newFakeSigner(t)
	c := dialFake(t, f, 0)
	r := newFakeRun(t, c)
	pages := [][]any{
		{ev(0, "run.registered", nil), ev(1, "policy.decision", nil)},
		{ev(2, "run.held", map[string]any{"incident_id": "inc-1", "reason": "TK-Q001"})},
		{ev(3, "run.resumed", map[string]any{"incident_id": "inc-1", "held_by": []any{}})},
		{ev(4, "run.quarantined", map[string]any{"incident_id": "inc-2", "reason": "operator"}),
			ev(5, "run.closing", map[string]any{"reason": "quarantine"})},
	}
	var page atomic.Int32
	f.handle = func(conn int, req map[string]any) any {
		if req["method"] != "read" {
			return f.standard(conn, req)
		}
		p := int(page.Load())
		if p >= len(pages) {
			return map[string]any{"events": []any{}, "next_seq": nil}
		}
		from, _ := req["from_seq"].(json.Number).Int64()
		first, _ := pages[p][0].(map[string]any)["run_seq"].(int)
		if from != int64(first) {
			t.Errorf("read from_seq %d, want %d", from, first)
		}
		page.Add(1)
		return map[string]any{"events": pages[p], "next_seq": nil}
	}
	want := []Containment{
		{},
		{Contained: true, State: "held", IncidentID: "inc-1", Reason: "TK-Q001"},
		{Contained: false, Reason: "TK-Q001"},
		{Contained: true, State: "quarantined", IncidentID: "inc-2", Reason: "operator"},
		{Contained: true, State: "quarantined", IncidentID: "inc-2", Reason: "operator"},
	}
	for i, w := range want {
		got, err := r.Contained(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got.Contained != w.Contained || got.State != w.State || got.IncidentID != w.IncidentID {
			t.Fatalf("poll %d: %+v, want %+v", i, got, w)
		}
	}
	if reads := f.received("read"); reads[0].req["run_token"] != "secret-token" || reads[0].req["limit"] != json.Number("1000") {
		t.Fatalf("read %v", reads[0].req)
	}
}

func ev(seq int, typ string, data map[string]any) any {
	if data == nil {
		data = map[string]any{}
	}
	return map[string]any{"run_seq": seq, "type": typ, "event_hash": "sha256:" + strings.Repeat("0", 64), "data": data}
}

func TestRunStringHidesToken(t *testing.T) {
	r := &run{id: "run-1", token: "secret-token"}
	for _, s := range []string{r.String(), r.GoString()} {
		if strings.Contains(s, "secret") {
			t.Fatal(s)
		}
	}
}
