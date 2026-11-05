package agentchannel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type matrixSigner struct {
	seen   chan map[string]any
	answer func(map[string]any) map[string]any
}

func (f *matrixSigner) dial(context.Context) (net.Conn, error) {
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		r := bufio.NewReader(b)
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return
			}
			var m map[string]any
			if json.Unmarshal(line, &m) != nil {
				return
			}
			f.seen <- m
			ans := map[string]any{"ok": true}
			if f.answer != nil {
				ans = f.answer(m)
			}
			out, _ := json.Marshal(ans)
			if _, err := b.Write(append(out, '\n')); err != nil {
				return
			}
		}
	}()
	return a, nil
}

func channelHarness(t *testing.T, f *matrixSigner) (*Server, net.Conn, *bufio.Reader, <-chan struct{}) {
	t.Helper()
	s := New(f.dial, "box-run", "box-token")
	s.runs["owned"] = runEntry{token: "owned-token"}
	s.approvals["approval-owned"] = true
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { s.handle(&activeConn{guest: a}); close(done) }()
	return s, b, bufio.NewReader(b), done
}

func frameExchange(t *testing.T, c net.Conn, r *bufio.Reader, raw string) map[string]any {
	t.Helper()
	if _, err := c.Write([]byte(raw + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("response %q: %v", line, err)
	}
	return m
}

func TestAllowedMethodsPassFakeSigner(t *testing.T) {
	methods := []string{"hello", "register_run", "decide", "complete", "observe", "model_event", "state_write", "approval_request", "approval_wait", "approval_consume", "approval_get", "approval_abandon", "constraint_add", "close_run", "tailer_lost", "status"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			f := &matrixSigner{seen: make(chan map[string]any, 2), answer: func(m map[string]any) map[string]any {
				if m["method"] == "approval_request" {
					return map[string]any{"approval_id": "approval-owned"}
				}
				if m["method"] == "register_run" {
					return map[string]any{"run_id": "fresh", "run_token": "token"}
				}
				return map[string]any{"ok": true}
			}}
			s, c, r, done := channelHarness(t, f)
			obj := `"method":"` + method + `"`
			if method != "hello" && method != "status" && method != "register_run" {
				obj += `,"run_id":"owned"`
			}
			if method == "approval_get" {
				obj += `,"approval_id":"approval-owned"`
			}
			ans := frameExchange(t, c, r, "{"+obj+"}")
			if ans["error"] != nil {
				t.Fatalf("refused: %v", ans)
			}
			select {
			case got := <-f.seen:
				if got["method"] != method {
					t.Fatalf("signer saw %v", got)
				}
			case <-time.After(time.Second):
				t.Fatal("fake signer did not see allowed method")
			}
			_ = c.Close()
			<-done
			_ = s
		})
	}
}

func TestRefusedMethodsNeverReachFakeSigner(t *testing.T) {
	for _, method := range []string{
		"approval_decide", "approval_decide_on_behalf", "approval_list", "approval_review", "approval_revoke", "approval_agents",
		"delegate_run", "tailer_heartbeat", "observe_effect", "read", "checkpoint_nudge", "decision_import", "passkey_register",
		"content_get", "content_erase", "why_finding", "review_finding", "incident_list", "incident_show", "incident_resolve",
		"run_hold", "run_quarantine", "run_resume", "response_pause", "response_resume", "identity_suspend", "identity_lift",
		"pcm_sign", "pcm_grant", "pcm_delegate", "pcm_evidence", "channel_open", "not_a_method",
	} {
		t.Run(method, func(t *testing.T) {
			f := &matrixSigner{seen: make(chan map[string]any, 1)}
			_, c, r, done := channelHarness(t, f)
			ans := frameExchange(t, c, r, `{"method":"`+method+`"}`)
			if ans["error"] == nil {
				t.Fatalf("method passed: %v", ans)
			}
			select {
			case got := <-f.seen:
				t.Fatalf("fake signer saw refused method: %v", got)
			case <-time.After(20 * time.Millisecond):
			}
			_ = c.Close()
			<-done
		})
	}
}

func TestFieldRulesOwnershipAndFreshRegister(t *testing.T) {
	for _, field := range []string{"caller", "on_behalf", "amended", "tool_results", "ext"} {
		for _, method := range []string{"decide", "observe", "complete"} {
			t.Run("top-level-"+field+"-"+method, func(t *testing.T) {
				f := &matrixSigner{seen: make(chan map[string]any, 1)}
				_, c, r, done := channelHarness(t, f)
				ans := frameExchange(t, c, r, `{"method":"`+method+`","run_id":"owned","`+field+`":{}}`)
				if ans["error"] == nil {
					t.Fatalf("field %s passed", field)
				}
				select {
				case got := <-f.seen:
					t.Fatalf("signer saw field refusal: %v", got)
				case <-time.After(20 * time.Millisecond):
				}
				_ = c.Close()
				<-done
			})
		}
	}
	for _, raw := range []string{
		`{"method":"register_run","box":{}}`,
		`{"method":"register_run","parent":"x"}`,
		`{"method":"register_run","principal":"x"}`,
		`{"method":"register_run","principal_token":"x"}`,
		`{"method":"register_run","source":"x"}`,
		`{"method":"register_run","tenant":"x"}`,
		`{"method":"register_run","analyzes":"x"}`,
		`{"method":"register_run","replay_of":"x"}`,
		`{"method":"register_run","investigation":"x"}`,
		`{"method":"register_run","ext":{}}`,
		`{"method":"observe","run_id":"owned","source":"tkbox.x"}`,
		`{"method":"approval_get","approval_id":"foreign"}`,
		`{"method":"decide","run_id":"foreign"}`,
		`{"method":"decide","run_id":"box-run"}`,
	} {
		t.Run(fmt.Sprint(len(raw)), func(t *testing.T) {
			f := &matrixSigner{seen: make(chan map[string]any, 1)}
			_, c, r, done := channelHarness(t, f)
			ans := frameExchange(t, c, r, raw)
			if ans["error"] == nil {
				t.Fatalf("accepted %s", raw)
			}
			select {
			case got := <-f.seen:
				t.Fatalf("signer saw refused frame %v", got)
			case <-time.After(20 * time.Millisecond):
			}
			_ = c.Close()
			<-done
		})
	}
	f := &matrixSigner{seen: make(chan map[string]any, 1), answer: func(map[string]any) map[string]any { return map[string]any{"run_id": "fresh", "run_token": "token"} }}
	_, c, r, done := channelHarness(t, f)
	ans := frameExchange(t, c, r, `{"method":"register_run","request_id":"req","agent":{"name":"agent"},"run_id":"attacker"}`)
	if ans["run_id"] != "fresh" {
		t.Fatalf("register reply %v", ans)
	}
	got := <-f.seen
	if len(got) != 3 || got["method"] != "register_run" || got["request_id"] != "req" || got["agent"] == nil {
		t.Fatalf("register was not rebuilt fresh: %v", got)
	}
	_ = c.Close()
	<-done
}

func TestSignerRunReuseAndClosedRunNotClosedAgain(t *testing.T) {
	s := New(nil, "box-run", "")
	if err := s.record("register_run", []byte(`{"run_id":"owned","run_token":"t"}`), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.record("register_run", []byte(`{"run_id":"owned","run_token":"t2"}`), nil); err == nil {
		t.Fatal("signer run id reuse accepted")
	}
	if err := s.record("close_run", []byte(`{"ok":true}`), map[string]any{"run_id": "owned"}); err != nil {
		t.Fatal(err)
	}
	called := false
	s.Dial = func(context.Context) (net.Conn, error) { called = true; return nil, errors.New("unexpected dial") }
	if errs := s.CloseRuns(context.Background()); len(errs) != 0 {
		t.Fatal(errs)
	}
	if called {
		t.Fatal("agent-closed run got a second close_run")
	}
}

func TestCloseRunsClosesOnlyOpenEntries(t *testing.T) {
	f := &matrixSigner{seen: make(chan map[string]any, 2)}
	s := New(f.dial, "box-run", "")
	s.runs["already-closed"] = runEntry{token: "closed-token", closed: true}
	s.runs["still-open"] = runEntry{token: "open-token"}
	if errs := s.CloseRuns(context.Background()); len(errs) != 0 {
		t.Fatal(errs)
	}
	select {
	case req := <-f.seen:
		if req["method"] != "close_run" || req["run_id"] != "still-open" || req["run_token"] != "open-token" {
			t.Fatalf("close request %v", req)
		}
	case <-time.After(time.Second):
		t.Fatal("open run was not closed")
	}
	if errs := s.CloseRuns(context.Background()); len(errs) != 0 {
		t.Fatal(errs)
	}
	select {
	case req := <-f.seen:
		t.Fatalf("closed run was closed again: %v", req)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestRunCapCountsClosedRuns(t *testing.T) {
	s := New(nil, "box-run", "")
	for i := 0; i < MaxRuns; i++ {
		s.runs[fmt.Sprintf("r%d", i)] = runEntry{closed: true}
	}
	err := s.check("register_run", map[string]any{}, nil)
	var refused *refusal
	if !errors.As(err, &refused) || refused.code != "quota_exceeded" || refused.kind != RefusedRunCap {
		t.Fatalf("cap error %v", err)
	}
}

func TestByteBudgetChargesFullFrameAndRecordsOnce(t *testing.T) {
	f := &matrixSigner{seen: make(chan map[string]any, 3)}
	s, c, r, done := channelHarness(t, f)
	var mu sync.Mutex
	var events int
	s.OnLimit = func(string) { mu.Lock(); events++; mu.Unlock() }
	frame := `{"method":"observe","run_id":"owned","value":"x"}`
	if got := frameExchange(t, c, r, frame); got["error"] != nil {
		t.Fatal(got)
	}
	if s.bytes != int64(len(frame)) {
		t.Fatalf("budget=%d, want complete frame %d", s.bytes, len(frame))
	}
	s.mu.Lock()
	s.bytes = ByteBudget - int64(len(frame)) + 1
	s.mu.Unlock()
	for i := 0; i < 2; i++ {
		ans := frameExchange(t, c, r, frame)
		em, _ := ans["error"].(map[string]any)
		if em["code"] != "quota_exceeded" {
			t.Fatalf("budget response %v", ans)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if events != 1 {
		t.Fatalf("limit events=%d, want one", events)
	}
	_ = c.Close()
	<-done
}

func TestByteBudgetChargesEachFullContentFrame(t *testing.T) {
	s := New(nil, "box-run", "")
	s.runs["owned"] = runEntry{token: "t"}
	for _, method := range []string{"model_event", "complete", "observe"} {
		frame := []byte(`{"method":"` + method + `","run_id":"owned","body":"b","result":"r","value":"v"}`)
		s.bytes = 0
		if err := s.check(method, map[string]any{"run_id": "owned"}, frame); err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		if s.bytes != int64(len(frame)) {
			t.Errorf("%s charged %d, want full frame %d", method, s.bytes, len(frame))
		}
	}
}

func TestApprovalOwnershipComesFromOwnSignerResponse(t *testing.T) {
	f := &matrixSigner{seen: make(chan map[string]any, 2), answer: func(m map[string]any) map[string]any {
		if m["method"] == "approval_request" {
			return map[string]any{"approval_id": "issued-here"}
		}
		return map[string]any{"ok": true}
	}}
	s, c, r, done := channelHarness(t, f)
	if ans := frameExchange(t, c, r, `{"method":"approval_request","run_id":"owned"}`); ans["error"] != nil {
		t.Fatal(ans)
	}
	<-f.seen
	if ans := frameExchange(t, c, r, `{"method":"approval_get","approval_id":"issued-here"}`); ans["error"] != nil {
		t.Fatal(ans)
	}
	<-f.seen
	if !s.approvals["issued-here"] {
		t.Fatal("approval response was not recorded for this box")
	}
	_ = c.Close()
	<-done
}

func TestInvalidFramesConsumeRateTokens(t *testing.T) {
	f := &matrixSigner{seen: make(chan map[string]any, 1)}
	s, c, r, done := channelHarness(t, f)
	s.mu.Lock()
	s.frames = 1
	s.last = time.Now()
	s.mu.Unlock()
	first := frameExchange(t, c, r, `{"method":"not_allowed"}`)
	if first["error"] == nil {
		t.Fatalf("invalid method accepted: %v", first)
	}
	second := frameExchange(t, c, r, `{"method":"status"}`)
	em, _ := second["error"].(map[string]any)
	if em["code"] != "quota_exceeded" || em["retry_after_ms"] == nil {
		t.Fatalf("invalid frame did not consume token: %v", second)
	}
	select {
	case got := <-f.seen:
		t.Fatalf("signer saw invalid or throttled frame: %v", got)
	default:
	}
	_ = c.Close()
	<-done
}

type orderedConn struct {
	net.Conn
	events *[]string
}

func (c orderedConn) Close() error {
	*c.events = append(*c.events, "connection")
	return c.Conn.Close()
}

type orderedListener struct {
	net.Listener
	events *[]string
}

type deadlineConn struct {
	net.Conn
	set chan time.Time
}

func (c deadlineConn) SetDeadline(t time.Time) error {
	select {
	case c.set <- t:
	default:
	}
	return c.Conn.SetDeadline(t)
}

func (l orderedListener) Close() error {
	*l.events = append(*l.events, "listener")
	return l.Listener.Close()
}

func TestCloseOrderListenerThenConnections(t *testing.T) {
	var events []string
	a, b := net.Pipe()
	s := New(nil, "box-run", "")
	s.connections[&activeConn{guest: orderedConn{Conn: a, events: &events}, signer: orderedConn{Conn: b, events: &events}}] = struct{}{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.Close(orderedListener{Listener: l, events: &events})
	if len(events) != 3 || events[0] != "listener" || events[1] != "connection" || events[2] != "connection" {
		t.Fatalf("close sequence %v", events)
	}
}

func TestRateLimitRetriesWithoutBlockingAndRecovers(t *testing.T) {
	f := &matrixSigner{seen: make(chan map[string]any, 2)}
	s, c, r, done := channelHarness(t, f)
	s.mu.Lock()
	s.frames = 0
	s.last = time.Now()
	s.mu.Unlock()
	ans := frameExchange(t, c, r, `{"method":"status"}`)
	em, _ := ans["error"].(map[string]any)
	if em["code"] != "quota_exceeded" || em["retry_after_ms"] == nil {
		t.Fatalf("rate refusal %v", ans)
	}
	select {
	case <-f.seen:
		t.Fatal("limited frame reached signer")
	default:
	}
	time.Sleep(30 * time.Millisecond)
	if ans = frameExchange(t, c, r, `{"method":"status"}`); ans["error"] != nil {
		t.Fatalf("rate bucket did not recover: %v", ans)
	}
	select {
	case <-f.seen:
	case <-time.After(time.Second):
		t.Fatal("recovered frame did not pass")
	}
	_ = c.Close()
	<-done
}

func TestSignerReplyDeadlineAndCloseWakeApprovalWait(t *testing.T) {
	if SignerReplyTimeout != 330*time.Second {
		t.Fatalf("reply timeout %s", SignerReplyTimeout)
	}
	accepted := make(chan net.Conn, 1)
	quit := make(chan struct{})
	deadlines := make(chan time.Time, 1)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := New(func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { r := bufio.NewReader(b); _, _ = r.ReadBytes('\n'); accepted <- b; <-quit; _ = b.Close() }()
		return deadlineConn{Conn: a, set: deadlines}, nil
	}, "box-run", "")
	s.runs["owned"] = runEntry{token: "token"}
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(l) }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte(`{"method":"approval_wait","run_id":"owned"}` + "\n"))
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("fake signer did not receive approval_wait")
	}
	select {
	case d := <-deadlines:
		left := time.Until(d)
		if left < 320*time.Second || left > SignerReplyTimeout {
			t.Fatalf("signer reply deadline %s away", left)
		}
	case <-time.After(time.Second):
		t.Fatal("signer reply deadline was not set")
	}
	closed := make(chan struct{})
	go func() { s.Close(l); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close waited on signer reply")
	}
	close(quit)
	_ = c.Close()
	_ = serveDone
}

func TestPartialFrameDeadlineShortHook(t *testing.T) {
	f := &matrixSigner{seen: make(chan map[string]any, 1)}
	s, c, _, done := channelHarness(t, f)
	s.FrameTimeout = 20 * time.Millisecond
	_, _ = c.Write([]byte("{"))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("partial frame did not time out")
	}
	select {
	case got := <-f.seen:
		t.Fatalf("partial frame reached signer: %v", got)
	default:
	}
	_ = c.Close()
}

func TestTwoBoxesIsolateRunsApprovalsBudgetsAndRate(t *testing.T) {
	f := &matrixSigner{seen: make(chan map[string]any, 1)}
	a := New(f.dial, "box-a", "")
	b := New(f.dial, "box-b", "")
	a.runs["a-run"] = runEntry{token: "a"}
	a.approvals["a-approval"] = true
	b.runs["b-run"] = runEntry{token: "b"}
	b.approvals["b-approval"] = true
	for _, tc := range []struct {
		s      *Server
		method string
		obj    map[string]any
	}{{a, "decide", map[string]any{"run_id": "b-run"}}, {b, "approval_get", map[string]any{"approval_id": "a-approval"}}} {
		if err := tc.s.check(tc.method, tc.obj, nil); err == nil {
			t.Fatalf("cross-box check passed: %s %v", tc.method, tc.obj)
		}
	}
	if a.bytes != 0 || b.bytes != 0 {
		t.Fatal("box budget state crossed")
	}
	a.bytes = ByteBudget
	if b.bytes != 0 {
		t.Fatal("box budgets shared")
	}
	a.frames = 0
	if b.frames != RateBurst {
		t.Fatal("box rates shared")
	}
}

func TestServeOverConnectionCapStillAccepts(t *testing.T) {
	f := &matrixSigner{seen: make(chan map[string]any, 2)}
	s := New(f.dial, "box-run", "")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	clients := make([]net.Conn, MaxConnections)
	for i := range clients {
		clients[i], err = net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		n := len(s.connections)
		s.mu.Unlock()
		if n == MaxConnections {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d connections active", n)
		}
		time.Sleep(time.Millisecond)
	}
	refused, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	} // intentionally never reads the refusal
	// Dial returns once the kernel queues the connection, before Serve accepts it. A second over-cap connection whose
	// refusal arrives shows Serve accepted the first while full, and wasn't held up by it.
	probe, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = probe.SetReadDeadline(time.Now().Add(5 * time.Second))
	if line, err := bufio.NewReader(probe).ReadBytes('\n'); err != nil || !strings.Contains(string(line), "quota_exceeded") {
		t.Fatalf("over-cap connection: %q, %v", line, err)
	}
	_ = probe.Close()
	for _, c := range clients {
		_ = c.Close()
	}
	deadline = time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		n := len(s.connections)
		s.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("closing guests left %d active", n)
		}
		time.Sleep(time.Millisecond)
	}
	next, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = next.Write([]byte(`{"method":"status"}` + "\n"))
	_ = next.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = bufio.NewReader(next).ReadBytes('\n'); err != nil {
		t.Fatalf("new connection was not served: %v", err)
	}
	_ = next.Close()
	_ = refused.Close()
	s.Close(l)
}

func TestStrictFrameFailures(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"duplicate keys", []byte(`{"method":"status","a":1,"a":2}`)},
		{"bad utf8", []byte("{\"method\":\"status\",\"x\":\"\xff\"}")},
		{"depth 129", []byte(`{"method":"status","x":` + strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129) + "}")},
		{"trailing data", []byte(`{"method":"status"} {}`)},
		{"non-object", []byte(`[1]`)},
		{"over 1 MiB", []byte(`{"method":"status","x":"` + strings.Repeat("x", MaxFrame) + `"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.name == "over 1 MiB" {
				_, _, err = ReadFrame(bufio.NewReader(strings.NewReader(string(tc.input) + "\n")))
			} else {
				_, err = Decode(tc.input)
			}
			if err == nil {
				t.Fatalf("accepted %s", tc.name)
			}
		})
	}
}
