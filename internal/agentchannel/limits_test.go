package agentchannel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A guest that opens and closes connections used to make the daemon open a signer connection (hello + channel_open)
// for each, outside the frame rate: about 7,850 a second. Each connection now costs a rate token before its dial.
func TestConnectionChurnStaysWithinRateLimit(t *testing.T) {
	var inWindow atomic.Int64
	end := time.Now().Add(time.Second)
	s := New(func(context.Context) (net.Conn, error) {
		if time.Now().Before(end) {
			inWindow.Add(1)
		}
		a, b := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, b); b.Close() }()
		return a, nil
	}, "box-run", "")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	defer s.Close(l)
	opened := 0
	for time.Now().Before(end) {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			continue
		}
		opened++
		c.Close()
	}
	n := inWindow.Load()
	t.Logf("guest opened %d connections in 1 s; the daemon dialled the signer %d times in it", opened, n)
	if n > RateBurst+RatePerSecond {
		t.Fatalf("%d signer connection setups in one second, past the box's %d frames/s (burst %d)", n, RatePerSecond, RateBurst)
	}
}

// decide's args go into the signer's content vault, but only model_event, complete and observe used to be charged.
func TestDecideIsChargedToByteBudget(t *testing.T) {
	f := &matrixSigner{seen: make(chan map[string]any, 128)}
	s, c, r, done := channelHarness(t, f)
	s.mu.Lock()
	s.ReadRate, s.ReadBurst = 1<<40, 1<<40 // 70 MiB through the byte budget, not the read pace
	s.mu.Unlock()
	pad := strings.Repeat("A", MaxFrame-300)
	passed := 0
	for i := 0; i < 70; i++ {
		frame := `{"method":"decide","request_id":"r` + string(rune('a'+i%26)) + `","run_id":"owned","run_token":"owned-token","stream":"s","client_seq":1,"tool_call_id":"t","tool":"Bash","args_source":"parsed","args":{"command":"` + pad + `"}}`
		if ans := frameExchange(t, c, r, frame); ans["error"] == nil {
			passed += len(frame)
			<-f.seen
		}
	}
	c.Close()
	<-done
	if passed > ByteBudget {
		t.Fatalf("%d MiB of decide args reached the signer's vault past the %d MiB budget", passed>>20, ByteBudget>>20)
	}
}

// hello and status record nothing, so they don't spend the byte budget; every forwarded frame counts towards
// MaxForwardedFrames.
func TestForwardedFramesAreCapped(t *testing.T) {
	s := New(nil, "box-run", "")
	s.runs["owned"] = runEntry{token: "t"}
	if r := s.check("status", fieldsOf(t, `{"method":"status"}`), []byte(`{"method":"status"}`)); r != nil || s.bytes != 0 || s.forwarded != 1 {
		t.Fatalf("status: %v, %d bytes charged, %d forwarded", r, s.bytes, s.forwarded)
	}
	s.forwarded = MaxForwardedFrames
	for _, method := range []string{"status", "decide"} {
		r := s.check(method, fieldsOf(t, `{"run_id":"owned"}`), []byte(`{}`))
		if r == nil || r.kind != RefusedFrameCap || r.code != "quota_exceeded" {
			t.Fatalf("%s past the frame cap: %+v", method, r)
		}
	}
}

// A register_run in flight when the box stops: the signer registers the run while the stop closes the channel. Its
// reply must still reach the run table, so CloseRuns closes the run.
func TestCloseKeepsInFlightRegistration(t *testing.T) {
	registered := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	closed := map[string]bool{}
	s := New(func(context.Context) (net.Conn, error) {
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
				_ = json.Unmarshal(line, &m)
				var ans map[string]any
				switch m["method"] {
				case "register_run":
					close(registered)
					<-release
					ans = map[string]any{"run_id": "child-1", "run_token": "tok-1"}
				case "close_run":
					mu.Lock()
					closed[m["run_id"].(string)] = true
					mu.Unlock()
					ans = map[string]any{"run_id": m["run_id"], "state": "closing", "run_seq": 3}
				}
				out, _ := json.Marshal(ans)
				if _, err := b.Write(append(out, '\n')); err != nil {
					return
				}
			}
		}()
		return a, nil
	}, "box-run", "")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	g, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if _, err := g.Write([]byte(`{"method":"register_run","request_id":"r1","agent":{"name":"claude-code"}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	<-registered
	stopped := make(chan struct{})
	go func() { s.Close(l); close(stopped) }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-stopped
	if errs := s.CloseRuns(context.Background()); len(errs) != 0 {
		t.Fatal(errs)
	}
	mu.Lock()
	defer mu.Unlock()
	if !closed["child-1"] {
		t.Fatalf("the signer registered child-1 for this channel, but stop left it open (closed: %v, run table: %v)", closed, s.runs)
	}
}

// Each close_run used to wait up to 300 s for its reply, one run after another, whatever the context said.
func TestCloseRunsEndsWithItsContext(t *testing.T) {
	peers := make(chan net.Conn, 1)
	s := New(func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { _, _ = bufio.NewReader(b).ReadBytes('\n') }() // reads close_run, never answers
		peers <- b
		return a, nil
	}, "box-run", "")
	s.runs["child-1"] = runEntry{token: "tok"}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan []error)
	go func() { done <- s.CloseRuns(ctx) }()
	select {
	case errs := <-done:
		if len(errs) != 1 || !strings.Contains(errs[0].Error(), "deadline") {
			t.Fatalf("errors %v", errs)
		}
	case <-time.After(3 * time.Second):
		(<-peers).Close()
		<-done
		t.Fatal("CloseRuns still waiting 3 s after its 100 ms context ended")
	}
}

// A register_run is forwarded as the agent's own request_id and agent bytes: never longer than what came in, and not
// re-escaped (json.Marshal turned each < into <, six times longer).
func TestRegisterRunIsForwardedVerbatim(t *testing.T) {
	in := `{"method":"register_run","request_id":"r<1>","agent":{"name":"claude-code","version":"<&>"},"x":1}`
	f, err := Decode([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"method":"register_run","request_id":"r<1>","agent":{"name":"claude-code","version":"<&>"}}`
	if got := string(registerFrame(f)); got != want || len(got) > len(in) {
		t.Fatalf("forwarded %s, want %s", got, want)
	}
}

// Box's own runs are named tkbox (or the operator's --agent): an agent run may not take a name that reads as Box's.
func TestReservedAgentNamesAreRefused(t *testing.T) {
	for _, name := range []string{"tkbox", "TKBOX", " tkbox-agent", `\u0074kbox`, "\u200btkbox", "\ufefftkbox", "\uff54\uff4b\uff42\uff4f\uff58", "tkb\u043ex", "\u00adtkbox"} {
		_, err := Decode([]byte(`{"method":"register_run","request_id":"r","agent":{"name":"` + name + `"}}`))
		if r, ok := err.(*refusal); !ok || r.kind != RefusedField {
			t.Errorf("agent name %q: %v", name, err)
		}
	}
	if _, err := Decode([]byte(`{"method":"register_run","request_id":"r","agent":{"name":"claude-code"}}`)); err != nil {
		t.Fatal(err)
	}
}

func decodeCostFrame(unit string) []byte {
	return []byte(`{"method":"status","x":[` + strings.Repeat(unit, (MaxFrame-64)/len(unit)) + `0]}`)
}

// The strict check used to build the whole value: 35–50 MiB allocated and 12–20 MiB live for one 1 MiB frame, with up
// to 16 such frames per box. Wide frames still cost 9–34 MiB (a map of names per object, every top-level field kept).
// It now keeps the names of the open objects in a list reused per depth, and the top-level fields the rules read.
func TestDecodeCost(t *testing.T) {
	frames := wideShapes()
	for _, unit := range []string{"[],", "{},", "0,", `{"a":1},`, `"s",`} {
		frames["["+unit+" ...]"] = decodeCostFrame(unit)
	}
	for unit, frame := range frames {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		f, err := Decode(frame)
		if err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		allocated := after.TotalAlloc - before.TotalAlloc
		runtime.GC()
		runtime.ReadMemStats(&after)
		live := int64(after.HeapAlloc) - int64(before.HeapAlloc)
		runtime.KeepAlive(f)
		t.Logf("%q: %d KiB frame, %d KiB allocated, %d KiB live after decoding", unit, len(frame)>>10, allocated>>10, live>>10)
		// a normal build allocates almost nothing (each object's names stay on the stack); -race moves them to the heap
		if allocated > 4*uint64(len(frame)) || live > int64(len(frame))/4 {
			t.Errorf("%q: %d KiB allocated and %d KiB live to check a %d KiB frame", unit, allocated>>10, live>>10, len(frame)>>10)
		}
	}
}

func BenchmarkDecode1MiB(b *testing.B) {
	frame := decodeCostFrame("{},")
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		if _, err := Decode(frame); err != nil {
			b.Fatal(err)
		}
	}
}

// A signer connection is replaced before it has been quiet as long as the signer allows (TestAQuietSignerConnectionIsReplaced
// shows it working).
func TestSignerQuietLimitIsUnderTheSigners(t *testing.T) {
	const signerIdle = 30 * time.Second // the signer drops a connection silent this long (its read timeout is per recv)
	if SignerQuietLimit >= signerIdle {
		t.Errorf("SignerQuietLimit %s, want under the signer's %s", SignerQuietLimit, signerIdle)
	}
}

// fill repeats unit(i) after prefix until the frame is about MaxFrame, then closes it.
func fill(prefix string, unit func(i int) string, suffix string) []byte {
	var b strings.Builder
	b.WriteString(prefix)
	for i := 0; ; i++ {
		u := unit(i)
		if b.Len()+len(u)+len(suffix)+1 > MaxFrame {
			break
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(u)
	}
	b.WriteString(suffix)
	return []byte(b.String())
}

// wideShapes are frames of about 1 MiB that are wide rather than deep: many names in one object, or many objects.
func wideShapes() map[string][]byte {
	key := func(i int) string { return fmt.Sprintf(`"%x":0`, i) }
	skey := func(i int) string { return fmt.Sprintf(`"%x":""`, i) }
	esc := func(i int) string {
		var b strings.Builder
		for _, c := range fmt.Sprintf("%x", i) {
			fmt.Fprintf(&b, `\u%04x`, c)
		}
		return `"` + b.String() + `":0`
	}
	return map[string][]byte{
		"top-level keys (Frame.raw, kept)":      fill(`{"method":"status",`, key, `}`),
		"top-level string keys (raw+str, kept)": fill(`{"method":"status",`, skey, `}`),
		"one wide nested object (name map)":     fill(`{"method":"status","x":{`, key, `}}`),
		"escaped names in a nested object":      fill(`{"method":"status","x":{`, esc, `}}`),
		"many 17-name objects": fill(`{"method":"status","x":[`, func(int) string {
			return `{"a":0,"b":0,"c":0,"d":0,"e":0,"f":0,"g":0,"h":0,"i":0,"j":0,"k":0,"l":0,"m":0,"n":0,"o":0,"p":0,"q":0}`
		}, `]}`),
		"escaped strings in an array": fill(`{"method":"status","x":[`, func(int) string { return `"A"` }, `]}`),
		"128-deep chains":             fill(`{"method":"status","x":[`, func(int) string { return strings.Repeat("[", 127) + strings.Repeat("]", 127) }, `]}`),
		"baseline: [0,0,...]":         fill(`{"method":"status","x":[`, func(int) string { return "0" }, `]}`),
	}
}

// CloseRuns with more runs than closeRunsAtOnce and a context that ends while closes are in flight: the loop appends
// the runs it never started to failures without the lock while the in-flight closes append theirs under it.
func TestCloseRunsCountsEveryRunItCouldNotClose(t *testing.T) {
	s := New(func(ctx context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { _, _ = bufio.NewReader(b).ReadBytes('\n'); <-ctx.Done(); b.Close() }() // never answers
		return a, nil
	}, "box-run", "")
	for i := 0; i < 64; i++ {
		s.runs[fmt.Sprintf("r%02d", i)] = runEntry{token: "t"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if errs := s.CloseRuns(ctx); len(errs) != 64 {
		t.Fatalf("%d failures for 64 runs that never closed", len(errs))
	}
}

// L7: the rebuilt register_run is one strict object of method, request_id and agent only, the agent's bytes as sent,
// never longer than the frame they came in.
func FuzzRegisterFrame(f *testing.F) {
	for _, s := range []string{
		`{"method":"register_run","request_id":"r","agent":{"name":"x"}}`,
		`{"agent":{"name":"x","box":{"id":"b"}},"method":"register_run","request_id":"r","run_id":"y"}`,
		`{"method":"register_run","request_id":"r\",\"parent\":\"x","agent":"a\",\"box\":{}"}`,
		`{"method":"register_run","request_id":1e5,"agent":[{"a":1}],"x":{"parent":1}}`,
		`{ "method" : "register_run" , "agent" : { "name" : "x" } }`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		in := []byte(s)
		fr, err := Decode(in)
		if err != nil || fr.Str("method") != "register_run" {
			return
		}
		out := registerFrame(fr)
		if len(out) > len(in) {
			t.Fatalf("rebuilt %d bytes from %d: %q", len(out), len(in), out)
		}
		g, err := parseFrame(out, frameFields)
		all, rerr := strictReference(out) // every name the rebuilt frame has
		if err != nil || rerr != nil {
			t.Fatalf("rebuilt frame %q is not strict JSON: %v %v", out, err, rerr)
		}
		for k := range all {
			if k != "method" && k != "request_id" && k != "agent" {
				t.Fatalf("rebuilt frame %q carries %q", out, k)
			}
		}
		if g.Str("method") != "register_run" || !bytes.Equal(g.Raw("agent"), fr.Raw("agent")) || !bytes.Equal(g.Raw("request_id"), fr.Raw("request_id")) {
			t.Fatalf("rebuilt %q from %q", out, in)
		}
	})
}

// The byte budget and the run cap never free up (the run cap only as a registration in flight ends), but they sent
// retry_after_ms: 1000, so Tracekit's hook client waited them out for about 30 s on every call before blocking it.
func TestSpentLifetimeLimitsSendNoRetry(t *testing.T) {
	s := New(nil, "box-run", "")
	s.runs["owned"] = runEntry{token: "t"}
	s.bytes = ByteBudget
	if r := s.check("decide", fieldsOf(t, `{"run_id":"owned"}`), []byte(`{}`)); r == nil || r.kind != RefusedByteBudget || r.retryMS != 0 {
		t.Fatalf("spent byte budget: %+v", r)
	}
	s.bytes = 0
	for i := 0; i < MaxRuns; i++ {
		s.runs[fmt.Sprintf("r%d", i)] = runEntry{closed: true}
	}
	if r := s.check("register_run", fieldsOf(t, `{}`), nil); r == nil || r.kind != RefusedRunCap || r.retryMS != 0 {
		t.Fatalf("run cap, nothing in flight: %+v", r)
	}
	delete(s.runs, "r0")
	s.reservations = 1 // a registration in flight may yet fail and free its place
	if r := s.check("register_run", fieldsOf(t, `{}`), nil); r == nil || r.kind != RefusedRunCap || r.retryMS == 0 {
		t.Fatalf("run cap, a registration in flight: %+v", r)
	}
}
