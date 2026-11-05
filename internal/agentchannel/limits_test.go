package agentchannel

import (
	"bufio"
	"context"
	"encoding/json"
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
	_, c, r, done := channelHarness(t, f)
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
	for _, name := range []string{"tkbox", "TKBOX", " tkbox-agent", `tkbox`} {
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
// to 16 such frames per box. It now keeps each open object's names and the top-level fields only.
func TestDecodeCost(t *testing.T) {
	for _, unit := range []string{"[],", "{},", "0,", `{"a":1},`, `"s",`} {
		frame := decodeCostFrame(unit)
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

// The proxy's idle timeout used to be 300 s, past the signer's own 30 s, so a guest idle between the two sent its next
// frame into a signer connection the signer had already dropped.
func TestIdleTimeoutIsUnderTheSigners(t *testing.T) {
	const signerIdle = 30 * time.Second // Tracekit's signer drops a connection idle this long
	if IdleTimeout >= signerIdle {
		t.Fatalf("IdleTimeout %s, want under the signer's %s", IdleTimeout, signerIdle)
	}
}
