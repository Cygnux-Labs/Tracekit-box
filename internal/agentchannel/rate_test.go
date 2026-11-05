package agentchannel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func cpuTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// floodServer is a box's channel whose signer answers every frame it gets.
func floodServer() *Server {
	return New(func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			r := bufio.NewReader(b)
			for {
				if _, err := r.ReadBytes('\n'); err != nil {
					b.Close()
					return
				}
				if _, err := b.Write([]byte(`{"run_id":"r1","run_token":"t1"}` + "\n")); err != nil {
					return
				}
			}
		}()
		return a, nil
	}, "box-run", "")
}

// flood: one box's 16 connections, opened while the rate bucket is full, then the bucket is emptied for good and each
// connection sends frame as fast as the channel takes it for window (during runs alongside). Every frame is refused
// for rate, none reaches the signer. It returns the frames sent, the frames refused for rate and the CPU the process
// spent.
func flood(t *testing.T, s *Server, frame []byte, window time.Duration, during func()) (int64, int64, time.Duration) {
	var refused atomic.Int64
	s.OnRefusal = func(r Refusal) {
		if r.Kind == RefusedRate {
			refused.Add(int64(1 + r.Folded))
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	var conns []net.Conn
	for i := 0; i < MaxConnections; i++ {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, `{"method":"status"}`+"\n") // the connection is up: its token and this frame's are taken
		if _, err := bufio.NewReader(c).ReadBytes('\n'); err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		go io.Copy(io.Discard, c)
	}
	s.mu.Lock()
	s.frames, s.last = 0, time.Now().Add(time.Hour) // no token for the rest of the test
	s.mu.Unlock()
	var sent atomic.Int64
	var wg sync.WaitGroup
	cpu0 := cpuTime()
	time.AfterFunc(window, func() { // a writer the channel has stalled stops at the window's end
		for _, c := range conns {
			_ = c.SetWriteDeadline(time.Now())
		}
	})
	for _, c := range conns {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			for {
				if _, err := c.Write(frame); err != nil {
					return
				}
				sent.Add(1)
			}
		}(c)
	}
	if during != nil {
		time.Sleep(window / 3)
		during()
	}
	wg.Wait()
	cpu := cpuTime() - cpu0
	for _, c := range conns {
		c.Close()
	}
	s.Close(l)
	return sent.Load(), refused.Load(), cpu
}

// A box that floods its channel used to have every byte read at the guest's speed: about 5 cores of the daemon for
// one box. Its connections now share a byte budget (ReadRate), and a read past it waits, so the guest's writes back
// up in vsock: the box costs well under a core, and another box's register_run is answered as usual meanwhile.
func TestAFloodingBoxIsPaced(t *testing.T) {
	const window = 3 * time.Second
	frame := append([]byte(`{"method":"status","x":"`+strings.Repeat("a", MaxFrame-40)+`"}`), '\n')
	var answered time.Duration
	sent, refused, cpu := flood(t, floodServer(), frame, window, func() {
		other := floodServer()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Error(err)
			return
		}
		go other.Serve(l)
		defer other.Close(l)
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		start := time.Now()
		fmt.Fprint(c, `{"method":"register_run","request_id":"r","agent":{"name":"claude-code"}}`+"\n")
		ans, err := bufio.NewReader(c).ReadBytes('\n')
		answered = time.Since(start)
		if err != nil || !strings.Contains(string(ans), `"run_id":"r1"`) {
			t.Errorf("the other box's register_run: %q %v", ans, err)
		}
	})
	t.Logf("one box flooding 1 MiB frames for %s: %d frames sent, %d refused for rate, process CPU %.2f s (%.2f cores); "+
		"the other box's register_run answered in %s", window, sent, refused, cpu.Seconds(), cpu.Seconds()/window.Seconds(),
		answered.Round(time.Microsecond))
	if cpu > window {
		t.Errorf("one flooding box kept %.1f cores busy", cpu.Seconds()/window.Seconds())
	}
	if answered > time.Second {
		t.Errorf("the other box's register_run took %s while the first flooded", answered)
	}
}

// Every frame over a box's rate used to be read and strictly checked before the rate refused it: one box flooding wide
// 1 MiB frames got 632 through in 3 s against 7,346 cheap ones, the strict check taking 9 cores. A frame over the rate
// is now passed over unread, so a wide frame costs no more than a cheap one. (What remains is reading the guest's
// bytes off the connection, and this test's own writers.)
func TestFramesOverTheRateAreNotChecked(t *testing.T) {
	const window = 3 * time.Second
	cheap := append([]byte(`{"method":"status","x":"`+strings.Repeat("a", MaxFrame-40)+`"}`), '\n')
	fat := append(wideShapes()["top-level string keys (raw+str, kept)"], '\n')
	sent := map[string]int64{}
	for _, tc := range []struct {
		name  string
		frame []byte
	}{{"a 1 MiB string (cheap to check)", cheap}, {"1 MiB of top-level string fields", fat}} {
		unpaced := floodServer()
		unpaced.ReadRate, unpaced.ReadBurst = 1<<40, 1<<40 // the check's cost alone, not the pacing's
		n, refused, cpu := flood(t, unpaced, tc.frame, window, nil)
		sent[tc.name] = n
		t.Logf("%-34s %5d frames sent in %s, %5d refused for rate, none forwarded: process CPU %5.1f s (%d decode slots)",
			tc.name, n, window, refused, cpu.Seconds(), cap(decodeSlots))
		if refused < n*9/10 { // the rest were still in the connections' buffers when the window ended
			t.Errorf("%s: %d of %d frames refused for rate", tc.name, refused, n)
		}
	}
	if cheapN, fatN := sent["a 1 MiB string (cheap to check)"], sent["1 MiB of top-level string fields"]; 2*fatN < cheapN {
		t.Errorf("wide frames over the rate went %d to the cheap ones' %d: they are still being checked", fatN, cheapN)
	}
}

// A box's connections together read no more than ReadBurst plus ReadRate for the time elapsed, however many there are,
// and no much less: the pace bounds the box, it doesn't starve it.
func TestReadPaceBoundsTheBoxsBytes(t *testing.T) {
	s := New(nil, "box-run", "")
	s.ReadRate, s.ReadBurst = 1<<20, 256<<10
	var read atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	stop := start.Add(time.Second)
	for i := 0; i < 4; i++ {
		guest, writer := net.Pipe()
		go func() { // the guest writes as fast as it is read
			for buf := make([]byte, 64<<10); ; {
				if _, err := writer.Write(buf); err != nil {
					return
				}
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer guest.Close()
			defer writer.Close()
			c, buf := pacedConn{Conn: guest, s: s}, make([]byte, 64<<10)
			for time.Now().Before(stop) {
				n, err := c.Read(buf)
				read.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	limit := float64(s.ReadBurst) + elapsed*float64(s.ReadRate)
	t.Logf("4 connections read %d KiB in %.2f s; the pace allows %d KiB", read.Load()>>10, elapsed, int64(limit)>>10)
	if got := float64(read.Load()); got > limit || got < limit/2 {
		t.Fatalf("read %d bytes, want at most %.0f and not under half of it", read.Load(), limit)
	}
}
