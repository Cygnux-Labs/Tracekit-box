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

// flood: one box's 16 connections, opened while the rate bucket is full, then the bucket is emptied for good and each
// connection sends frame as fast as the channel reads it for window. Every frame is refused for rate, none reaches the
// signer. It returns the frames sent, the frames refused for rate and the CPU the process spent.
func flood(t *testing.T, frame []byte, window time.Duration) (int64, int64, time.Duration) {
	s := New(func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			r := bufio.NewReader(b)
			for {
				if _, err := r.ReadBytes('\n'); err != nil {
					b.Close()
					return
				}
				if _, err := b.Write([]byte("{}\n")); err != nil {
					return
				}
			}
		}()
		return a, nil
	}, "box-run", "")
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
	end := time.Now().Add(window)
	for _, c := range conns {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			for time.Now().Before(end) {
				if _, err := c.Write(frame); err != nil {
					return
				}
				sent.Add(1)
			}
		}(c)
	}
	wg.Wait()
	cpu := cpuTime() - cpu0
	for _, c := range conns {
		c.Close()
	}
	s.Close(l)
	return sent.Load(), refused.Load(), cpu
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
		n, refused, cpu := flood(t, tc.frame, window)
		sent[tc.name] = n
		t.Logf("%-34s %5d frames sent in %s, %5d refused for rate, none forwarded: process CPU %5.1f s (%d decode slots)",
			tc.name, n, window, refused, cpu.Seconds(), cap(decodeSlots))
		if refused < n-int64(MaxConnections) {
			t.Errorf("%s: %d of %d frames refused for rate", tc.name, refused, n)
		}
	}
	if cheapN, fatN := sent["a 1 MiB string (cheap to check)"], sent["1 MiB of top-level string fields"]; 2*fatN < cheapN {
		t.Errorf("wide frames over the rate went %d to the cheap ones' %d: they are still being checked", fatN, cheapN)
	}
}
