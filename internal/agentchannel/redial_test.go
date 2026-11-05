package agentchannel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// keepQuiet sends hello on a fresh guest connection, then refused frames at 8, 16 and 24 s so the guest connection
// stays up while its signer link goes quiet; it returns once SignerQuietLimit has passed since the hello.
func keepQuiet(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	send := func(f string) string {
		fmt.Fprint(c, f+"\n")
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		ans, err := r.ReadBytes('\n')
		if err != nil {
			t.Errorf("%s: %v", f, err)
		}
		return string(ans)
	}
	send(`{"method":"hello"}`)
	start := time.Now()
	for _, at := range []time.Duration{8 * time.Second, 16 * time.Second, 24 * time.Second} {
		time.Sleep(time.Until(start.Add(at)))
		send(`{"method":"approval_decide"}`)
	}
	time.Sleep(time.Until(start.Add(SignerQuietLimit + 200*time.Millisecond)))
	return c, r
}

// A register_run that found its link quiet, when the signer could not be reached again: check() had reserved a place
// for it, but the handler marked it reserved only after the re-dial, so the failed re-dial's return never gave the
// place back. Each signer restart during a quiet link cost the box one of its MaxRuns for good.
func TestAFailedRedialReleasesItsRunReservation(t *testing.T) {
	t.Parallel()
	var dials atomic.Int32
	s := New(func(context.Context) (net.Conn, error) {
		if dials.Add(1) > 1 {
			return nil, errors.New("signer restarting")
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			r := bufio.NewReader(b)
			for {
				if _, err := r.ReadBytes('\n'); err != nil {
					return
				}
				if _, err := b.Write([]byte(`{"proto":[19,21]}` + "\n")); err != nil {
					return
				}
			}
		}()
		return a, nil
	}, "box-run", "")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go s.Serve(l)
	defer s.Close(l)
	c, r := keepQuiet(t, l.Addr().String())
	defer c.Close()
	fmt.Fprint(c, `{"method":"register_run","request_id":"r","agent":{"name":"claude-code"}}`+"\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	ans, _ := r.ReadBytes('\n')
	_, err := r.ReadBytes('\n') // the handler returns: the connection closes
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	n := s.reservations
	s.mu.Unlock()
	t.Logf("register_run on a quiet link, re-dial failing: answer %q, then %v; reservations held after the connection closed: %d",
		strings.TrimSpace(string(ans)), err, n)
	if n != 0 {
		t.Errorf("%d run reservation(s) leaked: the box's run cap shrinks by one for every failed re-dial", n)
	}
}

// 20 boxes at once, each with a quiet link that a register_run (or a status) replaces while Close runs at a jittered
// moment and the signer answers at a jittered pace: every run the signer registered is closed by CloseRuns, Close
// waits no longer than CloseReplyWait plus a dial, and -race stays quiet.
func TestRedialRacesCloseAndCloseRuns(t *testing.T) {
	t.Parallel()
	const boxes = 20
	var wg sync.WaitGroup
	for i := 0; i < boxes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var mu sync.Mutex
			registered, closed := map[string]bool{}, map[string]bool{}
			var n atomic.Int32
			s := New(func(context.Context) (net.Conn, error) {
				time.Sleep(time.Duration(rand.Intn(20)) * time.Millisecond)
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
						ans := `{"proto":[19,21]}`
						switch m["method"] {
						case "register_run":
							time.Sleep(time.Duration(rand.Intn(30)) * time.Millisecond)
							id := fmt.Sprintf("child-%d-%d", i, n.Add(1))
							mu.Lock()
							registered[id] = true
							mu.Unlock()
							ans = `{"run_id":"` + id + `","run_token":"t"}`
						case "close_run":
							mu.Lock()
							closed[m["run_id"].(string)] = true
							mu.Unlock()
							ans = `{"state":"closing","run_seq":1}`
						}
						if _, err := b.Write([]byte(ans + "\n")); err != nil {
							return
						}
					}
				}()
				return a, nil
			}, "box-run", "")
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			go s.Serve(l)
			c, _ := keepQuiet(t, l.Addr().String())
			defer c.Close()
			frame := `{"method":"register_run","request_id":"r","agent":{"name":"claude-code"}}`
			if i%4 == 3 {
				frame = `{"method":"status"}`
			}
			fmt.Fprint(c, frame+"\n")
			time.Sleep(time.Duration(rand.Intn(40)) * time.Millisecond)
			start := time.Now()
			s.Close(l)
			took := time.Since(start)
			if errs := s.CloseRuns(context.Background()); len(errs) != 0 {
				t.Errorf("box %d: %v", i, errs)
			}
			mu.Lock()
			defer mu.Unlock()
			for id := range registered {
				if !closed[id] {
					t.Errorf("box %d: the signer registered %s but stop left it open", i, id)
				}
			}
			if took > CloseReplyWait+time.Second {
				t.Errorf("box %d: Close took %v", i, took)
			}
		}(i)
	}
	wg.Wait()
}

// The re-dial ran on context.Background, so a stop that began while a quiet link was being replaced waited for the
// dial (up to connectTimeout for the dial and again for hello + channel_open), and teardown calls Close before it
// kills the VM. Dials now end when Close begins.
func TestCloseDoesNotWaitForARedial(t *testing.T) {
	t.Parallel()
	var dials atomic.Int32
	s := New(func(ctx context.Context) (net.Conn, error) {
		if dials.Add(1) > 1 {
			select { // a signer that accepts but doesn't answer channel_open within its 2+2 s
			case <-time.After(4 * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			r := bufio.NewReader(b)
			for {
				if _, err := r.ReadBytes('\n'); err != nil {
					return
				}
				if _, err := b.Write([]byte(`{"proto":[19,21]}` + "\n")); err != nil {
					return
				}
			}
		}()
		return a, nil
	}, "box-run", "")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go s.Serve(l)
	c, _ := keepQuiet(t, l.Addr().String())
	defer c.Close()
	fmt.Fprint(c, `{"method":"status"}`+"\n")
	time.Sleep(100 * time.Millisecond) // the re-dial is under way
	start := time.Now()
	s.Close(l)
	took := time.Since(start)
	t.Logf("Close during a re-dial took %v", took.Round(time.Millisecond))
	if took > CloseReplyWait {
		t.Errorf("a stop waited %v on a re-dial (CloseReplyWait %v; a kill waits for no signer)", took.Round(time.Millisecond), CloseReplyWait)
	}
}
