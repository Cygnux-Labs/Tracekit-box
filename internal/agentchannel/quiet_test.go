package agentchannel

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// Refused frames keep a guest connection alive (each is guest activity) but never reach the signer, whose connection was
// then silent past its 30 s: the next frame that passed went into a connection the signer had dropped, and the agent got
// no answer. A signer connection quiet for SignerQuietLimit is now replaced before a frame goes out.
// signer, whose connection is then silent past its 30 s; the next frame that passes goes into a connection the signer
// has dropped, and the agent gets no answer.
func TestAQuietSignerConnectionIsReplaced(t *testing.T) {
	t.Parallel()
	const signerIdle = 30 * time.Second
	s := New(func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			r := bufio.NewReader(b)
			for {
				_ = b.SetReadDeadline(time.Now().Add(signerIdle)) // the signer's per-recv read timeout
				if _, err := r.ReadBytes('\n'); err != nil {
					return
				}
				_ = b.SetWriteDeadline(time.Now().Add(time.Second))
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
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	send := func(f string) (string, error) {
		fmt.Fprint(c, f+"\n")
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		ans, err := r.ReadBytes('\n')
		return strings.TrimSpace(string(ans)), err
	}
	if ans, err := send(`{"method":"hello"}`); err != nil {
		t.Fatal(ans, err)
	}
	start := time.Now()
	for _, at := range []time.Duration{8 * time.Second, 16 * time.Second, 24 * time.Second} {
		time.Sleep(time.Until(start.Add(at)))
		ans, err := send(`{"method":"approval_decide"}`) // refused by the channel, under IdleTimeout
		if err != nil || !strings.Contains(ans, "forbidden") {
			t.Fatalf("refusal at %v: %q %v", at, ans, err)
		}
	}
	time.Sleep(time.Until(start.Add(31 * time.Second)))
	ans, err := send(`{"method":"status"}`)
	t.Logf("a status 31 s after the last frame the signer saw (refusals at 8, 16, 24 s): answer %q, err %v", ans, err)
	if err != nil {
		t.Errorf("the channel forwarded into a signer connection silent for 31 s: %v", err)
	}
}
