package tracekit

import (
	"bufio"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// slowCancelConn holds a past-deadline SetDeadline (the ctx cancel callback's) until release, as if that callback's
// goroutine were descheduled after it started.
type slowCancelConn struct {
	net.Conn
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (c *slowCancelConn) SetDeadline(t time.Time) error {
	if !t.IsZero() && t.Before(time.Unix(2, 0)) {
		c.once.Do(func() { close(c.entered) })
		<-c.release
	}
	return c.Conn.SetDeadline(t)
}

// TestCancelledCallIsNotPooled: a call whose ctx ends just as its answer arrives must not return its connection to
// the pool, where the late cancel callback would set a 1970 deadline under an unrelated call.
func TestCancelledCallIsNotPooled(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	sc := &slowCancelConn{Conn: a, entered: make(chan struct{}), release: make(chan struct{})}
	defer close(sc.release)
	tr := &transport{where: "unused", timeout: 5 * time.Second}
	tr.idle = []*conn{{nc: sc, r: bufio.NewReader(sc), used: time.Now()}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if _, err := bufio.NewReader(b).ReadBytes('\n'); err != nil {
			return
		}
		cancel()     // the call's ctx ends just as the answer comes
		<-sc.entered // its callback has started (and is held)
		b.Write([]byte(`{"ok":true}` + "\n"))
	}()
	m, err := tr.send(ctx, "decide", []byte(`{"method":"decide"}`), false, 0)
	if err != nil || m["ok"] != true {
		t.Fatalf("send: %v %v", m, err)
	}
	tr.mu.Lock()
	n := len(tr.idle)
	tr.mu.Unlock()
	if n != 0 {
		t.Fatal("a connection whose cancel callback is running went back to the pool")
	}
}
