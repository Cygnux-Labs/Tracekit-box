package guest

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Forwarder pipes every TCP connection accepted on the proxy address to a fresh host connection (vsock CID 2
// proto.PortEgress in the VM), raw bytes both ways with half-close. It is the VM's only way out.
type Forwarder struct {
	Dial func(ctx context.Context) (net.Conn, error)
	// MaxConns caps concurrent forwarded connections so a runaway agent cannot exhaust PID 1's file descriptors
	// (and with them the agent RPC). 0: defaultMaxForwardConns.
	MaxConns int
	Logf     func(format string, args ...any)
}

// defaultMaxForwardConns is the default Forwarder.MaxConns.
const defaultMaxForwardConns = 1024

// forwardDialTimeout bounds the host dial for one forwarded connection.
const forwardDialTimeout = 10 * time.Second

// Serve accepts until l is closed.
func (f *Forwarder) Serve(l net.Listener) error {
	limit := f.MaxConns
	if limit <= 0 {
		limit = defaultMaxForwardConns
	}
	slots := make(chan struct{}, limit)
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			if f.Logf != nil {
				f.Logf("egress: %d connections open, refusing another", limit)
			}
			c.Close()
			continue
		}
		safeGo(f.Logf, func() {
			defer func() { <-slots }()
			f.forward(c)
		})
	}
}

func (f *Forwarder) forward(c net.Conn) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), forwardDialTimeout)
	h, err := f.Dial(ctx)
	cancel()
	if err != nil {
		if f.Logf != nil {
			f.Logf("egress: dial host: %v", err)
		}
		return
	}
	defer h.Close()
	pipe(c, h)
}

type closeWriter interface{ CloseWrite() error }

// pipe copies a↔b; when one direction ends, the other side's write half is shut (or the conn closed if it cannot
// half-close), and pipe returns once both directions are done.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok && err == nil {
			cw.CloseWrite()
		} else {
			// an error either way ends both directions
			dst.Close()
			src.Close()
		}
	}
	go cp(b, a)
	go cp(a, b)
	wg.Wait()
}
