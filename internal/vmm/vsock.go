package vmm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	vsockHandshakeTimeout = 10 * time.Second // when ctx has no earlier deadline
	vsockMaxReplyLine     = 64               // "OK <u32>\n" is at most 14 bytes
)

// vsockDial connects to Firecracker's vsock UDS at path and asks for guest port. The returned conn first serves any
// bytes Firecracker sent after the "OK <n>\n" line.
func vsockDial(ctx context.Context, path string, port uint32) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, vsockHandshakeTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("vsock port %d: %w", port, err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	dl, _ := ctx.Deadline()
	conn.SetDeadline(dl)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) }) // unblock on cancel
	defer stop()

	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		return nil, fmt.Errorf("vsock port %d: send CONNECT: %w", port, ctxErr(ctx, err))
	}
	br := bufio.NewReaderSize(conn, vsockMaxReplyLine) // the minimum bufio size is 16; 64 bounds the line
	line, err := br.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return nil, fmt.Errorf("vsock port %d: handshake reply longer than %d bytes", port, vsockMaxReplyLine)
	case errors.Is(err, io.EOF):
		return nil, fmt.Errorf("vsock port %d: connection closed during handshake: nothing listens on that port in "+
			"the guest yet (is the guest agent up?)", port)
	case err != nil:
		return nil, fmt.Errorf("vsock port %d: handshake: %w", port, ctxErr(ctx, err))
	}
	reply := strings.TrimSuffix(string(line), "\n")
	n, found := strings.CutPrefix(reply, "OK ")
	if !found {
		return nil, fmt.Errorf("vsock port %d: unexpected handshake reply %q", port, reply)
	}
	if _, err := strconv.ParseUint(n, 10, 32); err != nil {
		return nil, fmt.Errorf("vsock port %d: unexpected handshake reply %q", port, reply)
	}
	if !stop() {
		return nil, fmt.Errorf("vsock port %d: %w", port, ctx.Err())
	}
	conn.SetDeadline(time.Time{})
	ok = true
	if rest := br.Buffered(); rest > 0 {
		b, _ := br.Peek(rest)
		return &prefixConn{Conn: conn, prefix: append([]byte(nil), b...)}, nil
	}
	return conn, nil
}

// ctxErr reports ctx's error for an I/O error caused by it. The conn deadline is ctx's deadline, and its timer can
// fire just before ctx's own.
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return err
}

// prefixConn serves prefix before reading from Conn.
type prefixConn struct {
	net.Conn
	mu     sync.Mutex
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

// CloseWrite half-closes when the underlying conn supports it (a *net.UnixConn does).
func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("vmm: CloseWrite not supported")
}

// listenUnix binds a private unix socket at path. A stale socket file nothing answers on is replaced; a live one
// is an error.
func listenUnix(path string) (*net.UnixListener, error) {
	if err := clearStaleSocket(path); err != nil {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	// The state dir is 0700 already; this is defense in depth.
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// vsockListener is a guest→host listener owned by a machine; Close forgets it.
type vsockListener struct {
	*net.UnixListener
	once    sync.Once
	onClose func()
}

func (l *vsockListener) Close() error {
	err := l.UnixListener.Close()
	l.once.Do(l.onClose)
	return err
}
