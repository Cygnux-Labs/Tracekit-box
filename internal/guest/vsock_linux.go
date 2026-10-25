//go:build linux

package guest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// AF_VSOCK over raw fds: the net package cannot wrap vsock sockets (net.FileListener/FileConn reject the family), so
// sockets are created non-blocking and wrapped in *os.File, which registers them with the runtime poller and gives
// deadlines and a Close that unblocks pending calls.

// VsockAddr is a vsock endpoint.
type VsockAddr struct{ CID, Port uint32 }

func (a VsockAddr) Network() string { return "vsock" }
func (a VsockAddr) String() string  { return fmt.Sprintf("vsock:%d:%d", a.CID, a.Port) }

func vsockAddr(sa unix.Sockaddr) VsockAddr {
	if v, ok := sa.(*unix.SockaddrVM); ok {
		return VsockAddr{CID: v.CID, Port: v.Port}
	}
	return VsockAddr{}
}

type vsockConn struct {
	f             *os.File
	local, remote VsockAddr
}

func newVsockConn(fd int) *vsockConn {
	c := &vsockConn{f: os.NewFile(uintptr(fd), "vsock")}
	if sa, err := unix.Getsockname(fd); err == nil {
		c.local = vsockAddr(sa)
	}
	if sa, err := unix.Getpeername(fd); err == nil {
		c.remote = vsockAddr(sa)
	}
	return c
}

func (c *vsockConn) Read(b []byte) (int, error)         { return c.f.Read(b) }
func (c *vsockConn) Write(b []byte) (int, error)        { return c.f.Write(b) }
func (c *vsockConn) Close() error                       { return c.f.Close() }
func (c *vsockConn) LocalAddr() net.Addr                { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr               { return c.remote }
func (c *vsockConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }

// CloseWrite shuts the write half so the peer reads EOF.
func (c *vsockConn) CloseWrite() error { return c.shutdown(unix.SHUT_WR) }

func (c *vsockConn) shutdown(how int) error {
	rc, err := c.f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = unix.Shutdown(int(fd), how) }); err != nil {
		return err
	}
	return serr
}

type vsockListener struct {
	f      *os.File
	rc     syscall.RawConn
	addr   VsockAddr
	closed atomic.Bool
}

// ListenVsock listens on port for connections from any CID (the host).
func ListenVsock(port uint32) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock bind %d: %w", port, err)
	}
	if err := unix.Listen(fd, 128); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock listen %d: %w", port, err)
	}
	f := os.NewFile(uintptr(fd), "vsock-listener")
	rc, err := f.SyscallConn()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &vsockListener{f: f, rc: rc, addr: VsockAddr{CID: unix.VMADDR_CID_ANY, Port: port}}, nil
}

func (l *vsockListener) Accept() (net.Conn, error) {
	var nfd int
	var aerr error
	err := l.rc.Read(func(fd uintptr) bool {
		for {
			nfd, _, aerr = unix.Accept4(int(fd), unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
			if aerr == unix.EINTR || aerr == unix.ECONNABORTED {
				continue
			}
			return aerr != unix.EAGAIN
		}
	})
	if err != nil {
		// a RawConn on a closed file reports internal/poll's error, not os.ErrClosed
		if l.closed.Load() || errors.Is(err, os.ErrClosed) {
			return nil, net.ErrClosed
		}
		return nil, err
	}
	if aerr != nil {
		return nil, fmt.Errorf("vsock accept: %w", aerr)
	}
	return newVsockConn(nfd), nil
}

func (l *vsockListener) Close() error {
	l.closed.Store(true)
	return l.f.Close()
}

func (l *vsockListener) Addr() net.Addr { return l.addr }

// DialVsock connects to cid:port, honouring ctx for the whole connect.
func DialVsock(ctx context.Context, cid, port uint32) (net.Conn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	err = unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port})
	if err != nil && err != unix.EINPROGRESS && err != unix.EINTR {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock connect %d:%d: %w", cid, port, err)
	}
	c := newVsockConn(fd)
	if err == nil {
		return c, nil
	}
	if dl, ok := ctx.Deadline(); ok {
		c.f.SetWriteDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { c.f.SetWriteDeadline(time.Unix(1, 0)) })
	defer stop()
	rc, err := c.f.SyscallConn()
	if err != nil {
		c.Close()
		return nil, err
	}
	var cerr error
	werr := rc.Write(func(fd uintptr) bool {
		// writable means the connect finished; getpeername tells success from a spurious wakeup
		if v, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR); err != nil || v != 0 {
			if err == nil {
				err = syscall.Errno(v)
			}
			cerr = err
			return true
		}
		if _, err := unix.Getpeername(int(fd)); err == nil {
			return true
		} else if err != unix.ENOTCONN {
			cerr = err
			return true
		}
		return false
	})
	if werr == nil {
		werr = cerr
	}
	if werr != nil {
		c.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("vsock connect %d:%d: %w", cid, port, werr)
	}
	c.f.SetWriteDeadline(time.Time{})
	if sa, err := unix.Getpeername(fd); err == nil {
		c.remote = vsockAddr(sa)
	}
	return c, nil
}
