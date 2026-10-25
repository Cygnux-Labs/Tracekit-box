// Package guest is the guest agent that runs as PID 1 inside the micro-VM: init (mounts, overlay root, reaping),
// boot-config fetch, the agent RPC server on vsock proto.PortAgent, exec, files, workspace diff and the egress
// forwarder.
//
// The RPC core (Server) runs over any net.Listener with any Spawner, so it is tested on macOS over unix sockets and
// net.Pipe; the Linux-only pieces (mounts, vsock, the wait4 reaper, overlay xattrs) live behind build tags.
package guest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// requestTimeout bounds how long a connection may take to send its request frame.
const requestTimeout = 30 * time.Second

// Server answers agent RPC requests, one per connection.
type Server struct {
	BoxID   string
	Spawner Spawner
	// OnShutdown runs after the shutdown op has been answered: the VM's halt in production, a recorder in tests.
	OnShutdown func()
	// Logf reports problems the host cannot see (the VM console in production). Nil discards.
	Logf func(format string, args ...any)

	start    time.Time
	state    atomic.Pointer[state]
	execs    atomic.Int64
	shutdown sync.Once
}

// state is what the boot config made of the VM; nil until applied.
type state struct {
	cfg proto.BootConfig
	ws  *Workspace
}

// Workspace is a mounted workspace: Path is what execs see; Upper and Base are the overlay's layers that diff
// compares.
type Workspace struct {
	Path  string
	Upper Tree
	Base  Tree
}

// NewServer returns a server that answers not_ready (ping: Ready=false) until SetReady.
func NewServer(boxID string, sp Spawner) *Server {
	return &Server{BoxID: boxID, Spawner: sp, start: time.Now()}
}

// SetReady publishes the applied boot config; ws is nil when the box has no workspace.
func (s *Server) SetReady(cfg proto.BootConfig, ws *Workspace) {
	s.state.Store(&state{cfg: cfg, ws: ws})
}

// Ready reports whether SetReady has been called.
func (s *Server) Ready() bool { return s.state.Load() != nil }

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Serve accepts connections until l is closed and handles each on its own goroutine.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			s.logf("agent rpc: accept: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go s.ServeConn(c)
	}
}

// ServeConn handles one request on c and closes it.
func (s *Server) ServeConn(c net.Conn) {
	defer c.Close()
	defer func() {
		// a bug in one handler must not take PID 1 (and the kernel) down with it
		if r := recover(); r != nil {
			s.logf("agent rpc: panic: %v", r)
			sendError(c, proto.CodeInternal, "internal error")
		}
	}()
	c.SetReadDeadline(time.Now().Add(requestTimeout))
	f, err := proto.ReadFrame(c)
	if err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	if f.Type != proto.TypeJSON {
		sendError(c, proto.CodeBadRequest, "first frame must be a JSON request")
		return
	}
	var h proto.Header
	if err := json.Unmarshal(f.Payload, &h); err != nil {
		sendError(c, proto.CodeBadRequest, "malformed request")
		return
	}
	st := s.state.Load()
	if h.Op == proto.OpPing {
		s.handlePing(c, f, st)
		return
	}
	switch h.Op {
	case proto.OpExec, proto.OpReadFile, proto.OpWriteFile, proto.OpStat, proto.OpDiff, proto.OpShutdown:
	default:
		sendError(c, proto.CodeBadRequest, fmt.Sprintf("unknown op %q", h.Op))
		return
	}
	if st == nil {
		sendError(c, proto.CodeNotReady, "boot config not applied yet")
		return
	}
	switch h.Op {
	case proto.OpExec:
		s.handleExec(c, f, st)
	case proto.OpReadFile:
		s.handleReadFile(c, f)
	case proto.OpWriteFile:
		s.handleWriteFile(c, f)
	case proto.OpStat:
		s.handleStat(c, f)
	case proto.OpDiff:
		s.handleDiff(c, f, st)
	case proto.OpShutdown:
		s.handleShutdown(c, f)
	}
}

func (s *Server) handlePing(c net.Conn, f proto.Frame, st *state) {
	var req proto.PingRequest
	if err := f.Decode(&req); err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	proto.WriteJSON(c, proto.TypeJSON, proto.PingResponse{
		Version:  proto.Version,
		BoxID:    s.BoxID,
		UptimeMS: time.Since(s.start).Milliseconds(),
		Ready:    st != nil,
	})
}

func (s *Server) handleShutdown(c net.Conn, f proto.Frame) {
	var req proto.ShutdownRequest
	if err := f.Decode(&req); err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	proto.WriteJSON(c, proto.TypeExit, proto.ExitStatus{})
	c.Close()
	s.shutdown.Do(func() {
		if s.OnShutdown != nil {
			go s.OnShutdown()
		}
	})
}

// safeGo runs f on a goroutine that logs a panic instead of crashing: in PID 1 a crash panics the kernel.
func safeGo(logf func(string, ...any), f func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil && logf != nil {
				logf("panic: %v", r)
			}
		}()
		f()
	}()
}

func sendError(c net.Conn, code, msg string) {
	proto.WriteJSON(c, proto.TypeError, proto.Error{Code: code, Message: msg})
}
