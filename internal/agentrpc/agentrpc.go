// Package agentrpc is the host side of the guest agent protocol (internal/proto): one connection per request over a
// Dialer (vmm.Machine.Dial(ctx, proto.PortAgent) in production, a net.Pipe in tests).
// The Guest interface and the Dialer type are the contract (lead); client.go implements them (agent B).
package agentrpc

import (
	"context"
	"io"
	"net"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// Dialer opens a fresh connection to the guest agent.
type Dialer func(ctx context.Context) (net.Conn, error)

// ExecIO is the stdio of one exec. Nil Stdin means /dev/null (no stdin frames are sent). Signals delivers signal
// names ("SIGINT", ...) to forward while the process runs; it may be nil.
type ExecIO struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Signals <-chan string
}

// Guest is what the daemon needs from a guest agent. Errors from the guest are *proto.Error; transport failures are
// other errors. Cancelling ctx closes the connection (for exec, the guest then kills the process group).
type Guest interface {
	Ping(ctx context.Context) (proto.PingResponse, error)
	Exec(ctx context.Context, req proto.ExecRequest, stdio ExecIO) (proto.ExitStatus, error)
	ReadFile(ctx context.Context, path string, maxBytes int64, w io.Writer) (proto.FileInfo, error)
	WriteFile(ctx context.Context, path string, mode uint32, r io.Reader) error
	Stat(ctx context.Context, path string) (proto.FileInfo, error)
	// Diff writes the workspace patch (git format, with binary patches) to w and returns its summary.
	Diff(ctx context.Context, maxBytes int64, w io.Writer) (proto.DiffSummary, error)
	Shutdown(ctx context.Context) error
}
