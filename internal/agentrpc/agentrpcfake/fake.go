// Package agentrpcfake is a scripted agentrpc.Guest for daemon tests.
package agentrpcfake

import (
	"context"
	"io"
	"strings"
	"sync"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// Guest records every call. ExecFunc, when set, runs execs; otherwise an exec echoes its argv joined by spaces to
// stdout and exits 0. Files is an in-memory filesystem for ReadFile/WriteFile/Stat. Patch and Summary answer Diff.
type Guest struct {
	mu        sync.Mutex
	Execs     []proto.ExecRequest
	ExecFunc  func(ctx context.Context, req proto.ExecRequest, stdio agentrpc.ExecIO) (proto.ExitStatus, error)
	Files     map[string][]byte
	Patch     string
	Summary   proto.DiffSummary
	PingErr   error
	Shutdowns int
}

func (g *Guest) Ping(ctx context.Context) (proto.PingResponse, error) {
	return proto.PingResponse{Version: proto.Version, Ready: true}, g.PingErr
}

func (g *Guest) Exec(ctx context.Context, req proto.ExecRequest, stdio agentrpc.ExecIO) (proto.ExitStatus, error) {
	g.mu.Lock()
	g.Execs = append(g.Execs, req)
	f := g.ExecFunc
	g.mu.Unlock()
	if f != nil {
		return f(ctx, req, stdio)
	}
	if stdio.Stdout != nil {
		io.WriteString(stdio.Stdout, strings.Join(req.Argv, " ")+"\n")
	}
	return proto.ExitStatus{Code: 0}, nil
}

func (g *Guest) ReadFile(ctx context.Context, path string, maxBytes int64, w io.Writer) (proto.FileInfo, error) {
	g.mu.Lock()
	b, ok := g.Files[path]
	g.mu.Unlock()
	if !ok {
		return proto.FileInfo{}, &proto.Error{Code: proto.CodeNotFound, Message: path}
	}
	_, err := w.Write(b)
	return proto.FileInfo{Path: path, Size: int64(len(b)), Mode: 0o644}, err
}

func (g *Guest) WriteFile(ctx context.Context, path string, mode uint32, r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.Files == nil {
		g.Files = map[string][]byte{}
	}
	g.Files[path] = b
	return nil
}

func (g *Guest) Stat(ctx context.Context, path string) (proto.FileInfo, error) {
	g.mu.Lock()
	b, ok := g.Files[path]
	g.mu.Unlock()
	if !ok {
		return proto.FileInfo{}, &proto.Error{Code: proto.CodeNotFound, Message: path}
	}
	return proto.FileInfo{Path: path, Size: int64(len(b)), Mode: 0o644}, nil
}

func (g *Guest) Diff(ctx context.Context, maxBytes int64, w io.Writer) (proto.DiffSummary, error) {
	_, err := io.WriteString(w, g.Patch)
	s := g.Summary
	s.Bytes = int64(len(g.Patch))
	return s, err
}

func (g *Guest) Shutdown(ctx context.Context) error {
	g.mu.Lock()
	g.Shutdowns++
	g.mu.Unlock()
	return nil
}

var _ agentrpc.Guest = (*Guest)(nil)
