package agentrpc

import (
	"context"
	"errors"
	"io"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// Client implements Guest over a Dialer.
// STUB: agent B replaces this file.
type Client struct{ Dial Dialer }

// New returns a Guest that dials d for every request.
func New(d Dialer) *Client { return &Client{Dial: d} }

var errStub = errors.New("agentrpc: not implemented")

func (c *Client) Ping(ctx context.Context) (proto.PingResponse, error) {
	return proto.PingResponse{}, errStub
}
func (c *Client) Exec(ctx context.Context, req proto.ExecRequest, stdio ExecIO) (proto.ExitStatus, error) {
	return proto.ExitStatus{}, errStub
}
func (c *Client) ReadFile(ctx context.Context, path string, maxBytes int64, w io.Writer) (proto.FileInfo, error) {
	return proto.FileInfo{}, errStub
}
func (c *Client) WriteFile(ctx context.Context, path string, mode uint32, r io.Reader) error {
	return errStub
}
func (c *Client) Stat(ctx context.Context, path string) (proto.FileInfo, error) {
	return proto.FileInfo{}, errStub
}
func (c *Client) Diff(ctx context.Context, maxBytes int64, w io.Writer) (proto.DiffSummary, error) {
	return proto.DiffSummary{}, errStub
}
func (c *Client) Shutdown(ctx context.Context) error { return errStub }

var _ Guest = (*Client)(nil)
