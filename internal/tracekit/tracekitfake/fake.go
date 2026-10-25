// Package tracekitfake is an in-memory tracekit.Client and Run that records every call and decides with a script.
package tracekitfake

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// Record is one call a fake Run received.
type Record struct {
	Method string // "decide", "approval_request", "approval_wait", "consume", "abandon", "complete", "observe", "close"
	Call   tracekit.Call
	Source string
	Trust  string
	Value  any
	Status string
	Reason string
}

type Client struct {
	mu        sync.Mutex
	Runs      []*Run
	StatusErr error
	// DecideFunc decides every call of every run; default allow.
	DecideFunc func(call tracekit.Call) tracekit.Decision
	// ApprovalState is what WaitApproval returns (default "approved").
	ApprovalState string
	Exported      []string
}

func (c *Client) Where() string { return "fake" }

func (c *Client) Status(ctx context.Context) (tracekit.Status, error) {
	return tracekit.Status{RPCVersion: 19, SignerName: "fake", SignerVersion: "1.4.2", Identity: "uid:0",
		Where: "fake"}, c.StatusErr
}

func (c *Client) NewRun(ctx context.Context, agent tracekit.Agent) (tracekit.Run, error) {
	if c.StatusErr != nil {
		return nil, c.StatusErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r := &Run{client: c, id: fmt.Sprintf("run%04d", len(c.Runs)+1), Agent: agent}
	c.Runs = append(c.Runs, r)
	return r, nil
}

func (c *Client) Export(ctx context.Context, runID, bundleOut, trustOut string) error {
	c.mu.Lock()
	c.Exported = append(c.Exported, runID)
	c.mu.Unlock()
	if err := os.WriteFile(bundleOut, []byte("fake bundle "+runID), 0o644); err != nil {
		return err
	}
	return os.WriteFile(trustOut, []byte("{}"), 0o644)
}

func (c *Client) Close() error { return nil }

type Run struct {
	client    *Client
	id        string
	Agent     tracekit.Agent
	mu        sync.Mutex
	Records   []Record
	Closed    bool
	Contain   tracekit.Containment
	seq       uint64
	approvals int
}

func (r *Run) ID() string { return r.id }

func (r *Run) add(rec Record) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Records = append(r.Records, rec)
	r.seq++
	return r.seq
}

func (r *Run) Decide(ctx context.Context, call tracekit.Call) (tracekit.Decision, error) {
	seq := r.add(Record{Method: "decide", Call: call})
	d := tracekit.Decision{Decision: "allow"}
	if f := r.client.DecideFunc; f != nil {
		d = f(call)
	}
	d.DecisionID = fmt.Sprintf("d%d", seq)
	d.RunSeq = seq
	return d, nil
}

func (r *Run) RequestApproval(ctx context.Context, call tracekit.Call, reason string) (string, error) {
	r.add(Record{Method: "approval_request", Call: call, Reason: reason})
	r.mu.Lock()
	r.approvals++
	id := fmt.Sprintf("appr%d", r.approvals)
	r.mu.Unlock()
	return id, nil
}

func (r *Run) WaitApproval(ctx context.Context, approvalID string, timeout time.Duration) (string, error) {
	r.add(Record{Method: "approval_wait", Reason: approvalID})
	if s := r.client.ApprovalState; s != "" {
		return s, nil
	}
	return tracekit.ApprovalApproved, nil
}

func (r *Run) Consume(ctx context.Context, call tracekit.Call, hint string) (tracekit.Consume, error) {
	r.add(Record{Method: "consume", Call: call})
	return tracekit.Consume{OK: true, ApprovalID: hint}, nil
}

func (r *Run) Abandon(ctx context.Context, approvalID, reason string) error {
	r.add(Record{Method: "abandon", Reason: reason})
	return nil
}

func (r *Run) Complete(ctx context.Context, call tracekit.Call, d tracekit.Decision, status string, result any) error {
	r.add(Record{Method: "complete", Call: call, Status: status, Value: result})
	return nil
}

func (r *Run) Observe(ctx context.Context, source, trust string, value any) error {
	r.add(Record{Method: "observe", Source: source, Trust: trust, Value: value})
	return nil
}

func (r *Run) Contained(ctx context.Context) (tracekit.Containment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Contain, nil
}

func (r *Run) Close(ctx context.Context, reason string) error {
	r.add(Record{Method: "close", Reason: reason})
	r.mu.Lock()
	r.Closed = true
	r.mu.Unlock()
	return nil
}

// Methods returns the methods recorded so far.
func (r *Run) Methods() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.Records))
	for i, rec := range r.Records {
		out[i] = rec.Method
	}
	return out
}

var (
	_ tracekit.Client = (*Client)(nil)
	_ tracekit.Run    = (*Run)(nil)
)
