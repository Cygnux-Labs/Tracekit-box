// Package egressfake has a scripted Decider and a recording Sink.
package egressfake

import (
	"context"
	"sync"

	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
)

// Decider allows hosts on the allowlist (req.OnAllowlist) unless Func is set.
type Decider struct {
	mu       sync.Mutex
	Requests []egress.Request
	Func     func(ctx context.Context, req egress.Request) (egress.Verdict, error)
}

func (d *Decider) Decide(ctx context.Context, req egress.Request) (egress.Verdict, error) {
	d.mu.Lock()
	d.Requests = append(d.Requests, req)
	f := d.Func
	d.mu.Unlock()
	if f != nil {
		return f(ctx, req)
	}
	if req.OnAllowlist {
		return egress.Verdict{Allow: true, Reason: "on the allowlist"}, nil
	}
	return egress.Verdict{Allow: false, Reason: "not on the allowlist"}, nil
}

// Sink records events.
type Sink struct {
	mu     sync.Mutex
	Events []egress.Event
}

func (s *Sink) Emit(e egress.Event) {
	s.mu.Lock()
	s.Events = append(s.Events, e)
	s.mu.Unlock()
}

// Kinds returns the kinds recorded so far.
func (s *Sink) Kinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.Events))
	for i, e := range s.Events {
		out[i] = e.Kind
	}
	return out
}
