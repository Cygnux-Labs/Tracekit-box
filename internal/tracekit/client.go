package tracekit

import (
	"context"
	"errors"
)

// STUB: agent E replaces this file (keep these signatures).

// Dial connects to the signer, checks its hello (protocol range must hold 19) and its status. Any failure is an
// *Unavailable (or an incompatibility error naming both versions): the caller fails closed.
func Dial(ctx context.Context, opts Options) (Client, error) {
	return nil, &Unavailable{Err: errors.New("not implemented")}
}

// Gate runs the decide → (ask: approval_request, approval_wait until ctx ends) → approval_consume sequence of the
// 1.4.2 integrations (tracekit/integrations/gate.py). The caller runs the action only when Outcome.Allowed, then calls
// Run.Complete with Outcome.Decision. A signer that can't be reached refuses (fail closed); an unanswered approval is
// abandoned when ctx ends.
func Gate(ctx context.Context, r Run, call Call, hooks GateHooks) (Outcome, error) {
	return Outcome{}, errors.New("not implemented")
}
