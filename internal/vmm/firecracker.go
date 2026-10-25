package vmm

import "errors"

// FirecrackerOptions configures the Firecracker launcher.
type FirecrackerOptions struct {
	Binary string // path to the firecracker binary
}

// NewFirecracker returns a Launcher that runs Firecracker directly (no jailer in v0).
// STUB: agent A replaces this file.
func NewFirecracker(opts FirecrackerOptions) Launcher { return stub{} }

type stub struct{}

func (stub) New(Spec) (Machine, error) { return nil, errors.New("vmm: not implemented") }
func (stub) Check() error              { return errors.New("vmm: not implemented") }
