// Package vmm runs micro-VMs. The contract (this file) is fixed by the lead; the Firecracker implementation lives in
// firecracker.go and friends (agent A). Tests above this package use vmmfake.
package vmm

import (
	"context"
	"net"
)

// Spec describes one micro-VM.
type Spec struct {
	ID         string  // box id; also passed on the kernel command line as tkbox.id=<ID>
	KernelPath string  // uncompressed vmlinux (Firecracker CI kernel)
	KernelArgs string  // extra kernel args appended to the implementation's defaults
	RootfsPath string  // ext4, attached read-only as /dev/vda and used as root
	Drives     []Drive // attached in order after the rootfs: /dev/vdb, /dev/vdc, ...
	VCPUs      int
	MemoryMiB  int
	// StateDir holds this VM's runtime files: fc.sock (API), vsock.sock (vsock UDS) and console.log. It exists and is
	// private (0700) before Start; the implementation creates nothing outside it.
	StateDir string
	GuestCID uint32 // guest vsock CID, >= 3, unique per running VM
	// MaxConsoleBytes caps console.log; output past it is dropped (0: 8 MiB).
	MaxConsoleBytes int64
}

// Drive is an extra block device.
type Drive struct {
	ID       string // "workspace_base", "workspace_upper"
	Path     string
	ReadOnly bool
}

// Machine is one micro-VM. All methods are safe for concurrent use.
type Machine interface {
	ID() string
	// Listen returns a listener for guest→host vsock connections to port (Firecracker forwards them to the UDS
	// "<vsock.sock>_<port>"). Call it before Start for ports the guest dials at boot.
	Listen(port uint32) (net.Listener, error)
	// Start launches the VMM process, configures the machine and boots it. It returns once the guest is booting;
	// readiness is the caller's concern (ping the agent).
	Start(ctx context.Context) error
	// Dial opens a host→guest vsock connection to port (the "CONNECT <port>\n" / "OK <n>\n" handshake is done).
	Dial(ctx context.Context, port uint32) (net.Conn, error)
	Pause(ctx context.Context) error
	Resume(ctx context.Context) error
	// Shutdown asks the guest to stop (Ctrl-Alt-Del on x86_64; on aarch64 the caller should use the agent's shutdown
	// op first) and waits up to ctx for the VMM to exit, then kills it.
	Shutdown(ctx context.Context) error
	// Kill ends the VMM process at once (SIGKILL). Idempotent.
	Kill() error
	// Done is closed when the VMM process has exited and its resources are released.
	Done() <-chan struct{}
	// Err is why the VMM exited (nil for a clean exit), valid after Done is closed.
	Err() error
	PID() int
	ConsolePath() string
}

// Launcher creates machines. The v0 implementation runs Firecracker directly; a jailer-based Launcher can replace it
// without touching callers.
type Launcher interface {
	New(spec Spec) (Machine, error)
	// Check reports whether this host can run VMs (KVM usable, binaries present), with an actionable error if not.
	Check() error
}
