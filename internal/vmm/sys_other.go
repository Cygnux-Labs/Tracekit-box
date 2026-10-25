//go:build !linux

package vmm

import (
	"fmt"
	"runtime"
	"syscall"
)

// maxUnixPath is the longest unix socket path bind/connect accept (sun_path is 104 bytes with the NUL on the BSDs).
const maxUnixPath = 103

// sysProcAttr: Firecracker only runs on Linux; this exists so the package (and its fake-VMM tests) build elsewhere.
func sysProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

func checkKVM() error {
	return fmt.Errorf("vmm: boxes need a Linux host with KVM, this is %s/%s: on macOS run Box inside a Linux VM "+
		"with nested virtualization (see dev/lima.yaml)", runtime.GOOS, runtime.GOARCH)
}
