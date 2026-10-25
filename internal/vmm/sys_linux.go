//go:build linux

package vmm

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxUnixPath is the longest unix socket path bind/connect accept (sun_path is 108 bytes with the NUL).
const maxUnixPath = 107

// sysProcAttr puts the VMM in its own process group (a terminal's Ctrl-C reaches the daemon, which decides) and
// kills it if the daemon dies: nothing would record a VM that outlived it. Pdeathsig follows the forking thread;
// Start runs on an ordinary goroutine and Go does not retire such threads, so it lasts as long as the daemon.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

const kvmGetAPIVersion = 0xAE00 // _IO(KVMIO, 0x00)

func checkKVM() error {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR|syscall.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return errors.New("vmm: /dev/kvm does not exist: run Box on bare metal or in a VM with nested " +
			"virtualization, and load KVM (sudo modprobe kvm_intel, kvm_amd, or use a kernel with KVM on arm64)")
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("vmm: cannot open /dev/kvm read-write as uid %d: add the user to the kvm group "+
			"(sudo usermod -aG kvm $USER, then log in again) or grant access with sudo setfacl -m u:$USER:rw /dev/kvm",
			os.Getuid())
	case err != nil:
		return fmt.Errorf("vmm: open /dev/kvm: %w", err)
	}
	defer f.Close()
	v, err := unix.IoctlRetInt(int(f.Fd()), kvmGetAPIVersion)
	if err != nil {
		return fmt.Errorf("vmm: /dev/kvm does not answer KVM_GET_API_VERSION (%v): KVM is not usable on this host", err)
	}
	if v != 12 {
		return fmt.Errorf("vmm: /dev/kvm reports KVM API version %d, Firecracker needs 12", v)
	}
	return nil
}
