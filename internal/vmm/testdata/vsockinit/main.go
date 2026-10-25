//go:build linux

// Command vsockinit is PID 1 for the vmm boot test (go test -tags kvm). It prints markers on the console, listens on
// vsock 1024, dials the host on vsock 1026 with one line, echoes one line per host connection, then reboots. With
// tkbox.test=stay on the kernel command line it keeps serving until the host stops the VM.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	fmt.Println("TKBOX-TEST-INIT-START")
	if err := unix.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		fail("mount /proc: %v", err)
	}
	b, _ := os.ReadFile("/proc/cmdline")
	cmdline := strings.TrimSpace(string(b))
	fmt.Println("TKBOX-TEST-CMDLINE", cmdline)
	id, stay := param(cmdline, "tkbox.id"), param(cmdline, "tkbox.test") == "stay"

	// Listen before telling the host we are up, so it can dial at once.
	lfd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fail("vsock socket: %v", err)
	}
	if err := unix.Bind(lfd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: 1024}); err != nil {
		fail("vsock bind 1024: %v", err)
	}
	if err := unix.Listen(lfd, 4); err != nil {
		fail("vsock listen: %v", err)
	}

	if err := hello(id); err != nil {
		fail("dial host 1026: %v", err)
	}
	fmt.Println("TKBOX-TEST-INIT-OK")

	for {
		nfd, _, err := unix.Accept(lfd)
		if err != nil {
			fail("vsock accept: %v", err)
		}
		c := os.NewFile(uintptr(nfd), "vsock")
		line, err := bufio.NewReader(c).ReadString('\n')
		if err == nil {
			c.Write([]byte(line))
		}
		c.Close()
		if !stay {
			break
		}
	}
	reboot()
}

func hello(id string) error {
	var err error
	for i := 0; i < 50; i++ {
		var fd int
		fd, err = unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: 1026})
		if err == nil {
			_, err = unix.Write(fd, []byte("hello from guest "+id+"\n"))
			unix.Close(fd)
			return err
		}
		unix.Close(fd)
		time.Sleep(20 * time.Millisecond)
	}
	return err
}

func param(cmdline, key string) string {
	v := ""
	for _, f := range strings.Fields(cmdline) {
		if k, val, ok := strings.Cut(f, "="); ok && k == key {
			v = val // the last one wins, as in the kernel
		}
	}
	return v
}

func fail(format string, args ...any) {
	fmt.Printf("TKBOX-TEST-FAIL "+format+"\n", args...)
	reboot()
}

func reboot() {
	fmt.Println("TKBOX-TEST-REBOOT")
	unix.Sync()
	unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
	select {}
}
