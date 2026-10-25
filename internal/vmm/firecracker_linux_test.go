//go:build linux

package vmm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPdeathsigHelper is the "daemon" for TestPdeathsig: it starts a fake VMM, writes its pid and waits to be killed.
func TestPdeathsigHelper(t *testing.T) {
	dir := os.Getenv("TKBOX_PDEATHSIG_DIR")
	if dir == "" {
		t.Skip("helper process for TestPdeathsig")
	}
	for _, f := range []string{"vmlinux", "rootfs.ext4"} {
		os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600)
	}
	spec := Spec{ID: "fake-nocad", KernelPath: filepath.Join(dir, "vmlinux"), RootfsPath: filepath.Join(dir, "rootfs.ext4"),
		VCPUs: 1, MemoryMiB: 128, StateDir: dir, GuestCID: 3}
	exe, _ := os.Executable()
	m := newMachine(spec, exe, "arm64")
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "pid"), []byte(strconv.Itoa(m.PID())), 0o600)
	time.Sleep(time.Minute)
}

func TestPdeathsig(t *testing.T) {
	dir := stateDir(t)
	exe, _ := os.Executable()
	daemon := exec.Command(exe, "-test.run=^TestPdeathsigHelper$")
	daemon.Env = append(os.Environ(), "TKBOX_PDEATHSIG_DIR="+dir)
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	defer daemon.Process.Kill()
	var pid int
	for i := 0; i < 500 && pid == 0; i++ {
		b, _ := os.ReadFile(filepath.Join(dir, "pid"))
		pid, _ = strconv.Atoi(string(b))
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("helper did not start a VMM")
	}
	if !alive(pid) {
		t.Fatal("VMM not running")
	}
	daemon.Process.Kill()
	daemon.Wait()
	for i := 0; i < 300; i++ {
		if !alive(pid) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("VMM pid %d outlived its daemon", pid)
}

// alive: the process exists and is not a zombie.
func alive(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// pid (comm) state ...; comm may contain spaces, so split after the last ')'.
	s := string(b)
	rest := s[strings.LastIndexByte(s, ')')+1:]
	return !strings.HasPrefix(strings.TrimSpace(rest), "Z")
}
