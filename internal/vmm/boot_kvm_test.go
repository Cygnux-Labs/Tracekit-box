//go:build kvm && linux

package vmm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/assets"
)

// Real boots: go test -tags kvm ./internal/vmm/ -run TestBoot -v (needs /dev/kvm, mkfs.ext4, network for the first
// asset download; TKBOX_TEST_CACHE overrides the cache dir).

var (
	bootOnce           sync.Once
	bootKernel, bootFC string
	bootRootfs         string
	bootErr            error
)

func bootAssets(t *testing.T) (kernel, fc, rootfs string) {
	t.Helper()
	bootOnce.Do(func() {
		cache := os.Getenv("TKBOX_TEST_CACHE")
		if cache == "" {
			home, _ := os.UserHomeDir()
			cache = filepath.Join(home, ".cache", "tkbox-test")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		ka, err := assets.Kernel(runtime.GOARCH)
		if err == nil {
			bootKernel, err = assets.Ensure(ctx, cache, ka)
		}
		if err != nil {
			bootErr = err
			return
		}
		fa, err := assets.Firecracker(runtime.GOARCH)
		if err == nil {
			bootFC, err = assets.Ensure(ctx, cache, fa)
		}
		if err != nil {
			bootErr = err
			return
		}
		bootRootfs, bootErr = buildRootfs(cache)
	})
	if bootErr != nil {
		t.Fatal(bootErr)
	}
	return bootKernel, bootFC, bootRootfs
}

// buildRootfs compiles testdata/vsockinit as /sbin/tkbox-guest into a fresh ext4.
func buildRootfs(cache string) (string, error) {
	dir := filepath.Join(cache, "rootfs-test") // rebuilt every run
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	root := filepath.Join(dir, "root")
	for _, d := range []string{"sbin", "dev", "proc"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return "", err
		}
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	build := exec.Command(goBin, "build", "-trimpath", "-ldflags=-s -w", "-o", filepath.Join(root, "sbin", "tkbox-guest"), "./testdata/vsockinit")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build init: %v\n%s", err, out)
	}
	mkfs, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		mkfs = "/usr/sbin/mkfs.ext4"
	}
	img := filepath.Join(dir, "rootfs.ext4")
	f, err := os.Create(img)
	if err != nil {
		return "", err
	}
	f.Truncate(32 << 20)
	f.Close()
	if out, err := exec.Command(mkfs, "-q", "-F", "-L", "tkboxtest", "-d", root, img).CombinedOutput(); err != nil {
		return "", fmt.Errorf("mkfs.ext4: %v\n%s", err, out)
	}
	return img, nil
}

func bootSpec(t *testing.T, id, args string) (Launcher, Spec) {
	kernel, fc, rootfs := bootAssets(t)
	l := NewFirecracker(FirecrackerOptions{Binary: fc})
	if err := l.Check(); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "tkb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(dir, "console.log"))
			t.Logf("console.log:\n%s", b)
		}
		os.RemoveAll(dir)
	})
	return l, Spec{
		ID: id, KernelPath: kernel, RootfsPath: rootfs, KernelArgs: args,
		VCPUs: 1, MemoryMiB: 256, StateDir: dir, GuestCID: uint32(1000 + os.Getpid()%50000),
	}
}

// acceptLine returns the first line of the first connection on l.
func acceptLine(l net.Listener) <-chan string {
	ch := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			ch <- "accept: " + err.Error()
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		ch <- line
	}()
	return ch
}

func echo(t *testing.T, m Machine, msg string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := m.Dial(ctx, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte(msg + "\n"))
	if line, err := bufio.NewReader(c).ReadString('\n'); line != msg+"\n" {
		t.Fatalf("echo: %q %v", line, err)
	}
}

func assertGone(t *testing.T, m Machine, spec Spec, pid int) {
	t.Helper()
	for _, s := range []string{"fc.sock", "vsock.sock", "vsock.sock_1026"} {
		if _, err := os.Lstat(filepath.Join(spec.StateDir, s)); err == nil {
			t.Errorf("%s left behind", s)
		}
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("firecracker pid %d still exists (%v)", pid, err)
	}
}

func TestBoot(t *testing.T) {
	for _, tc := range []struct{ name, args string }{{"default", ""}, {"verbose", "loglevel=7"}, {"poweroff", "tkbox.test=poweroff"}} {
		t.Run(tc.name, func(t *testing.T) {
			l, spec := bootSpec(t, "boot-"+tc.name, tc.args)
			m, err := l.New(spec)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Kill()
			ln, err := m.Listen(1026)
			if err != nil {
				t.Fatal(err)
			}
			got := acceptLine(ln)

			t0 := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := m.Start(ctx); err != nil {
				t.Fatal(err)
			}
			started := time.Since(t0)
			pid := m.PID()
			select {
			case line := <-got:
				if line != "hello from guest boot-"+tc.name+"\n" {
					t.Fatalf("guest line %q", line)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("no guest connection on vsock 1026")
			}
			guestUp := time.Since(t0)
			echo(t, m, "echo over vsock")

			select {
			case <-m.Done():
			case <-time.After(15 * time.Second):
				t.Fatal("VM did not exit after the guest rebooted")
			}
			total := time.Since(t0)
			if err := m.Err(); err != nil {
				t.Fatalf("guest reboot: Err = %v", err)
			}
			console, _ := os.ReadFile(m.ConsolePath())
			for _, want := range []string{"TKBOX-TEST-INIT-OK", "tkbox.id=boot-" + tc.name, "TKBOX-TEST-REBOOT"} {
				if !strings.Contains(string(console), want) {
					t.Errorf("console lacks %q", want)
				}
			}
			assertGone(t, m, spec, pid)
			if os.Getenv("TKBOX_TEST_CONSOLE") != "" {
				t.Logf("console.log:\n%s", console)
			}
			t.Logf("%s/%s: Start returned in %s, guest dialled the host after %s, VM gone after %s; console %d bytes",
				runtime.GOARCH, tc.name, started.Round(time.Millisecond), guestUp.Round(time.Millisecond),
				total.Round(time.Millisecond), len(console))
		})
	}
}

func TestBootShutdown(t *testing.T) {
	l, spec := bootSpec(t, "boot-stay", "tkbox.test=stay")
	m, err := l.New(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Kill()
	ln, err := m.Listen(1026)
	if err != nil {
		t.Fatal(err)
	}
	got := acceptLine(ln)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	pid := m.PID()
	if line := <-got; !strings.HasPrefix(line, "hello from guest") {
		t.Fatalf("guest line %q", line)
	}
	echo(t, m, "one")
	if err := m.Pause(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	echo(t, m, "two after resume")

	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer scancel()
	t0 := time.Now()
	if err := m.Shutdown(sctx); err != nil {
		t.Fatal(err)
	}
	took := time.Since(t0)
	select {
	case <-m.Done():
	default:
		t.Fatal("Done open after Shutdown")
	}
	err = m.Err()
	switch runtime.GOARCH {
	case "arm64": // no Ctrl-Alt-Del: the deadline passes and the VMM is killed
		if err == nil || !strings.Contains(err.Error(), "shutdown deadline") {
			t.Fatalf("Err = %v", err)
		}
	case "amd64": // Ctrl-Alt-Del reboots the guest (the test init leaves C_A_D on)
		if err != nil {
			t.Fatalf("Err = %v", err)
		}
	}
	if err := m.Kill(); err != nil {
		t.Fatal(err)
	}
	assertGone(t, m, spec, pid)
	t.Logf("%s: Shutdown took %s, Err = %v", runtime.GOARCH, took.Round(time.Millisecond), err)
}
