//go:build linux

package guest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// Paths the guest owns. /run is a tmpfs, so none of this reaches a disk.
const (
	wsBaseDir  = "/run/tkbox/ws/base" // workspace base ext4, read-only
	wsRWDir    = "/run/tkbox/ws/rw"   // workspace upper ext4: upper/ and work/
	stageDir   = "/tmp"               // on the read-only root: a tmpfs for the root overlay's upper/work while switching
	oldRootDir = ".tkbox-oldroot"
)

// shutdownGrace is how long processes get between SIGTERM and SIGKILL at shutdown.
const shutdownGrace = 3 * time.Second

var console = os.Stderr

func logf(format string, args ...any) {
	fmt.Fprintf(console, "tkbox-guest: "+format+"\n", args...)
}

// Main is PID 1. It never returns: a fatal error is printed to the console and the VM is stopped.
func Main(version string) {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "tkbox-guest is the VM's init: boot it with init=/sbin/tkbox-guest")
		os.Exit(2)
	}
	// Ctrl-Alt-Del (the host's shutdown on x86_64) arrives as SIGINT instead of an immediate reboot without sync
	unix.Reboot(unix.LINUX_REBOOT_CMD_CAD_OFF)
	if err := earlyMounts(); err != nil {
		fatal("mounts: %v", err)
	}
	openConsole()
	logf("starting %s", version)
	if err := overlayRoot(); err != nil {
		fatal("overlay root: %v", err)
	}
	if err := loopbackUp(); err != nil {
		logf("loopback: %v", err) // 127.0.0.1 is needed for the proxy; the boot continues so the host sees why
	}
	cmdline, _ := os.ReadFile("/proc/cmdline")
	boxID := CmdlineValue(string(cmdline), proto.CmdlineBoxID)
	unix.Sethostname([]byte(hostnameFor(boxID, "")))

	g := &guestVM{reaper: NewReaper()}
	g.srv = NewServer(boxID, g.reaper)
	g.srv.Logf = logf
	g.srv.OnShutdown = g.shutdown
	l, err := ListenVsock(proto.PortAgent)
	if err != nil {
		fatal("agent rpc: %v", err)
	}
	go g.srv.Serve(l)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigs
		logf("%v: shutting down", s)
		g.shutdown()
	}()

	cfg, err := FetchBootConfig(context.Background(), func(ctx context.Context) (net.Conn, error) {
		return DialVsock(ctx, unix.VMADDR_CID_HOST, proto.PortConfig)
	}, bootConfigWait)
	if err != nil {
		failClosed("boot config: %v", err)
	}
	if err := CheckBootConfig(cfg, boxID); err != nil {
		failClosed("boot config: %v", err)
	}
	ws, err := g.apply(cfg)
	if err != nil {
		failClosed("apply boot config: %v", err)
	}
	g.srv.SetReady(*cfg, ws)
	logf("ready (box %s)", cfg.BoxID)
	select {}
}

type guestVM struct {
	srv    *Server
	reaper *Reaper
	once   sync.Once
	ws     *proto.WorkspaceMount
}

func hostnameFor(boxID, configured string) string {
	switch {
	case configured != "":
		return configured
	case boxID != "":
		return "tkbox-" + boxID
	}
	return "tkbox"
}

// apply makes the boot config real: clock, hostname, CA bundle, workspace, egress forwarder.
func (g *guestVM) apply(cfg *proto.BootConfig) (*Workspace, error) {
	if cfg.UnixNano > 0 {
		host := time.Unix(0, cfg.UnixNano)
		if d := time.Since(host); d > 2*time.Second || d < -2*time.Second {
			tv := unix.NsecToTimeval(cfg.UnixNano)
			if err := unix.Settimeofday(&tv); err != nil {
				return nil, fmt.Errorf("set clock: %w", err)
			}
		}
	}
	name := hostnameFor(cfg.BoxID, cfg.Hostname)
	if err := unix.Sethostname([]byte(name)); err != nil {
		return nil, fmt.Errorf("hostname: %w", err)
	}
	os.WriteFile("/etc/hostname", []byte(name+"\n"), 0o644)
	if err := WriteHosts("/etc/hosts", name); err != nil {
		logf("/etc/hosts: %v", err)
	}
	if err := InstallCA(cfg.CACertPEM, cfg.CABundlePath, systemCABundles); err != nil {
		return nil, fmt.Errorf("CA bundle: %w", err)
	}
	var ws *Workspace
	if cfg.Workspace != nil {
		if err := mountWorkspace(cfg.Workspace); err != nil {
			return nil, fmt.Errorf("workspace: %w", err)
		}
		g.ws = cfg.Workspace
		ws = &Workspace{
			Path:  cfg.Workspace.Path,
			Upper: &DirTree{Root: filepath.Join(wsRWDir, "upper"), Overlay: true},
			Base:  &DirTree{Root: wsBaseDir},
		}
	}
	l, err := net.Listen("tcp", cfg.ProxyListen)
	if err != nil {
		return nil, fmt.Errorf("egress forwarder: %w", err)
	}
	fw := &Forwarder{Logf: logf, Dial: func(ctx context.Context) (net.Conn, error) {
		return DialVsock(ctx, unix.VMADDR_CID_HOST, proto.PortEgress)
	}}
	go fw.Serve(l)
	return ws, nil
}

func earlyMounts() error {
	type m struct {
		src, dst, fs string
		flags        uintptr
		data         string
	}
	for _, x := range []m{
		{"proc", "/proc", "proc", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"sysfs", "/sys", "sysfs", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID, "mode=0755"},
	} {
		if err := unix.Mount(x.src, x.dst, x.fs, x.flags, x.data); err != nil && !(err == unix.EBUSY && x.dst == "/dev") {
			return fmt.Errorf("mount %s on %s: %w", x.fs, x.dst, err)
		}
	}
	for _, d := range []string{"/dev/pts", "/dev/shm"} {
		os.MkdirAll(d, 0o755)
	}
	if err := unix.Mount("devpts", "/dev/pts", "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return fmt.Errorf("mount devpts: %w", err)
	}
	if err := unix.Mount("shm", "/dev/shm", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777"); err != nil {
		return fmt.Errorf("mount /dev/shm: %w", err)
	}
	for link, target := range map[string]string{
		"/dev/fd": "/proc/self/fd", "/dev/stdin": "/proc/self/fd/0", "/dev/stdout": "/proc/self/fd/1",
		"/dev/stderr": "/proc/self/fd/2", "/dev/core": "/proc/kcore",
	} {
		os.Symlink(target, link)
	}
	if err := unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		return fmt.Errorf("mount /run: %w", err)
	}
	return nil
}

// openConsole points fds 0-2 at /dev/console (the kernel may have had no /dev/console to open before devtmpfs).
func openConsole() {
	fd, err := unix.Open("/dev/console", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	for i := 0; i <= 2; i++ {
		unix.Dup3(fd, i, 0)
	}
	if fd > 2 {
		unix.Close(fd)
	}
}

// overlayRoot makes / writable: an overlay of the read-only root (lower) and a tmpfs (upper/work), switched into with
// pivot_root. /proc, /sys, /dev and /run move along.
func overlayRoot() error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}
	if err := unix.Mount("tmpfs", stageDir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		return fmt.Errorf("mount stage tmpfs: %w", err)
	}
	upper, work, merged := stageDir+"/upper", stageDir+"/work", stageDir+"/merged"
	for _, d := range []string{upper, work, merged} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return err
		}
	}
	if err := unix.Mount("overlay", merged, "overlay", 0, fmt.Sprintf("lowerdir=/,upperdir=%s,workdir=%s", upper, work)); err != nil {
		return fmt.Errorf("mount overlay: %w (does the kernel have CONFIG_OVERLAY_FS?)", err)
	}
	for _, d := range []string{"/proc", "/sys", "/dev", "/run"} {
		if err := os.MkdirAll(merged+d, 0o755); err != nil {
			return err
		}
		if err := unix.Mount(d, merged+d, "", unix.MS_MOVE, ""); err != nil {
			return fmt.Errorf("move %s: %w", d, err)
		}
	}
	if err := os.Mkdir(merged+"/"+oldRootDir, 0o700); err != nil {
		return err
	}
	if err := unix.Chdir(merged); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", oldRootDir); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Chroot("."); err != nil {
		return err
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	// the overlay keeps its own references to the layers, so the old root and the stage tmpfs can go
	if err := unix.Unmount("/"+oldRootDir, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	os.Remove("/" + oldRootDir)
	if err := unix.Mount("tmpfs", "/tmp", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777"); err != nil {
		return fmt.Errorf("mount /tmp: %w", err)
	}
	return os.MkdirAll("/run/tkbox", 0o755)
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCGIFFLAGS: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCSIFFLAGS: %w", err)
	}
	return nil
}

// mountWorkspace mounts base (ro) and upper (rw) ext4 disks and the overlay of the two at w.Path.
func mountWorkspace(w *proto.WorkspaceMount) error {
	for _, d := range []string{wsBaseDir, wsRWDir, w.Path} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// noload: never replay a journal on the read-only base (the device is read-only too)
	if err := unix.Mount(w.BaseDevice, wsBaseDir, "ext4", unix.MS_RDONLY|unix.MS_NODEV, "noload"); err != nil {
		return fmt.Errorf("mount base %s: %w", w.BaseDevice, err)
	}
	if err := unix.Mount(w.UpperDevice, wsRWDir, "ext4", unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("mount upper %s: %w", w.UpperDevice, err)
	}
	upper, work := filepath.Join(wsRWDir, "upper"), filepath.Join(wsRWDir, "work")
	for _, d := range []string{upper, work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return MountOverlay(wsBaseDir, upper, work, w.Path)
}

// MountOverlay mounts lower+upper at target with redirect_dir and metacopy off, which diff relies on (a renamed
// directory is then copied up whole instead of redirected, and a chmod copies data too). Kernels that do not know
// the options get a plain mount; diff refuses an upper layer that uses either feature anyway.
func MountOverlay(lower, upper, work, target string) error {
	base := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
	err := unix.Mount("overlay", target, "overlay", unix.MS_NODEV, base+",redirect_dir=off,metacopy=off")
	if errors.Is(err, unix.EINVAL) {
		err = unix.Mount("overlay", target, "overlay", unix.MS_NODEV, base)
	}
	if err != nil {
		return fmt.Errorf("mount overlay on %s: %w", target, err)
	}
	return nil
}

// shutdown is the shutdown op and SIGINT/SIGTERM to PID 1: stop every process, unmount the workspace cleanly (so
// the upper ext4 the host diffs or keeps is consistent) and reboot, which makes Firecracker exit.
func (g *guestVM) shutdown() {
	g.once.Do(func() {
		unix.Kill(-1, unix.SIGTERM)
		waitNoProcesses(shutdownGrace)
		unix.Kill(-1, unix.SIGKILL)
		waitNoProcesses(time.Second)
		unix.Sync()
		if g.ws != nil {
			for _, d := range []string{g.ws.Path, wsRWDir, wsBaseDir} {
				if err := unix.Unmount(d, 0); err != nil {
					logf("unmount %s: %v", d, err)
					unix.Unmount(d, unix.MNT_DETACH)
				}
			}
		}
		unix.Sync()
		logf("stopped")
		unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
		select {}
	})
}

// waitNoProcesses waits until no process but PID 1 exists (the reaper reaps them) or d passes.
func waitNoProcesses(d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if err := unix.Kill(-1, 0); errors.Is(err, unix.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fatal stops the VM after an error init cannot recover from.
func fatal(format string, args ...any) {
	logf("FATAL: "+format, args...)
	stop()
}

// failClosed stops the VM when it cannot get or apply its boot config: a box without its config must not run.
func failClosed(format string, args ...any) {
	logf("refusing to run without a valid boot config: "+format, args...)
	stop()
}

// stop syncs and stops the VM. Firecracker exits on a guest reboot on both x86_64 and aarch64 (power-off only halts
// the CPUs on x86_64), so restart is the reliable "stop"; PID 1 must never exit, which would panic the kernel.
func stop() {
	unix.Sync()
	time.Sleep(100 * time.Millisecond) // let the console drain
	unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
	for {
		unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
		time.Sleep(time.Second)
	}
}
