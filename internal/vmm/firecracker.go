package vmm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// FirecrackerOptions configures the Firecracker launcher.
type FirecrackerOptions struct {
	Binary string // path to the firecracker binary; empty looks up "firecracker" in PATH
}

// TestedFirecracker is the Firecracker release this package is tested against (assets pins the same one).
const TestedFirecracker = "v1.17.0"

// Limits enforced on a Spec.
const (
	MaxVCPUs       = 32   // Firecracker's limit
	MinMemoryMiB   = 128  // below this the guest kernel and agent do not fit
	MaxDrives      = 8    // extra drives after the rootfs
	MaxBootArgsLen = 1536 // Firecracker caps the command line at 2048 and appends its own entries
)

const (
	apiStartTimeout = 5 * time.Second // firecracker launched → API socket answers
	killWait        = 5 * time.Second // SIGKILL sent → process reaped
	versionTimeout  = 5 * time.Second
)

// NewFirecracker returns a Launcher that runs Firecracker directly (no jailer in v0).
func NewFirecracker(opts FirecrackerOptions) Launcher { return &fcLauncher{bin: opts.Binary} }

type fcLauncher struct{ bin string }

func (l *fcLauncher) binary() (string, error) {
	bin := l.bin
	if bin == "" {
		bin = "firecracker"
	}
	p, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("vmm: firecracker binary %q not found or not executable: let tkbox fetch the pinned "+
			"release or point it at a Firecracker %s binary", bin, TestedFirecracker)
	}
	return p, nil
}

func (l *fcLauncher) Check() error {
	if err := checkKVM(); err != nil {
		return err
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("vmm: Firecracker runs on x86_64 and aarch64 hosts only, this is linux/%s", runtime.GOARCH)
	}
	bin, err := l.binary()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), versionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Env = []string{}
	out := &capBuffer{max: 4 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("vmm: %s --version failed (%v): reinstall Firecracker %s for this architecture; output: %q",
			bin, err, TestedFirecracker, firstLine(out.String()))
	}
	if v := firstLine(out.String()); !strings.HasPrefix(v, "Firecracker v") {
		return fmt.Errorf("vmm: %s does not look like Firecracker (--version said %q): point tkbox at a Firecracker "+
			"%s binary", bin, v, TestedFirecracker)
	}
	return nil
}

func (l *fcLauncher) New(spec Spec) (Machine, error) {
	if err := validateSpec(spec); err != nil {
		return nil, err
	}
	bin, err := l.binary()
	if err != nil {
		return nil, err
	}
	return newMachine(spec, bin, runtime.GOARCH), nil
}

func newMachine(spec Spec, bin, arch string) *machine {
	m := &machine{
		spec:      spec,
		bin:       bin,
		arch:      arch,
		sock:      filepath.Join(spec.StateDir, "fc.sock"),
		vsock:     filepath.Join(spec.StateDir, "vsock.sock"),
		console:   filepath.Join(spec.StateDir, "console.log"),
		listeners: map[uint32]*vsockListener{},
		done:      make(chan struct{}),
	}
	m.bootArgs = bootArgs(spec, arch)
	return m
}

// bootArgs is the kernel command line: our defaults, then Spec.KernelArgs (later values win in the kernel).
func bootArgs(spec Spec, arch string) string {
	// quiet: kernel messages on the emulated UART cost ~1.7 s of boot under nested virtualization; warnings, errors
	// and panics still print, and KernelArgs "loglevel=7" brings the rest back.
	args := []string{"console=ttyS0", "reboot=k", "panic=1", "quiet"}
	switch arch {
	case "amd64":
		// No PCI bus (virtio-mmio only); skip i8042 probing Firecracker's minimal controller does not need.
		args = append(args, "pci=off", "i8042.noaux", "i8042.nomux", "i8042.nopnp", "i8042.dumbkbd")
	}
	// aarch64 needs nothing extra: Firecracker appends earlycon=uart,mmio,<addr> and pci=off itself, and keep_bootcon
	// (in Firecracker's getting-started) would print every line twice once ttyS0 takes over.
	args = append(args, "root=/dev/vda", "ro", "rootfstype=ext4", "init=/sbin/tkbox-guest", "tkbox.id="+spec.ID)
	if s := strings.TrimSpace(spec.KernelArgs); s != "" {
		args = append(args, s)
	}
	return strings.Join(args, " ")
}

func validateSpec(s Spec) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("vmm: invalid spec for box %q: "+format, append([]any{s.ID}, args...)...)
	}
	if !validName(s.ID, "-") {
		return bad("id must be 1-64 characters of A-Z, a-z, 0-9 and -")
	}
	if s.GuestCID < 3 || s.GuestCID == ^uint32(0) {
		return bad("guest CID %d must be between 3 and 4294967294", s.GuestCID)
	}
	if s.VCPUs < 1 || s.VCPUs > MaxVCPUs {
		return bad("%d vCPUs: use 1 to %d", s.VCPUs, MaxVCPUs)
	}
	if s.MemoryMiB < MinMemoryMiB {
		return bad("%d MiB of memory: use at least %d", s.MemoryMiB, MinMemoryMiB)
	}
	if s.MaxConsoleBytes < 0 {
		return bad("negative console cap")
	}
	if s.KernelPath == "" || s.RootfsPath == "" {
		return bad("kernel and rootfs paths are required")
	}
	if len(s.Drives) > MaxDrives {
		return bad("%d extra drives: at most %d", len(s.Drives), MaxDrives)
	}
	seen := map[string]bool{"rootfs": true}
	for _, d := range s.Drives {
		if !validName(d.ID, "_") || seen[d.ID] {
			return bad("drive id %q must be unique, not \"rootfs\", and 1-64 characters of A-Z, a-z, 0-9 and _", d.ID)
		}
		seen[d.ID] = true
		if d.Path == "" {
			return bad("drive %q has no path", d.ID)
		}
	}
	if strings.ContainsFunc(s.KernelArgs, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return bad("kernel args contain control characters")
	}
	if n := len(bootArgs(s, runtime.GOARCH)); n > MaxBootArgsLen {
		return bad("kernel command line is %d bytes, over the %d byte cap: shorten the kernel args", n, MaxBootArgsLen)
	}
	if !filepath.IsAbs(s.StateDir) {
		return bad("state dir %q must be an absolute path", s.StateDir)
	}
	fi, err := os.Stat(s.StateDir)
	if err != nil {
		return bad("state dir: %v", err)
	}
	if !fi.IsDir() {
		return bad("state dir %s is not a directory", s.StateDir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return bad("state dir %s is mode %#o: it must be private (chmod 700 %s)", s.StateDir, fi.Mode().Perm(), s.StateDir)
	}
	if longest := filepath.Join(s.StateDir, "vsock.sock_4294967295"); len(longest) > maxUnixPath {
		return bad("state dir %s is too long for unix sockets (%d bytes, at most %d with the socket name): use a "+
			"shorter state directory or box id", s.StateDir, len(longest), maxUnixPath)
	}
	return nil
}

func validName(s, extra string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune(extra, r)) {
			return false
		}
	}
	return true
}

type mstate int

const (
	stNew      mstate = iota
	stStarting        // process may be running, not booted yet
	stRunning         // InstanceStart accepted
	stExited
)

type machine struct {
	spec     Spec
	bin      string
	arch     string
	bootArgs string
	sock     string // API
	vsock    string // vsock UDS
	console  string

	mu         sync.Mutex
	state      mstate
	paused     bool
	cmd        *exec.Cmd
	api        *apiClient
	cons       *capWriter
	consFile   *os.File
	ownSockets bool // our process created fc.sock/vsock.sock, so we remove them
	listeners  map[uint32]*vsockListener
	reason     error // why we ended the process; overrides its exit status
	err        error
	done       chan struct{}
	finishOnce sync.Once
}

func (m *machine) ID() string          { return m.spec.ID }
func (m *machine) ConsolePath() string { return m.console }
func (m *machine) Done() <-chan struct{} {
	return m.done
}

func (m *machine) Err() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

func (m *machine) PID() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == nil || m.cmd.Process == nil {
		return 0
	}
	return m.cmd.Process.Pid
}

func (m *machine) errorf(format string, args ...any) error {
	return fmt.Errorf("vmm: box %s: "+format, append([]any{m.spec.ID}, args...)...)
}

func (m *machine) Listen(port uint32) (net.Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == stExited {
		return nil, m.errorf("listen on vsock port %d: the VM has exited", port)
	}
	if m.listeners[port] != nil {
		return nil, m.errorf("vsock port %d is already listening", port)
	}
	ul, err := listenUnix(fmt.Sprintf("%s_%d", m.vsock, port))
	if err != nil {
		return nil, m.errorf("listen on vsock port %d: %v", port, err)
	}
	l := &vsockListener{UnixListener: ul}
	l.onClose = func() {
		m.mu.Lock()
		if m.listeners[port] == l {
			delete(m.listeners, port)
		}
		m.mu.Unlock()
	}
	m.listeners[port] = l
	return l, nil
}

func (m *machine) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.state != stNew {
		m.mu.Unlock()
		return m.errorf("Start called on a machine that was already started or killed")
	}
	m.state = stStarting
	m.mu.Unlock()

	if err := m.launch(); err != nil {
		m.finish(err)
		return err
	}
	go m.wait()
	if err := m.configure(ctx); err != nil {
		return m.failStart(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != stStarting {
		return m.errorf("the VM exited while starting%s", m.consoleHint())
	}
	m.state = stRunning
	return nil
}

// launch checks the inputs and starts the firecracker process.
func (m *machine) launch() error {
	files := []string{m.spec.KernelPath, m.spec.RootfsPath}
	for _, d := range m.spec.Drives {
		files = append(files, d.Path)
	}
	for _, f := range files {
		if fi, err := os.Stat(f); err != nil {
			return m.errorf("%v", err)
		} else if !fi.Mode().IsRegular() {
			return m.errorf("%s is not a regular file", f)
		}
	}
	for _, p := range []string{m.sock, m.vsock} {
		if err := clearStaleSocket(p); err != nil {
			return m.errorf("%v: is another Firecracker running for this box? stop it first", err)
		}
	}
	f, err := os.OpenFile(m.console, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return m.errorf("open console log: %v", err)
	}
	cons := newCapWriter(f, m.spec.MaxConsoleBytes)

	cmd := exec.Command(m.bin, "--api-sock", m.sock, "--id", m.spec.ID)
	cmd.Dir = m.spec.StateDir
	cmd.Env = []string{} // the daemon's environment (keys, tokens) is none of the VMM's business
	cmd.Stdout, cmd.Stderr = cons, cons
	cmd.SysProcAttr = sysProcAttr()
	cmd.WaitDelay = 2 * time.Second

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cons, m.consFile = cons, f
	if m.reason != nil { // killed before we got here
		return m.reason
	}
	if err := cmd.Start(); err != nil {
		return m.errorf("start %s: %v", m.bin, err)
	}
	m.cmd = cmd
	m.ownSockets = true
	m.api = newAPIClient(m.sock)
	return nil
}

func (m *machine) configure(ctx context.Context) error {
	if err := m.waitAPI(ctx); err != nil {
		return err
	}
	type step struct {
		path string
		body any
	}
	steps := []step{
		{"/machine-config", fcMachineConfig{VCPUCount: m.spec.VCPUs, MemSizeMiB: m.spec.MemoryMiB}},
		{"/boot-source", fcBootSource{KernelImagePath: abs(m.spec.KernelPath), BootArgs: m.bootArgs}},
		{"/drives/rootfs", fcDrive{DriveID: "rootfs", PathOnHost: abs(m.spec.RootfsPath), IsRootDevice: true, IsReadOnly: true}},
	}
	for _, d := range m.spec.Drives {
		steps = append(steps, step{"/drives/" + d.ID, fcDrive{DriveID: d.ID, PathOnHost: abs(d.Path), IsReadOnly: d.ReadOnly}})
	}
	steps = append(steps,
		step{"/vsock", fcVsock{GuestCID: m.spec.GuestCID, UDSPath: m.vsock}},
		step{"/actions", fcAction{ActionType: "InstanceStart"}},
	)
	for _, s := range steps {
		if err := m.api.put(ctx, s.path, s.body); err != nil {
			return m.errorf("configure: %v", err)
		}
	}
	return nil
}

// waitAPI polls the API socket until Firecracker answers.
func (m *machine) waitAPI(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, apiStartTimeout)
	defer cancel()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		probe, pcancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, err := m.api.do(probe, http.MethodGet, "/", nil)
		pcancel()
		if err == nil {
			return nil
		}
		select {
		case <-m.done:
			return m.errorf("firecracker exited before its API came up%s", m.consoleHint())
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return m.errorf("firecracker API did not answer within %s (%v)%s", apiStartTimeout, err, m.consoleHint())
			}
			return m.errorf("start: %v", ctx.Err())
		case <-tick.C:
		}
	}
}

// failStart kills a process that failed to configure, waits for it and returns err.
func (m *machine) failStart(err error) error {
	m.killWith(err)
	m.waitGone()
	return err
}

func (m *machine) wait() {
	werr := m.cmd.Wait()
	m.mu.Lock()
	err := m.reason
	m.mu.Unlock()
	if err == nil && werr != nil {
		err = m.errorf("firecracker exited: %v%s", werr, m.consoleHint())
	}
	m.finish(err)
}

// finish releases everything and closes done. It runs once: after the process exits, or instead of it when the
// machine never launched.
func (m *machine) finish(err error) {
	m.finishOnce.Do(func() {
		m.mu.Lock()
		m.state = stExited
		m.err = err
		ls := m.listeners
		m.listeners = map[uint32]*vsockListener{}
		own, api, f := m.ownSockets, m.api, m.consFile
		m.mu.Unlock()
		for _, l := range ls {
			l.Close() // unlinks vsock.sock_<port>
		}
		if own {
			os.Remove(m.sock)
			os.Remove(m.vsock)
		}
		if api != nil {
			api.close()
		}
		if f != nil {
			f.Close()
		}
		close(m.done)
	})
}

func (m *machine) Dial(ctx context.Context, port uint32) (net.Conn, error) {
	m.mu.Lock()
	st, paused := m.state, m.paused
	m.mu.Unlock()
	switch {
	case st == stExited:
		return nil, m.errorf("dial vsock port %d: the VM has exited", port)
	case st != stRunning:
		return nil, m.errorf("dial vsock port %d: the VM is not started", port)
	case paused:
		return nil, m.errorf("dial vsock port %d: the VM is paused; resume it first", port)
	}
	c, err := vsockDial(ctx, m.vsock, port)
	if err != nil {
		select {
		case <-m.done:
			return nil, m.errorf("dial vsock port %d: the VM has exited", port)
		default:
		}
		return nil, m.errorf("%v", err)
	}
	return c, nil
}

func (m *machine) Pause(ctx context.Context) error  { return m.setVMState(ctx, "Paused", true) }
func (m *machine) Resume(ctx context.Context) error { return m.setVMState(ctx, "Resumed", false) }

func (m *machine) setVMState(ctx context.Context, state string, paused bool) error {
	m.mu.Lock()
	st, api := m.state, m.api
	m.mu.Unlock()
	if st != stRunning {
		return m.errorf("%s: the VM is not running", strings.ToLower(state))
	}
	if err := api.patch(ctx, "/vm", fcVM{State: state}); err != nil {
		return m.errorf("%v", err)
	}
	m.mu.Lock()
	m.paused = paused
	m.mu.Unlock()
	return nil
}

func (m *machine) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	st, paused, api := m.state, m.paused, m.api
	m.mu.Unlock()
	switch st {
	case stExited:
		return nil
	case stNew:
		m.killWith(m.errorf("shut down before start"))
		return nil
	}
	if paused {
		// Resuming would let the guest run again; a paused box was stopped on purpose.
		m.killWith(m.errorf("killed while paused"))
		return m.waitGone()
	}
	if st == stRunning && m.arch == "amd64" {
		// Best effort: a failure here still ends in the kill below.
		api.put(ctx, "/actions", fcAction{ActionType: "SendCtrlAltDel"})
	}
	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
	}
	m.killWith(m.errorf("the guest did not stop before the shutdown deadline; killed"))
	return m.waitGone()
}

func (m *machine) Kill() error {
	m.killWith(m.errorf("killed"))
	return nil
}

// killWith records reason (first one wins) and sends SIGKILL; a machine that never launched finishes at once.
func (m *machine) killWith(reason error) {
	m.mu.Lock()
	switch m.state {
	case stExited:
		m.mu.Unlock()
		return
	case stNew:
		m.mu.Unlock()
		m.finish(reason)
		return
	}
	if m.reason == nil {
		m.reason = reason
	}
	cmd := m.cmd
	m.mu.Unlock()
	if cmd != nil {
		cmd.Process.Kill() // os.Process is safe after reaping (pidfd on Linux): no stray signal to a reused pid
	}
}

// waitGone waits for done after a kill.
func (m *machine) waitGone() error {
	select {
	case <-m.done:
		return nil
	case <-time.After(killWait):
		return m.errorf("firecracker (pid %d) did not exit within %s of SIGKILL", m.PID(), killWait)
	}
}

// consoleHint quotes the end of the console for error messages.
func (m *machine) consoleHint() string {
	m.mu.Lock()
	cons := m.cons
	m.mu.Unlock()
	if cons == nil {
		return ""
	}
	tail := strings.TrimSpace(cons.Tail())
	if tail == "" {
		return fmt.Sprintf(" (console log: %s)", m.console)
	}
	lines := strings.Split(tail, "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	last := strings.Join(lines, " | ")
	if len(last) > 400 {
		last = last[len(last)-400:]
	}
	return fmt.Sprintf(": console: %q (full log: %s)", last, m.console)
}

func clearStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	if c, err := net.DialTimeout("unix", path, 100*time.Millisecond); err == nil {
		c.Close()
		return fmt.Errorf("%s is in use", path)
	}
	return os.Remove(path)
}

func abs(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

// capBuffer keeps the first max bytes written and drops the rest.
type capBuffer struct {
	bytes.Buffer
	max int
}

func (b *capBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
