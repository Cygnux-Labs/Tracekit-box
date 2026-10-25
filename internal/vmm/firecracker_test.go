package vmm

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stateDir returns a short private dir (unix socket paths are capped near 104 bytes).
func stateDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "vmm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func testSpec(t *testing.T, id string) Spec {
	t.Helper()
	dir := stateDir(t)
	files := filepath.Join(dir, "files")
	os.Mkdir(files, 0o700)
	for _, f := range []string{"vmlinux", "rootfs.ext4", "upper.ext4"} {
		os.WriteFile(filepath.Join(files, f), []byte("x"), 0o600)
	}
	return Spec{
		ID: id, KernelPath: filepath.Join(files, "vmlinux"), RootfsPath: filepath.Join(files, "rootfs.ext4"),
		Drives: []Drive{{ID: "workspace_upper", Path: filepath.Join(files, "upper.ext4")}},
		VCPUs:  2, MemoryMiB: 256, StateDir: dir, GuestCID: 7, KernelArgs: "quiet",
	}
}

func fakeMachine(t *testing.T, spec Spec, arch string) *machine {
	t.Helper()
	if err := validateSpec(spec); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m := newMachine(spec, exe, arch)
	t.Cleanup(func() { m.Kill(); <-m.Done() })
	return m
}

func ctxT(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func requests(t *testing.T, dir string) []fakeReq {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(dir, "requests.log"))
	var out []fakeReq
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var r fakeReq
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("requests.log: %v", err)
		}
		if r.Path != "/" {
			out = append(out, r)
		}
	}
	return out
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestLifecycle(t *testing.T) {
	spec := testSpec(t, "fake-ok")
	m := fakeMachine(t, spec, "amd64")
	l, err := m.Listen(1026)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Listen(1026); err == nil {
		t.Fatal("second Listen on the same port succeeded")
	}
	if fi, err := os.Stat(spec.StateDir + "/vsock.sock_1026"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("listener socket: %v %v", fi.Mode(), err)
	}
	if err := m.Start(ctxT(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if m.PID() == 0 {
		t.Fatal("no pid")
	}
	if err := m.Start(ctxT(t, time.Second)); err == nil {
		t.Fatal("second Start succeeded")
	}

	// guest → host
	accepted := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			accepted <- err.Error()
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		accepted <- line
	}()
	select {
	case got := <-accepted:
		if got != "hello from fake-ok\n" {
			t.Fatalf("guest line %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no guest connection on 1026")
	}

	// host → guest
	c, err := m.Dial(ctxT(t, 5*time.Second), 1024)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("ping\n"))
	if line, _ := bufio.NewReader(c).ReadString('\n'); line != "ping\n" {
		t.Fatalf("echo %q", line)
	}
	c.Close()
	if _, err := m.Dial(ctxT(t, 5*time.Second), 1025); err == nil || !strings.Contains(err.Error(), "nothing listens") {
		t.Fatalf("dial closed port: %v", err)
	}

	if err := m.Pause(ctxT(t, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Dial(ctxT(t, time.Second), 1024); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("dial while paused: %v", err)
	}
	if err := m.Resume(ctxT(t, 5*time.Second)); err != nil {
		t.Fatal(err)
	}

	if err := m.Shutdown(ctxT(t, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.Done():
	default:
		t.Fatal("Done not closed after Shutdown")
	}
	if err := m.Err(); err != nil {
		t.Fatalf("clean shutdown: Err = %v", err)
	}
	for _, s := range []string{"fc.sock", "vsock.sock", "vsock.sock_1026"} {
		if exists(filepath.Join(spec.StateDir, s)) {
			t.Errorf("%s left behind", s)
		}
	}
	if _, err := l.Accept(); err == nil {
		t.Error("listener still open after exit")
	}
	if err := m.Kill(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Dial(ctxT(t, time.Second), 1024); err == nil {
		t.Fatal("Dial after exit succeeded")
	}
	if b, _ := os.ReadFile(m.ConsolePath()); !strings.Contains(string(b), "fake firecracker fake-ok starting") {
		t.Fatalf("console: %q", b)
	}

	var got []string
	for _, r := range requests(t, spec.StateDir) {
		got = append(got, r.Method+" "+r.Path+" "+string(r.Body))
	}
	want := []string{
		`PUT /machine-config {"vcpu_count":2,"mem_size_mib":256}`,
		`PUT /boot-source {"kernel_image_path":"` + spec.KernelPath + `","boot_args":"console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd root=/dev/vda ro rootfstype=ext4 init=/sbin/tkbox-guest tkbox.id=fake-ok quiet"}`,
		`PUT /drives/rootfs {"drive_id":"rootfs","path_on_host":"` + spec.RootfsPath + `","is_root_device":true,"is_read_only":true}`,
		`PUT /drives/workspace_upper {"drive_id":"workspace_upper","path_on_host":"` + spec.Drives[0].Path + `","is_root_device":false,"is_read_only":false}`,
		`PUT /vsock {"guest_cid":7,"uds_path":"` + spec.StateDir + `/vsock.sock"}`,
		`PUT /actions {"action_type":"InstanceStart"}`,
		`PATCH /vm {"state":"Paused"}`,
		`PATCH /vm {"state":"Resumed"}`,
		`PUT /actions {"action_type":"SendCtrlAltDel"}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestShutdownArm64KillsAfterDeadline(t *testing.T) {
	spec := testSpec(t, "fake-nocad")
	m := fakeMachine(t, spec, "arm64")
	if err := m.Start(ctxT(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := m.Shutdown(ctxT(t, 300*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 250*time.Millisecond {
		t.Fatalf("Shutdown returned after %s, before the deadline", d)
	}
	if err := m.Err(); err == nil || !strings.Contains(err.Error(), "shutdown deadline") {
		t.Fatalf("Err = %v", err)
	}
	for _, r := range requests(t, spec.StateDir) {
		if strings.Contains(string(r.Body), "SendCtrlAltDel") {
			t.Fatal("SendCtrlAltDel sent on arm64")
		}
	}
	if exists(filepath.Join(spec.StateDir, "fc.sock")) {
		t.Fatal("fc.sock left behind")
	}
}

func TestShutdownPausedKillsAtOnce(t *testing.T) {
	m := fakeMachine(t, testSpec(t, "fake-ok"), "amd64")
	if err := m.Start(ctxT(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := m.Pause(ctxT(t, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := m.Shutdown(ctxT(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("paused shutdown waited")
	}
	if err := m.Err(); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("Err = %v", err)
	}
}

func TestStartFaultMessage(t *testing.T) {
	spec := testSpec(t, "fake-badcfg")
	m := fakeMachine(t, spec, "arm64")
	err := m.Start(ctxT(t, 10*time.Second))
	if err == nil || !strings.Contains(err.Error(), "Invalid kernel path: fake") || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-m.Done():
	default:
		t.Fatal("Done not closed after a failed Start")
	}
	if m.Err() == nil || exists(filepath.Join(spec.StateDir, "fc.sock")) {
		t.Fatalf("Err = %v, fc.sock exists = %v", m.Err(), exists(filepath.Join(spec.StateDir, "fc.sock")))
	}
}

func TestStartProcessExits(t *testing.T) {
	m := fakeMachine(t, testSpec(t, "fake-exit"), "arm64")
	err := m.Start(ctxT(t, 10*time.Second))
	if err == nil || !strings.Contains(err.Error(), "exited before its API came up") ||
		!strings.Contains(err.Error(), "Failed to open the API socket") {
		t.Fatalf("err = %v", err)
	}
}

func TestCrashAfterStart(t *testing.T) {
	m := fakeMachine(t, testSpec(t, "fake-crash"), "arm64")
	if err := m.Start(ctxT(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("crash not noticed")
	}
	if err := m.Err(); err == nil || !strings.Contains(err.Error(), "exit status 3") || !strings.Contains(err.Error(), "something broke") {
		t.Fatalf("Err = %v", err)
	}
}

func TestConsoleCap(t *testing.T) {
	spec := testSpec(t, "fake-spam")
	spec.MaxConsoleBytes = 1000
	m := fakeMachine(t, spec, "arm64")
	if err := m.Start(ctxT(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	m.Kill()
	<-m.Done()
	b, _ := os.ReadFile(m.ConsolePath())
	if len(b) > 1200 || !strings.Contains(string(b), "reached the 1000 byte cap") {
		t.Fatalf("console is %d bytes: %q", len(b), b[max(0, len(b)-200):])
	}
}

func TestKillBeforeStart(t *testing.T) {
	m := fakeMachine(t, testSpec(t, "fake-ok"), "arm64")
	l, err := m.Listen(1026)
	if err != nil {
		t.Fatal(err)
	}
	m.Kill()
	m.Kill()
	select {
	case <-m.Done():
	case <-time.After(time.Second):
		t.Fatal("Done not closed")
	}
	if _, err := l.Accept(); err == nil {
		t.Fatal("listener open after Kill")
	}
	if err := m.Start(ctxT(t, time.Second)); err == nil {
		t.Fatal("Start after Kill succeeded")
	}
	if m.PID() != 0 {
		t.Fatal("pid without a process")
	}
}

func TestStaleAndLiveSockets(t *testing.T) {
	spec := testSpec(t, "fake-ok")
	sock := filepath.Join(spec.StateDir, "fc.sock")

	// stale: a socket file nothing listens on is replaced
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ul.SetUnlinkOnClose(false)
	ul.Close()
	m := fakeMachine(t, spec, "arm64")
	if err := m.Start(ctxT(t, 10*time.Second)); err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	m.Kill()
	<-m.Done()

	// live: another process answers, so Start refuses and leaves it alone
	live, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	go func() {
		for {
			c, err := live.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	m2 := fakeMachine(t, spec, "arm64")
	if err := m2.Start(ctxT(t, 10*time.Second)); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("live socket: %v", err)
	}
	if !exists(sock) {
		t.Fatal("removed a live socket")
	}
}

func TestValidateSpec(t *testing.T) {
	good := testSpec(t, "box-1")
	if err := validateSpec(good); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Spec){
		"empty id":     func(s *Spec) { s.ID = "" },
		"id charset":   func(s *Spec) { s.ID = "box_1" },
		"id slash":     func(s *Spec) { s.ID = "../x" },
		"id too long":  func(s *Spec) { s.ID = strings.Repeat("a", 65) },
		"cid 2":        func(s *Spec) { s.GuestCID = 2 },
		"cid any":      func(s *Spec) { s.GuestCID = ^uint32(0) },
		"vcpus 0":      func(s *Spec) { s.VCPUs = 0 },
		"vcpus 33":     func(s *Spec) { s.VCPUs = 33 },
		"memory":       func(s *Spec) { s.MemoryMiB = 127 },
		"no dir":       func(s *Spec) { s.StateDir = filepath.Join(s.StateDir, "missing") },
		"rel dir":      func(s *Spec) { s.StateDir = "rel" },
		"drive rootfs": func(s *Spec) { s.Drives = []Drive{{ID: "rootfs", Path: "/x"}} },
		"drive dup":    func(s *Spec) { s.Drives = []Drive{{ID: "a", Path: "/x"}, {ID: "a", Path: "/y"}} },
		"drive id":     func(s *Spec) { s.Drives = []Drive{{ID: "a/b", Path: "/x"}} },
		"drive path":   func(s *Spec) { s.Drives = []Drive{{ID: "a"}} },
		"newline arg":  func(s *Spec) { s.KernelArgs = "a\nb" },
		"long args":    func(s *Spec) { s.KernelArgs = strings.Repeat("a", MaxBootArgsLen) },
		"no kernel":    func(s *Spec) { s.KernelPath = "" },
	}
	for name, mut := range cases {
		s := good
		s.Drives = append([]Drive(nil), good.Drives...)
		mut(&s)
		if err := validateSpec(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	open := stateDir(t)
	os.Chmod(open, 0o755)
	s := good
	s.StateDir = open
	if err := validateSpec(s); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Errorf("open state dir: %v", err)
	}
	long := filepath.Join(stateDir(t), strings.Repeat("d", 100))
	os.Mkdir(long, 0o700)
	s.StateDir = long
	if err := validateSpec(s); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("long state dir: %v", err)
	}
}

func TestBootArgsArm64(t *testing.T) {
	got := bootArgs(Spec{ID: "b1", KernelArgs: " init=/bin/sh "}, "arm64")
	want := "console=ttyS0 reboot=k panic=1 keep_bootcon root=/dev/vda ro rootfstype=ext4 init=/sbin/tkbox-guest tkbox.id=b1 init=/bin/sh"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestNewFindsBinary(t *testing.T) {
	spec := testSpec(t, "box-1")
	if _, err := NewFirecracker(FirecrackerOptions{Binary: "/nonexistent/firecracker"}).New(spec); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing binary: %v", err)
	}
	exe, _ := os.Executable()
	m, err := NewFirecracker(FirecrackerOptions{Binary: exe}).New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID() != "box-1" || m.ConsolePath() != filepath.Join(spec.StateDir, "console.log") {
		t.Fatalf("%s %s", m.ID(), m.ConsolePath())
	}
	m.Kill()
}

func TestCheckVersion(t *testing.T) {
	if err := checkKVM(); err != nil {
		t.Skip(err)
	}
	exe, _ := os.Executable()
	if err := NewFirecracker(FirecrackerOptions{Binary: exe}).Check(); err != nil {
		t.Fatal(err)
	}
	if err := NewFirecracker(FirecrackerOptions{Binary: "/bin/echo"}).Check(); err == nil {
		t.Fatal("echo passed as firecracker")
	}
}
