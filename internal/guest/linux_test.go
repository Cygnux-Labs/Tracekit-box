//go:build linux

package guest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// TestOverlayDiffReal mounts a real overlay, changes it through the merged view, and checks the patch computed from
// the upper layer (real whiteout devices and opaque xattrs) rebuilds the merged tree with git apply.
func TestOverlayDiffReal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (overlay mounts, trusted xattrs): go test -c && sudo ./guest.test -test.run Overlay")
	}
	d := t.TempDir()
	base, upper, work, merged := filepath.Join(d, "base"), filepath.Join(d, "upper"), filepath.Join(d, "work"), filepath.Join(d, "merged")
	for _, p := range []string{base, upper, work, merged} {
		must(t, os.MkdirAll(p, 0o755))
	}
	writeFile(t, base, "README.md", lines(30, func(i int) string { return fmt.Sprint("readme ", i) }), 0o644)
	writeFile(t, base, "del.txt", "bye\n", 0o644)
	writeFile(t, base, "gone/a.txt", "a\n", 0o644)
	writeFile(t, base, "gone/deep/b.txt", "b\n", 0o644)
	writeFile(t, base, "opq/keep.txt", "keep\n", 0o644)
	writeFile(t, base, "opq/drop.txt", "drop\n", 0o644)
	writeFile(t, base, "opq/sub/x.txt", "x\n", 0o644)
	writeFile(t, base, "run.sh", "#!/bin/sh\n", 0o644)
	writeFile(t, base, "mv-src.txt", "moving\n", 0o644)
	writeFile(t, base, "f2d", "file\n", 0o644)
	writeFile(t, base, "d2f/x.txt", "x\n", 0o644)
	writeFile(t, base, "touched.txt", "same\n", 0o644)
	writeFile(t, base, "bin.dat", "\x00\x01bin"+randBytes(5, 5000), 0o644)
	writeLink(t, base, "link", "README.md")

	must(t, MountOverlay(base, upper, work, merged))
	defer unix.Unmount(merged, unix.MNT_DETACH)
	m := func(rel string) string { return filepath.Join(merged, rel) }
	readme, _ := os.ReadFile(m("README.md"))
	must(t, os.WriteFile(m("README.md"), []byte(strings.Replace(string(readme), "readme 10\n", "readme ten\n", 1)), 0o644))
	must(t, os.Remove(m("del.txt")))
	must(t, os.RemoveAll(m("gone")))
	must(t, os.RemoveAll(m("opq")))
	must(t, os.Mkdir(m("opq"), 0o755)) // over a whiteout: an opaque directory
	writeFile(t, merged, "opq/keep.txt", "keep\n", 0o644)
	writeFile(t, merged, "opq/new.txt", "new\n", 0o644)
	must(t, os.Chmod(m("run.sh"), 0o755))
	must(t, os.Rename(m("mv-src.txt"), m("mv-dst.txt")))
	must(t, os.Remove(m("f2d")))
	writeFile(t, merged, "f2d/inner.txt", "inner\n", 0o644)
	must(t, os.RemoveAll(m("d2f")))
	writeFile(t, merged, "d2f", "now a file\n", 0o644)
	fh, err := os.OpenFile(m("touched.txt"), os.O_WRONLY, 0) // copy-up without a change
	must(t, err)
	fh.Close()
	writeFile(t, merged, "bin.dat", "\x00\x02BIN"+randBytes(6, 5000), 0o644)
	must(t, os.Remove(m("link")))
	must(t, os.Symlink("run.sh", m("link")))
	writeFile(t, merged, "new/deep/file.txt", "deep\n", 0o644)
	writeFile(t, merged, ".git/config", "[core]\n", 0o644)
	must(t, unix.Mkfifo(m("fifo"), 0o644))

	// the test must really exercise the overlay's own markers
	whiteouts := 0
	filepath.WalkDir(upper, func(p string, de os.DirEntry, err error) error {
		if fi, err := os.Lstat(p); err == nil && isWhiteoutDevice(fi) {
			whiteouts++
		}
		return nil
	})
	if whiteouts < 3 {
		t.Fatalf("expected whiteout devices in the upper layer, found %d", whiteouts)
	}
	if a, err := overlayXattrs(filepath.Join(upper, "opq")); err != nil || !a.opaque {
		t.Fatalf("opq is not opaque in the upper layer: %+v %v", a, err)
	}

	sum, patch, err := Diff(&DirTree{Root: upper, Overlay: true}, &DirTree{Root: base}, 64<<20)
	must(t, err)
	gitApply(t, base, merged, patch)
	st := map[string]string{}
	for _, f := range sum.Files {
		st[f.Path] = f.Status
	}
	for p, s := range map[string]string{"README.md": "modified", "del.txt": "deleted", "gone/deep/b.txt": "deleted",
		"opq/drop.txt": "deleted", "opq/sub/x.txt": "deleted", "opq/new.txt": "added", "run.sh": "mode",
		"mv-src.txt": "deleted", "mv-dst.txt": "added", "f2d": "type", "d2f": "type", "bin.dat": "modified", "link": "modified"} {
		if st[p] != s {
			t.Errorf("%s: status %q, want %q", p, st[p], s)
		}
	}
	for _, p := range []string{"touched.txt", "opq/keep.txt", ".git/config", "fifo"} {
		if _, ok := st[p]; ok {
			t.Errorf("%s should not be in the diff", p)
		}
	}

	// an upper layer with a redirect (redirect_dir=on) is refused, never silently half-diffed
	must(t, os.Mkdir(filepath.Join(upper, "redir"), 0o755))
	must(t, unix.Lsetxattr(filepath.Join(upper, "redir"), "trusted.overlay.redirect", []byte("/gone"), 0))
	if _, _, err := Diff(&DirTree{Root: upper, Overlay: true}, &DirTree{Root: base}, 64<<20); !errors.Is(err, errOverlayFeature) {
		t.Fatalf("redirect: want errOverlayFeature, got %v", err)
	}
}

// rawExec runs one exec over a net.Pipe against srv, speaking frames directly.
func rawExec(t *testing.T, srv *Server, argv ...string) (string, proto.ExitStatus) {
	t.Helper()
	a, b := net.Pipe()
	go srv.ServeConn(b)
	defer a.Close()
	a.SetDeadline(time.Now().Add(20 * time.Second))
	must(t, proto.WriteJSON(a, proto.TypeJSON, proto.ExecRequest{Op: proto.OpExec, Argv: argv}))
	var out strings.Builder
	for {
		f, err := proto.ReadFrame(a)
		must(t, err)
		switch f.Type {
		case proto.TypeStdout, proto.TypeStderr:
			out.Write(f.Payload)
		case proto.TypeExit:
			var es proto.ExitStatus
			must(t, f.Decode(&es))
			return out.String(), es
		case proto.TypeError:
			t.Fatalf("exec %v: %v", argv, f.AsError())
		}
	}
}

// TestReaper runs in a child process that is a subreaper, like PID 1: orphans are reparented to it, and one wait4(-1)
// loop must reap them all and still hand every exec its own status.
func TestReaper(t *testing.T) {
	if os.Getenv("TKBOX_REAPER_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestReaper$", "-test.v")
		cmd.Env = append(os.Environ(), "TKBOX_REAPER_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("reaper child: %v\n%s", err, out)
		}
		return
	}
	must(t, unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0))
	srv := NewServer("r", NewReaper())
	srv.SetReady(proto.BootConfig{Env: []string{"PATH=/usr/bin:/bin"}}, nil)

	out, es := rawExec(t, srv, "sh", "-c", "sleep 0.3 & echo $!; exit 3")
	if es.Code != 3 {
		t.Fatalf("exit %+v", es)
	}
	orphan, _ := strconv.Atoi(strings.TrimSpace(out))
	_, es = rawExec(t, srv, "sh", "-c", "kill -9 $$")
	if es.Code != -1 || es.Signal != "SIGKILL" {
		t.Fatalf("killed: %+v", es)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, es := rawExec(t, srv, "sh", "-c", fmt.Sprintf("exit %d", i))
			if es.Code != i {
				t.Errorf("exec %d got status %+v", i, es)
			}
		}(i)
	}
	wg.Wait()
	// the orphaned sleep was reparented to us and must be reaped, not left a zombie
	deadline := time.Now().Add(3 * time.Second)
	for {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", orphan))
		if os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("orphan %d not reaped: %s", orphan, stat)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestVsockLoopback exercises the raw-fd vsock listener and dialer over the local CID, and the agent RPC on top.
func TestVsockLoopback(t *testing.T) {
	port := uint32(40000 + os.Getpid()%20000)
	l, err := ListenVsock(port)
	if err != nil {
		t.Skipf("no vsock: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	c, err := DialVsock(ctx, unix.VMADDR_CID_LOCAL, port)
	if err != nil {
		l.Close()
		t.Skipf("no vsock loopback (modprobe vsock_loopback): %v", err)
	}
	s := <-accepted
	go func() { io.Copy(s, s); s.(interface{ CloseWrite() error }).CloseWrite() }()
	c.Write([]byte("ping over vsock"))
	must(t, c.(interface{ CloseWrite() error }).CloseWrite())
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "ping over vsock" {
		t.Fatalf("echo %q %v", got, err)
	}
	c.Close()
	s.Close()

	// deadlines work through the poller
	c2, err := DialVsock(ctx, unix.VMADDR_CID_LOCAL, port)
	must(t, err)
	s2, err := l.Accept()
	must(t, err)
	c2.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := c2.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
	c2.Close()
	s2.Close()

	// the agent RPC over vsock
	srv := NewServer("vs", WaitSpawner{})
	srv.SetReady(proto.BootConfig{Env: []string{"PATH=/usr/bin:/bin"}}, nil)
	go srv.Serve(l)
	c3, err := DialVsock(ctx, unix.VMADDR_CID_LOCAL, port)
	must(t, err)
	defer c3.Close()
	must(t, proto.WriteJSON(c3, proto.TypeJSON, proto.PingRequest{Op: proto.OpPing}))
	f, err := proto.ReadFrame(c3)
	must(t, err)
	var pr proto.PingResponse
	if err := f.Decode(&pr); err != nil || !pr.Ready || pr.BoxID != "vs" {
		t.Fatalf("ping %+v %v", pr, err)
	}
	// Close unblocks a pending Accept
	must(t, l.Close())
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept after close: %v", err)
	}
}
