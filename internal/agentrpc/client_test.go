//go:build unix

package agentrpc_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/guest"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// pipeDialer serves every dial with a fresh net.Pipe handled by srv.
func pipeDialer(srv *guest.Server) agentrpc.Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go srv.ServeConn(b)
		return a, nil
	}
}

type fixture struct {
	srv       *guest.Server
	c         *agentrpc.Client
	ws        string
	shutdowns chan struct{}
}

func newFixture(t *testing.T, lim proto.GuestLimits) *fixture {
	t.Helper()
	d := t.TempDir()
	base, upper := filepath.Join(d, "base"), filepath.Join(d, "upper")
	for _, p := range []string{base, upper} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	srv := guest.NewServer("box1", guest.WaitSpawner{})
	f := &fixture{srv: srv, c: agentrpc.New(pipeDialer(srv)), ws: d, shutdowns: make(chan struct{}, 1)}
	srv.OnShutdown = func() { f.shutdowns <- struct{}{} }
	srv.SetReady(proto.BootConfig{
		Version: proto.Version, BoxID: "box1",
		Env:    []string{"PATH=/usr/bin:/bin", "BOXVAR=base", "OTHER=keep"},
		Limits: lim,
	}, &guest.Workspace{Path: d, Upper: &guest.DirTree{Root: upper}, Base: &guest.DirTree{Root: base}})
	return f
}

func ctxT(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var pe *proto.Error
	if !errors.As(err, &pe) || pe.Code != code {
		t.Fatalf("want guest error %s, got %v", code, err)
	}
}

func TestNotReady(t *testing.T) {
	srv := guest.NewServer("box0", guest.WaitSpawner{})
	c := agentrpc.New(pipeDialer(srv))
	p, err := c.Ping(ctxT(t, 5*time.Second))
	if err != nil || p.Ready || p.BoxID != "box0" || p.Version != proto.Version {
		t.Fatalf("ping %+v %v", p, err)
	}
	_, err = c.Exec(ctxT(t, 5*time.Second), proto.ExecRequest{Argv: []string{"true"}}, agentrpc.ExecIO{})
	wantCode(t, err, proto.CodeNotReady)
	_, err = c.Stat(ctxT(t, 5*time.Second), "/")
	wantCode(t, err, proto.CodeNotReady)
}

func TestExecBasics(t *testing.T) {
	f := newFixture(t, proto.GuestLimits{})
	p, err := f.c.Ping(ctxT(t, 5*time.Second))
	if err != nil || !p.Ready {
		t.Fatalf("ping %+v %v", p, err)
	}
	var out, errb bytes.Buffer
	es, err := f.c.Exec(ctxT(t, 10*time.Second), proto.ExecRequest{
		Argv: []string{"sh", "-c", `echo "$BOXVAR $OTHER $REQ"; pwd; echo oops >&2; exit 3`},
		Env:  []string{"BOXVAR=override", "REQ=1"},
	}, agentrpc.ExecIO{Stdout: &out, Stderr: &errb})
	if err != nil {
		t.Fatal(err)
	}
	wd, _ := filepath.EvalSymlinks(f.ws)
	if es.Code != 3 || es.Signal != "" || out.String() != "override keep 1\n"+wd+"\n" && out.String() != "override keep 1\n"+f.ws+"\n" || errb.String() != "oops\n" {
		t.Fatalf("exit %+v stdout %q stderr %q", es, out.String(), errb.String())
	}
	_, err = f.c.Exec(ctxT(t, 5*time.Second), proto.ExecRequest{Argv: []string{"no-such-binary-xyz"}}, agentrpc.ExecIO{})
	wantCode(t, err, proto.CodeNotFound)
	_, err = f.c.Exec(ctxT(t, 5*time.Second), proto.ExecRequest{Argv: []string{"true"}, Cwd: "rel"}, agentrpc.ExecIO{})
	wantCode(t, err, proto.CodeBadRequest)
	_, err = f.c.Exec(ctxT(t, 5*time.Second), proto.ExecRequest{Argv: []string{"true"}, Env: []string{"NOEQUALS"}}, agentrpc.ExecIO{})
	wantCode(t, err, proto.CodeBadRequest)
}

func TestExecStdin(t *testing.T) {
	f := newFixture(t, proto.GuestLimits{})
	data := bytes.Repeat([]byte("0123456789abcdef"), 200000) // 3.2 MB, several frames each way
	var out bytes.Buffer
	es, err := f.c.Exec(ctxT(t, 20*time.Second), proto.ExecRequest{Argv: []string{"cat"}},
		agentrpc.ExecIO{Stdin: bytes.NewReader(data), Stdout: &out})
	if err != nil || es.Code != 0 || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("cat: %+v %v, %d bytes back", es, err, out.Len())
	}
	// the process exits while the host is still streaming stdin: late frames are dropped, never a guest crash
	for _, argv := range [][]string{{"true"}, {"head", "-c", "10"}} {
		es, err = f.c.Exec(ctxT(t, 20*time.Second), proto.ExecRequest{Argv: argv},
			agentrpc.ExecIO{Stdin: io.LimitReader(zeroReader{}, 64<<20), Stdout: io.Discard})
		if err != nil || es.Code != 0 {
			t.Fatalf("%v with unread stdin: %+v %v", argv, es, err)
		}
	}
	// without Stdin the child reads /dev/null
	out.Reset()
	es, err = f.c.Exec(ctxT(t, 5*time.Second), proto.ExecRequest{Argv: []string{"sh", "-c", "cat; echo done"}},
		agentrpc.ExecIO{Stdout: &out})
	if err != nil || es.Code != 0 || out.String() != "done\n" {
		t.Fatalf("no stdin: %+v %v %q", es, err, out.String())
	}
}

// lineWatcher closes ready when the output contains want.
type lineWatcher struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	want  string
	ready chan struct{}
	once  sync.Once
}

func (w *lineWatcher) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if strings.Contains(w.buf.String(), w.want) {
		w.once.Do(func() { close(w.ready) })
	}
	return len(p), nil
}

func (w *lineWatcher) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func TestExecSignals(t *testing.T) {
	f := newFixture(t, proto.GuestLimits{})
	sigs := make(chan string, 2)
	w := &lineWatcher{want: "ready\n", ready: make(chan struct{})}
	go func() {
		<-w.ready
		sigs <- "SIGBOGUS" // dropped by the client
		sigs <- "SIGINT"
	}()
	es, err := f.c.Exec(ctxT(t, 10*time.Second), proto.ExecRequest{
		Argv: []string{"sh", "-c", `trap 'echo got-int; exit 7' INT; echo ready; while :; do sleep 0.05; done`},
	}, agentrpc.ExecIO{Stdout: w, Signals: sigs})
	if err != nil || es.Code != 7 || !strings.Contains(w.String(), "got-int") {
		t.Fatalf("trap: %+v %v %q", es, err, w.String())
	}

	sigs2 := make(chan string, 1)
	w2 := &lineWatcher{want: "ready\n", ready: make(chan struct{})}
	go func() { <-w2.ready; sigs2 <- "SIGTERM" }()
	es, err = f.c.Exec(ctxT(t, 10*time.Second), proto.ExecRequest{Argv: []string{"sh", "-c", `echo ready; exec sleep 30`}},
		agentrpc.ExecIO{Stdout: w2, Signals: sigs2})
	if err != nil || es.Code != -1 || es.Signal != "SIGTERM" {
		t.Fatalf("term: %+v %v", es, err)
	}
}

func TestExecTimeout(t *testing.T) {
	f := newFixture(t, proto.GuestLimits{ExecTimeoutMS: 30000})
	start := time.Now()
	es, err := f.c.Exec(ctxT(t, 10*time.Second), proto.ExecRequest{Argv: []string{"sh", "-c", "sleep 30 & sleep 30"}, TimeoutMS: 300},
		agentrpc.ExecIO{})
	if err != nil || !es.TimedOut || es.Code != -1 || es.Signal != "SIGKILL" {
		t.Fatalf("timeout: %+v %v", es, err)
	}
	// the background sleep is in the group and holds the pipes: it must have been killed too, not waited for
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout took %v", time.Since(start))
	}
	// the box default applies when the request has none
	f = newFixture(t, proto.GuestLimits{ExecTimeoutMS: 200})
	es, err = f.c.Exec(ctxT(t, 10*time.Second), proto.ExecRequest{Argv: []string{"sleep", "30"}}, agentrpc.ExecIO{})
	if err != nil || !es.TimedOut {
		t.Fatalf("default timeout: %+v %v", es, err)
	}
}

func TestExecOutputCaps(t *testing.T) {
	f := newFixture(t, proto.GuestLimits{MaxOutputBytes: 1 << 20})
	var out bytes.Buffer
	es, err := f.c.Exec(ctxT(t, 20*time.Second), proto.ExecRequest{Argv: []string{"head", "-c", "5000000", "/dev/zero"}},
		agentrpc.ExecIO{Stdout: &out})
	if err != nil || es.Code != 0 || !es.Truncated || out.Len() != 1<<20 {
		t.Fatalf("guest cap: %+v %v %d", es, err, out.Len())
	}
	// the client's own cap holds even when the guest allows more
	f = newFixture(t, proto.GuestLimits{})
	f.c.MaxOutputBytes = 1000
	out.Reset()
	es, err = f.c.Exec(ctxT(t, 20*time.Second), proto.ExecRequest{Argv: []string{"head", "-c", "3000000", "/dev/zero"}},
		agentrpc.ExecIO{Stdout: &out})
	if err != nil || !es.Truncated || out.Len() != 1000 {
		t.Fatalf("client cap: %+v %v %d", es, err, out.Len())
	}
}

func TestExecCancelKillsGroup(t *testing.T) {
	f := newFixture(t, proto.GuestLimits{})
	ctx, cancel := context.WithCancel(context.Background())
	w := &lineWatcher{want: "\n", ready: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := f.c.Exec(ctx, proto.ExecRequest{Argv: []string{"sh", "-c", "sleep 30 & echo $!; wait"}}, agentrpc.ExecIO{Stdout: w})
		done <- err
	}()
	select {
	case <-w.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("no pid")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(w.String()))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("background process %d survived the cancelled exec", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestExecBusy(t *testing.T) {
	f := newFixture(t, proto.GuestLimits{MaxProcs: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &lineWatcher{want: "up\n", ready: make(chan struct{})}
	go f.c.Exec(ctx, proto.ExecRequest{Argv: []string{"sh", "-c", "echo up; sleep 30"}}, agentrpc.ExecIO{Stdout: w})
	<-w.ready
	_, err := f.c.Exec(ctxT(t, 5*time.Second), proto.ExecRequest{Argv: []string{"true"}}, agentrpc.ExecIO{})
	wantCode(t, err, proto.CodeBusy)
}

func TestFiles(t *testing.T) {
	f := newFixture(t, proto.GuestLimits{})
	ctx := ctxT(t, 10*time.Second)
	p := filepath.Join(f.ws, "new", "dir", "f.txt")
	data := bytes.Repeat([]byte("x"), 3<<20)
	if err := f.c.WriteFile(ctx, p, 0o755, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	fi, err := f.c.Stat(ctx, p)
	if err != nil || fi.Size != int64(len(data)) || fi.Mode&0o777 != 0o755 || fi.IsDir {
		t.Fatalf("stat %+v %v", fi, err)
	}
	var got bytes.Buffer
	fi, err = f.c.ReadFile(ctx, p, 0, &got)
	if err != nil || !bytes.Equal(got.Bytes(), data) || fi.Size != int64(len(data)) {
		t.Fatalf("read %+v %v %d", fi, err, got.Len())
	}
	_, err = f.c.ReadFile(ctx, p, 100, io.Discard)
	wantCode(t, err, proto.CodeTooLarge)
	_, err = f.c.ReadFile(ctx, filepath.Join(f.ws, "missing"), 0, io.Discard)
	wantCode(t, err, proto.CodeNotFound)
	_, err = f.c.ReadFile(ctx, f.ws, 0, io.Discard)
	wantCode(t, err, proto.CodeBadRequest)
	_, err = f.c.Stat(ctx, "relative/path")
	wantCode(t, err, proto.CodeBadRequest)
	wantCode(t, f.c.WriteFile(ctx, "relative", 0, strings.NewReader("x")), proto.CodeBadRequest)
	// a failing source never commits a partial file
	q := filepath.Join(f.ws, "partial.txt")
	err = f.c.WriteFile(ctx, q, 0, io.MultiReader(strings.NewReader("half"), errReader{}))
	if err == nil {
		t.Fatal("failing source: no error")
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(q); !os.IsNotExist(err) {
		t.Fatalf("partial file committed: %v", err)
	}
	ents, _ := os.ReadDir(f.ws)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tkbox-write-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("source broke") }

func TestDiffAndShutdown(t *testing.T) {
	f := newFixture(t, proto.GuestLimits{})
	ctx := ctxT(t, 10*time.Second)
	os.WriteFile(filepath.Join(f.ws, "base", "a.txt"), []byte("one\n"), 0o644)
	os.WriteFile(filepath.Join(f.ws, "upper", "a.txt"), []byte("two\n"), 0o644)
	os.WriteFile(filepath.Join(f.ws, "upper", "b.txt"), []byte("new\n"), 0o644)
	var patch bytes.Buffer
	sum, err := f.c.Diff(ctx, 0, &patch)
	if err != nil || len(sum.Files) != 2 || sum.Bytes != int64(patch.Len()) || !strings.Contains(patch.String(), "+two\n") {
		t.Fatalf("diff %+v %v\n%s", sum, err, patch.String())
	}
	_, err = f.c.Diff(ctx, 10, io.Discard)
	wantCode(t, err, proto.CodeTooLarge)

	if err := f.c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.shutdowns:
	case <-time.After(2 * time.Second):
		t.Fatal("OnShutdown not called")
	}
}

func TestUnixSocketListener(t *testing.T) {
	f := newFixture(t, proto.GuestLimits{})
	sock := filepath.Join(t.TempDir(), "agent.sock")
	if len(sock) > 100 {
		sock = filepath.Join(os.TempDir(), "tkbox-agent-"+strconv.Itoa(os.Getpid())+".sock")
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(sock)
	go f.srv.Serve(l)
	defer l.Close()
	c := agentrpc.New(func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	})
	var out bytes.Buffer
	es, err := c.Exec(ctxT(t, 10*time.Second), proto.ExecRequest{Argv: []string{"echo", "hi"}}, agentrpc.ExecIO{Stdout: &out})
	if err != nil || es.Code != 0 || out.String() != "hi\n" {
		t.Fatalf("%+v %v %q", es, err, out.String())
	}
}

// hostile returns a client whose guest runs fn after reading the request frame.
func hostile(fn func(c net.Conn, req proto.Frame)) *agentrpc.Client {
	return agentrpc.New(func(ctx context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			req, err := proto.ReadFrame(b)
			if err != nil {
				return
			}
			fn(b, req)
			io.Copy(io.Discard, b)
		}()
		return a, nil
	})
}

func TestHostileGuest(t *testing.T) {
	ctx := func() context.Context { return ctxT(t, 3*time.Second) }
	isProto := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, agentrpc.ErrProtocol) {
			t.Fatalf("want ErrProtocol, got %v", err)
		}
	}

	t.Run("oversize frame", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) {
			var hdr [5]byte
			binary.BigEndian.PutUint32(hdr[1:], proto.MaxFrame+1)
			c.Write(hdr[:])
		})
		_, err := c.Ping(ctx())
		isProto(t, err)
	})
	t.Run("garbage", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) { c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")) })
		_, err := c.Ping(ctx())
		if err == nil {
			t.Fatal("garbage accepted")
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) {
			proto.WriteFrame(c, proto.TypeJSON, []byte(`{"version":1,"ready":true,"evil":1}`))
		})
		_, err := c.Ping(ctx())
		isProto(t, err)
	})
	t.Run("wrong frame type", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) { proto.WriteFrame(c, proto.TypeStdout, []byte("x")) })
		_, err := c.Stat(ctx(), "/x")
		isProto(t, err)
	})
	t.Run("malformed error", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) { proto.WriteFrame(c, proto.TypeError, []byte("{nope")) })
		_, err := c.Ping(ctx())
		wantCode(t, err, proto.CodeInternal)
	})
	t.Run("huge error message", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) {
			proto.WriteJSON(c, proto.TypeError, proto.Error{Code: "busy", Message: strings.Repeat("A", 100000)})
		})
		_, err := c.Ping(ctx())
		var pe *proto.Error
		if !errors.As(err, &pe) || len(pe.Message) > 5000 {
			t.Fatalf("message not bounded: %v", len(err.Error()))
		}
	})
	t.Run("closes early", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) { c.Close() })
		_, err := c.Ping(ctx())
		isProto(t, err)
		isProto(t, c.Shutdown(ctx()))
	})
	t.Run("silent guest honours ctx", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) { time.Sleep(10 * time.Second) })
		cx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := c.Exec(cx, proto.ExecRequest{Argv: []string{"x"}}, agentrpc.ExecIO{})
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
			t.Fatalf("got %v after %v", err, time.Since(start))
		}
	})
	t.Run("read_file over max", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) {
			proto.WriteJSON(c, proto.TypeJSON, proto.FileInfo{Path: "/x", Size: 5})
			for i := 0; i < 10; i++ {
				proto.WriteFrame(c, proto.TypeStdout, make([]byte, 1000))
			}
			proto.WriteJSON(c, proto.TypeExit, proto.ExitStatus{})
		})
		var got bytes.Buffer
		_, err := c.ReadFile(ctx(), "/x", 4096, &got)
		wantCode(t, err, proto.CodeTooLarge)
		if got.Len() > 4096 {
			t.Fatalf("wrote %d bytes past the cap", got.Len())
		}
	})
	t.Run("read_file claims huge size", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) {
			proto.WriteJSON(c, proto.TypeJSON, proto.FileInfo{Path: "/x", Size: 1 << 40})
		})
		_, err := c.ReadFile(ctx(), "/x", 4096, io.Discard)
		wantCode(t, err, proto.CodeTooLarge)
	})
	t.Run("diff longer than summary", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) {
			proto.WriteJSON(c, proto.TypeJSON, proto.DiffSummary{Files: []proto.DiffFile{{Path: "a", Status: "added"}}, Bytes: 10})
			proto.WriteFrame(c, proto.TypeStdout, make([]byte, 20))
			proto.WriteJSON(c, proto.TypeExit, proto.ExitStatus{})
		})
		_, err := c.Diff(ctx(), 0, io.Discard)
		isProto(t, err)
	})
	t.Run("diff shorter than summary", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) {
			proto.WriteJSON(c, proto.TypeJSON, proto.DiffSummary{Files: []proto.DiffFile{}, Bytes: 10})
			proto.WriteFrame(c, proto.TypeStdout, make([]byte, 5))
			proto.WriteJSON(c, proto.TypeExit, proto.ExitStatus{})
		})
		_, err := c.Diff(ctx(), 0, io.Discard)
		isProto(t, err)
	})
	for _, bad := range []string{"../etc/passwd", "/abs", ".git/config", "a/.GIT/x", "a//b", "a/./b", ""} {
		t.Run("diff path "+bad, func(t *testing.T) {
			c := hostile(func(c net.Conn, _ proto.Frame) {
				proto.WriteJSON(c, proto.TypeJSON, proto.DiffSummary{Files: []proto.DiffFile{{Path: bad, Status: "added"}}})
				proto.WriteJSON(c, proto.TypeExit, proto.ExitStatus{})
			})
			_, err := c.Diff(ctx(), 0, io.Discard)
			isProto(t, err)
		})
	}
	t.Run("diff summary over max", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) {
			proto.WriteJSON(c, proto.TypeJSON, proto.DiffSummary{Files: []proto.DiffFile{}, Bytes: 1 << 40})
		})
		_, err := c.Diff(ctx(), 1000, io.Discard)
		wantCode(t, err, proto.CodeTooLarge)
	})
	t.Run("write_file early ack", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) { proto.WriteJSON(c, proto.TypeExit, proto.ExitStatus{}) })
		err := c.WriteFile(ctx(), "/x", 0, io.LimitReader(zeroReader{}, 10<<20))
		isProto(t, err)
	})
	t.Run("write_file guest error mid-stream", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) {
			proto.ReadFrame(c)
			proto.WriteJSON(c, proto.TypeError, proto.Error{Code: proto.CodeInternal, Message: "disk full"})
		})
		err := c.WriteFile(ctx(), "/x", 0, io.LimitReader(zeroReader{}, 10<<20))
		wantCode(t, err, proto.CodeInternal)
	})
	t.Run("exec flood is capped", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) {
			for i := 0; i < 50; i++ {
				proto.WriteFrame(c, proto.TypeStdout, make([]byte, 100000))
			}
			proto.WriteJSON(c, proto.TypeExit, proto.ExitStatus{Code: 0})
		})
		c.MaxOutputBytes = 250000
		var out bytes.Buffer
		es, err := c.Exec(ctx(), proto.ExecRequest{Argv: []string{"x"}}, agentrpc.ExecIO{Stdout: &out})
		if err != nil || !es.Truncated || out.Len() != 250000 {
			t.Fatalf("%+v %v %d", es, err, out.Len())
		}
	})
	t.Run("exec stray frame", func(t *testing.T) {
		c := hostile(func(c net.Conn, _ proto.Frame) { proto.WriteFrame(c, proto.TypeStdin, []byte("x")) })
		_, err := c.Exec(ctx(), proto.ExecRequest{Argv: []string{"x"}}, agentrpc.ExecIO{})
		isProto(t, err)
	})
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
