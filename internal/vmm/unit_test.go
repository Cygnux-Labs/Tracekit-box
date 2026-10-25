package vmm

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeAPI serves h on a unix socket and returns a client for it.
func fakeAPI(t *testing.T, h http.HandlerFunc) *apiClient {
	t.Helper()
	sock := filepath.Join(stateDir(t), "fc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	c := newAPIClient(sock)
	t.Cleanup(c.close)
	return c
}

func TestAPIClient(t *testing.T) {
	var got []string
	c := fakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+r.Header.Get("Content-Type")+" "+string(b))
		switch r.URL.Path {
		case "/fault":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"fault_message":"The requested operation is not supported after starting the microVM."}`))
		case "/plain":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("boom"))
		case "/big":
			w.Write(bytes.Repeat([]byte("a"), apiMaxBody*2))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	ctx := context.Background()
	if err := c.put(ctx, "/boot-source", fcBootSource{KernelImagePath: "/k", BootArgs: "a b"}); err != nil {
		t.Fatal(err)
	}
	if err := c.patch(ctx, "/vm", fcVM{State: "Paused"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`PUT /boot-source application/json {"kernel_image_path":"/k","boot_args":"a b"}`,
		`PATCH /vm application/json {"state":"Paused"}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q", got)
	}
	err := c.put(ctx, "/fault", fcAction{ActionType: "InstanceStart"})
	if err == nil || !strings.Contains(err.Error(), "not supported after starting the microVM") || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("fault: %v", err)
	}
	if err := c.put(ctx, "/plain", nil); err == nil || !strings.Contains(err.Error(), "boom (HTTP 500)") {
		t.Fatalf("plain: %v", err)
	}
	b, err := c.do(ctx, http.MethodGet, "/big", nil)
	if err != nil || len(b) != apiMaxBody {
		t.Fatalf("big: %d %v", len(b), err)
	}
}

func TestAPIClientNoSocket(t *testing.T) {
	c := newAPIClient(filepath.Join(stateDir(t), "missing.sock"))
	if err := c.put(context.Background(), "/vm", fcVM{State: "Paused"}); err == nil {
		t.Fatal("no error without a socket")
	}
}

// fakeVsockUDS serves one connection per accept with handle.
func fakeVsockUDS(t *testing.T, handle func(c net.Conn, req string)) string {
	t.Helper()
	path := filepath.Join(stateDir(t), "vsock.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				// Read the request a byte at a time so nothing past the line is consumed.
				var req []byte
				b := make([]byte, 1)
				for len(req) < 64 {
					if _, err := c.Read(b); err != nil {
						return
					}
					req = append(req, b[0])
					if b[0] == '\n' {
						break
					}
				}
				handle(c, string(req))
			}()
		}
	}()
	return path
}

func TestVsockDialLeftoverBytes(t *testing.T) {
	path := fakeVsockUDS(t, func(c net.Conn, req string) {
		if req != "CONNECT 1024\n" {
			c.Write([]byte("BAD " + req))
			return
		}
		// The reply and the first payload bytes in one write, as Firecracker may deliver them.
		c.Write([]byte("OK 1073741824\nhello "))
		io.Copy(c, c)
	})
	c, err := vsockDial(context.Background(), path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("world\n"))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "hello world\n" {
		t.Fatalf("got %q %v", line, err)
	}
	if _, ok := c.(interface{ CloseWrite() error }); !ok {
		t.Fatal("conn lost CloseWrite")
	}
}

func TestVsockDialErrors(t *testing.T) {
	cases := map[string]struct {
		handle func(c net.Conn, req string)
		want   string
	}{
		"bad reply":  {func(c net.Conn, _ string) { c.Write([]byte("NOPE\n")) }, "unexpected handshake reply"},
		"bad port":   {func(c net.Conn, _ string) { c.Write([]byte("OK x\n")) }, "unexpected handshake reply"},
		"closed":     {func(c net.Conn, _ string) {}, "nothing listens"},
		"long line":  {func(c net.Conn, _ string) { c.Write(bytes.Repeat([]byte("O"), 200)); time.Sleep(time.Second) }, "longer than"},
		"no reply":   {func(c net.Conn, _ string) { time.Sleep(2 * time.Second) }, "deadline exceeded"},
		"half reply": {func(c net.Conn, _ string) { c.Write([]byte("OK 12")); time.Sleep(2 * time.Second) }, "deadline exceeded"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := fakeVsockUDS(t, tc.handle)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			c, err := vsockDial(ctx, path, 1024)
			if err == nil {
				c.Close()
				t.Fatal("dial succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVsockDialCancel(t *testing.T) {
	path := fakeVsockUDS(t, func(c net.Conn, _ string) { time.Sleep(2 * time.Second) })
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := vsockDial(ctx, path, 1024)
	if !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
}

func TestVsockDialNoSocket(t *testing.T) {
	if _, err := vsockDial(context.Background(), filepath.Join(stateDir(t), "none"), 1024); err == nil {
		t.Fatal("dial without a socket succeeded")
	}
}

func TestCapWriter(t *testing.T) {
	var buf bytes.Buffer
	w := newCapWriter(&buf, 10)
	for _, s := range []string{"12345", "678", "90abc", "def"} {
		if n, err := w.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", s, n, err)
		}
	}
	out := buf.String()
	if !strings.HasPrefix(out, "1234567890\n[tkbox: console output reached the 10 byte cap") || strings.Count(out, "[tkbox") != 1 {
		t.Fatalf("out %q", out)
	}
	if strings.Contains(out, "abc") || !w.Dropped() {
		t.Fatalf("kept dropped bytes: %q", out)
	}
	if w.Tail() != "1234567890abcdef" {
		t.Fatalf("tail %q", w.Tail())
	}
}

func TestCapWriterTailBound(t *testing.T) {
	w := newCapWriter(io.Discard, 0)
	if w.max != DefaultMaxConsoleBytes {
		t.Fatal("default cap")
	}
	w.Write(bytes.Repeat([]byte("a"), consoleTailBytes))
	w.Write([]byte("end"))
	if tail := w.Tail(); len(tail) != consoleTailBytes || !strings.HasSuffix(tail, "end") {
		t.Fatalf("tail len %d", len(tail))
	}
	w.Write(bytes.Repeat([]byte("b"), 3*consoleTailBytes))
	if len(w.Tail()) != consoleTailBytes {
		t.Fatal("tail grew")
	}
}

type failWriter struct{ n int }

func (f *failWriter) Write(p []byte) (int, error) { f.n++; return 0, errors.New("disk full") }

func TestCapWriterNeverFails(t *testing.T) {
	f := &failWriter{}
	w := newCapWriter(f, 100)
	for i := 0; i < 3; i++ {
		if n, err := w.Write([]byte("abc")); n != 3 || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if f.n != 1 {
		t.Fatalf("kept writing to a failed file: %d", f.n)
	}
}
