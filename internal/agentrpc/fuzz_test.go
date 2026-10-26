//go:build unix

package agentrpc_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// capWriter fails the test the moment more than max bytes are written to it.
type capWriter struct {
	t   *testing.T
	max int64
	n   int64
	buf bytes.Buffer
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	if w.n > w.max {
		w.t.Fatalf("client wrote %d bytes past the %d-byte cap", w.n, w.max)
	}
	return w.buf.Write(p)
}

// replyDialer is a guest that reads the request (and drains whatever else the client sends) and answers with reply.
func replyDialer(reply []byte) agentrpc.Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			if _, err := proto.ReadFrame(b); err != nil {
				return
			}
			go io.Copy(io.Discard, b)
			b.Write(reply)
		}()
		return a, nil
	}
}

func frames(fs ...[]byte) []byte { return bytes.Join(fs, nil) }

func fr(typ byte, payload string) []byte {
	var b bytes.Buffer
	proto.WriteFrame(&b, typ, []byte(payload))
	return b.Bytes()
}

// FuzzClientReplies: whatever a hostile guest answers, the host-side client returns promptly, never writes past its
// caps, accepts a diff only when every path is relative, clean and free of .git and the patch is exactly the declared
// size, and reports guest errors with bounded text.
func FuzzClientReplies(f *testing.F) {
	f.Add(uint8(0), fr(proto.TypeJSON, `{"version":1,"box_id":"b","ready":true}`))
	f.Add(uint8(1), fr(proto.TypeJSON, `{"path":"/x","size":1,"mode":420,"is_dir":false,"mod_time":1}`))
	f.Add(uint8(2), frames(fr(proto.TypeStdout, "hello"), fr(proto.TypeStderr, "e"), fr(proto.TypeExit, `{"code":0}`)))
	f.Add(uint8(3), frames(fr(proto.TypeJSON, `{"path":"/x","size":3}`), fr(proto.TypeStdout, "abc"), fr(proto.TypeExit, `{"code":0}`)))
	f.Add(uint8(4), fr(proto.TypeExit, `{"code":0}`))
	f.Add(uint8(5), frames(fr(proto.TypeJSON, `{"files":[{"path":"a/b","status":"added"}],"bytes":3}`), fr(proto.TypeStdout, "abc"), fr(proto.TypeExit, `{"code":0}`)))
	f.Add(uint8(5), frames(fr(proto.TypeJSON, `{"files":[{"path":"a/.GIT/x","status":"added"}],"bytes":0}`), fr(proto.TypeExit, `{"code":0}`)))
	f.Add(uint8(5), frames(fr(proto.TypeJSON, `{"files":[{"path":"a\\..\\b","status":"added"}],"bytes":0}`), fr(proto.TypeExit, `{"code":0}`)))
	f.Add(uint8(6), fr(proto.TypeExit, `{"code":0}`))
	f.Add(uint8(0), fr(proto.TypeError, `{"code":"busy","message":"`+strings.Repeat("é", 3000)+`"}`))
	f.Add(uint8(2), fr(proto.TypeStdin, "x"))
	f.Fuzz(func(t *testing.T, op uint8, reply []byte) {
		c := agentrpc.New(replyDialer(reply))
		const outCap, readCap, diffCap = 1000, 500, 700
		c.MaxOutputBytes = outCap
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		start := time.Now()
		var err error
		switch op % 7 {
		case 0:
			_, err = c.Ping(ctx)
		case 1:
			_, err = c.Stat(ctx, "/x")
		case 2:
			out := &capWriter{t: t, max: outCap} // stdout and stderr share the cap
			_, err = c.Exec(ctx, proto.ExecRequest{Argv: []string{"x"}}, agentrpc.ExecIO{Stdout: out, Stderr: out, Stdin: strings.NewReader("in")})
		case 3:
			w := &capWriter{t: t, max: readCap}
			_, err = c.ReadFile(ctx, "/x", readCap, w)
		case 4:
			err = c.WriteFile(ctx, "/x", 0o644, strings.NewReader("content"))
		case 5:
			w := &capWriter{t: t, max: diffCap}
			var sum proto.DiffSummary
			sum, err = c.Diff(ctx, diffCap, w)
			if err == nil {
				if sum.Bytes != w.n || sum.Bytes > diffCap {
					t.Fatalf("diff accepted with %d bytes written, summary says %d", w.n, sum.Bytes)
				}
				for _, df := range sum.Files {
					if !cleanRel(df.Path) {
						t.Fatalf("diff accepted path %q", df.Path)
					}
				}
			}
		case 6:
			err = c.Shutdown(ctx)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("call took %v (err %v)", d, err)
		}
		if err == nil {
			return
		}
		var pe *proto.Error
		switch {
		case errors.As(err, &pe):
			if len(pe.Message) > 4096+len("…") || len(pe.Code) > 64 || pe.Code == "" {
				t.Fatalf("guest error not bounded: code %d bytes, message %d bytes", len(pe.Code), len(pe.Message))
			}
		case errors.Is(err, agentrpc.ErrProtocol):
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			t.Fatalf("call ran into its deadline: %v", err)
		}
	})
}

func cleanRel(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) {
		return false
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." || strings.EqualFold(c, ".git") {
			return false
		}
	}
	return true
}
