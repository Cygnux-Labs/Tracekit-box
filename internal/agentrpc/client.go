package agentrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// Client implements Guest over a Dialer. The guest is hostile: every frame is bounded by proto.MaxFrame, totals are
// capped (maxBytes, MaxOutputBytes), JSON is decoded strictly into typed structs, anything out of protocol is an
// ErrProtocol, and ctx (deadline or cancel) closes the connection. Callers must pass a ctx with a deadline or cancel:
// a silent guest otherwise holds the call open.
type Client struct {
	Dial Dialer
	// MaxOutputBytes caps the exec stdout+stderr the client forwards, whatever the guest claims (0:
	// proto.DefaultMaxOutputBytes). Past it output is dropped and ExitStatus.Truncated is set.
	MaxOutputBytes int64
}

// New returns a Guest that dials d for every request.
func New(d Dialer) *Client { return &Client{Dial: d} }

// ErrProtocol wraps every guest reply that breaks the protocol.
var ErrProtocol = errors.New("agentrpc: guest broke the protocol")

// maxErrorMessage bounds the guest-supplied text kept in a *proto.Error.
const maxErrorMessage = 4096

// allowedSignals are the signal names the protocol forwards.
var allowedSignals = map[string]bool{"SIGINT": true, "SIGTERM": true, "SIGKILL": true, "SIGHUP": true, "SIGQUIT": true}

func protoErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrProtocol}, args...)...)
}

// call is one connection. Frame writes are serialized, and urgent frames (signals) go before the data frames (stdin)
// that are waiting: a signal waits for at most the one frame being written, never behind a stdin stream. Cancelling
// ctx closes the connection, which also ends a write the guest is not reading.
type call struct {
	ctx  context.Context
	conn net.Conn
	stop func() bool

	wmu     sync.Mutex
	wcond   sync.Cond // on wmu
	writing bool      // a frame is being written
	urgent  int       // urgent writers waiting
}

func (c *Client) open(ctx context.Context) (*call, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := c.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("agentrpc: dial guest: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	k := &call{ctx: ctx, conn: conn}
	k.wcond.L = &k.wmu
	k.stop = context.AfterFunc(ctx, func() { conn.Close() })
	return k, nil
}

func (k *call) close() {
	k.stop()
	k.conn.Close()
}

// write writes one data frame, after any urgent frame that is waiting.
func (k *call) write(typ byte, p []byte) error { return k.writeFrame(false, typ, p) }

// writeUrgent writes one frame ahead of the data frames that are waiting.
func (k *call) writeUrgent(typ byte, p []byte) error { return k.writeFrame(true, typ, p) }

func (k *call) writeFrame(urgent bool, typ byte, p []byte) error {
	k.wmu.Lock()
	if urgent {
		k.urgent++
	}
	for k.writing || (!urgent && k.urgent > 0) {
		k.wcond.Wait()
	}
	if urgent {
		k.urgent--
	}
	k.writing = true
	k.wmu.Unlock()
	err := proto.WriteFrame(k.conn, typ, p)
	k.wmu.Lock()
	k.writing = false
	k.wcond.Broadcast()
	k.wmu.Unlock()
	return k.err(err)
}

func (k *call) send(req any) error {
	b, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("agentrpc: marshal request: %w", err)
	}
	return k.write(proto.TypeJSON, b)
}

func (k *call) read() (proto.Frame, error) {
	f, err := proto.ReadFrame(k.conn)
	if err != nil {
		switch {
		case errors.Is(err, proto.ErrFrameTooLarge):
			return f, protoErr("frame over %d bytes", proto.MaxFrame)
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			if k.ctx.Err() == nil {
				return f, protoErr("connection closed before the reply ended")
			}
		}
		return f, k.err(err)
	}
	return f, nil
}

// err turns a transport error caused by ctx into ctx's error.
func (k *call) err(err error) error {
	if err == nil {
		return nil
	}
	if cerr := k.ctx.Err(); cerr != nil {
		return fmt.Errorf("agentrpc: %w", cerr)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("agentrpc: %w", context.DeadlineExceeded)
	}
	return fmt.Errorf("agentrpc: %w", err)
}

// guestError decodes a TypeError frame, bounding the guest's message.
func guestError(f proto.Frame) error {
	e := f.AsError()
	if len(e.Message) > maxErrorMessage {
		e.Message = e.Message[:maxErrorMessage] + "…"
	}
	if len(e.Code) > 64 {
		e.Code = proto.CodeInternal
	}
	return e
}

func decode(f proto.Frame, v any) error {
	if err := f.Decode(v); err != nil {
		return protoErr("%v", err)
	}
	return nil
}

// roundTrip sends req and decodes the single TypeJSON reply into resp.
func (c *Client) roundTrip(ctx context.Context, req, resp any) error {
	k, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer k.close()
	if err := k.send(req); err != nil {
		return err
	}
	f, err := k.read()
	if err != nil {
		return err
	}
	switch f.Type {
	case proto.TypeJSON:
		return decode(f, resp)
	case proto.TypeError:
		return guestError(f)
	}
	return protoErr("unexpected frame type %d", f.Type)
}

func (c *Client) Ping(ctx context.Context) (proto.PingResponse, error) {
	var r proto.PingResponse
	err := c.roundTrip(ctx, proto.PingRequest{Op: proto.OpPing}, &r)
	return r, err
}

func (c *Client) Stat(ctx context.Context, path string) (proto.FileInfo, error) {
	var fi proto.FileInfo
	err := c.roundTrip(ctx, proto.StatRequest{Op: proto.OpStat, Path: path}, &fi)
	return fi, err
}

// Exec runs req. Stdin and Signals are pumped on their own goroutines, a signal ahead of any stdin frame still to be
// written; a Stdin reader blocked in Read is abandoned (not waited for) when the exec ends. Cancelling ctx closes the
// connection: the guest kills the process group.
func (c *Client) Exec(ctx context.Context, req proto.ExecRequest, stdio ExecIO) (proto.ExitStatus, error) {
	req.Op = proto.OpExec
	req.Stdin = stdio.Stdin != nil
	k, err := c.open(ctx)
	if err != nil {
		return proto.ExitStatus{}, err
	}
	defer k.close()
	if err := k.send(req); err != nil {
		return proto.ExitStatus{}, err
	}
	finished := make(chan struct{})
	defer close(finished)
	if stdio.Stdin != nil {
		go func() {
			buf := make([]byte, 64<<10)
			for {
				n, rerr := stdio.Stdin.Read(buf)
				if n > 0 {
					if k.write(proto.TypeStdin, buf[:n]) != nil {
						return
					}
				}
				if rerr != nil {
					break // EOF or a failed reader: either way stdin ends here
				}
				select {
				case <-finished:
					return
				default:
				}
			}
			k.write(proto.TypeStdinEOF, nil)
		}()
	}
	if stdio.Signals != nil {
		go func() {
			for {
				select {
				case <-finished:
					return
				case s, ok := <-stdio.Signals:
					if !ok {
						return
					}
					if !allowedSignals[s] {
						continue
					}
					b, _ := json.Marshal(proto.Signal{Signal: s})
					if k.writeUrgent(proto.TypeSignal, b) != nil {
						return
					}
				}
			}
		}()
	}
	limit := c.MaxOutputBytes
	if limit <= 0 {
		limit = proto.DefaultMaxOutputBytes
	}
	var n int64
	truncated := false
	for {
		f, err := k.read()
		if err != nil {
			return proto.ExitStatus{}, err
		}
		switch f.Type {
		case proto.TypeStdout, proto.TypeStderr:
			w := stdio.Stdout
			if f.Type == proto.TypeStderr {
				w = stdio.Stderr
			}
			p := f.Payload
			if room := limit - n; int64(len(p)) > room {
				truncated = true
				p = p[:max(room, 0)]
			}
			n += int64(len(p))
			if w != nil && len(p) > 0 {
				if _, err := w.Write(p); err != nil {
					return proto.ExitStatus{}, fmt.Errorf("agentrpc: exec output: %w", err)
				}
			}
		case proto.TypeExit:
			var es proto.ExitStatus
			if err := decode(f, &es); err != nil {
				return proto.ExitStatus{}, err
			}
			es.Truncated = es.Truncated || truncated
			return es, nil
		case proto.TypeError:
			return proto.ExitStatus{}, guestError(f)
		default:
			return proto.ExitStatus{}, protoErr("unexpected frame type %d in exec", f.Type)
		}
	}
}

func tooLarge(format string, args ...any) error {
	return &proto.Error{Code: proto.CodeTooLarge, Message: fmt.Sprintf(format, args...)}
}

func (c *Client) ReadFile(ctx context.Context, path string, maxBytes int64, w io.Writer) (proto.FileInfo, error) {
	if maxBytes <= 0 {
		maxBytes = proto.DefaultMaxReadBytes
	}
	k, err := c.open(ctx)
	if err != nil {
		return proto.FileInfo{}, err
	}
	defer k.close()
	if err := k.send(proto.ReadFileRequest{Op: proto.OpReadFile, Path: path, MaxBytes: maxBytes}); err != nil {
		return proto.FileInfo{}, err
	}
	f, err := k.read()
	if err != nil {
		return proto.FileInfo{}, err
	}
	switch f.Type {
	case proto.TypeJSON:
	case proto.TypeError:
		return proto.FileInfo{}, guestError(f)
	default:
		return proto.FileInfo{}, protoErr("unexpected frame type %d in read_file", f.Type)
	}
	var fi proto.FileInfo
	if err := decode(f, &fi); err != nil {
		return proto.FileInfo{}, err
	}
	if fi.Size > maxBytes || fi.Size < 0 {
		return proto.FileInfo{}, tooLarge("%s is %d bytes, over max_bytes %d", path, fi.Size, maxBytes)
	}
	var n int64
	for {
		f, err := k.read()
		if err != nil {
			return proto.FileInfo{}, err
		}
		switch f.Type {
		case proto.TypeStdout:
			n += int64(len(f.Payload))
			if n > maxBytes {
				return proto.FileInfo{}, tooLarge("%s: guest sent more than max_bytes %d", path, maxBytes)
			}
			if _, err := w.Write(f.Payload); err != nil {
				return proto.FileInfo{}, fmt.Errorf("agentrpc: read_file output: %w", err)
			}
		case proto.TypeExit:
			var es proto.ExitStatus
			if err := decode(f, &es); err != nil {
				return proto.FileInfo{}, err
			}
			return fi, nil
		case proto.TypeError:
			return proto.FileInfo{}, guestError(f)
		default:
			return proto.FileInfo{}, protoErr("unexpected frame type %d in read_file", f.Type)
		}
	}
}

// WriteFile streams r to the guest. If r fails, the connection is closed without TypeStdinEOF so the guest drops
// the partial file instead of committing it.
func (c *Client) WriteFile(ctx context.Context, path string, mode uint32, r io.Reader) error {
	k, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer k.close()
	if err := k.send(proto.WriteFileRequest{Op: proto.OpWriteFile, Path: path, Mode: mode}); err != nil {
		return err
	}
	var sentEOF atomic.Bool
	pumpErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 256<<10)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				if err := k.write(proto.TypeStdin, buf[:n]); err != nil {
					pumpErr <- err
					return
				}
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				pumpErr <- fmt.Errorf("agentrpc: write_file source: %w", rerr)
				k.conn.Close() // no EOF frame: the guest discards the temp file
				return
			}
		}
		sentEOF.Store(true)
		pumpErr <- k.write(proto.TypeStdinEOF, nil)
	}()
	type reply struct {
		f   proto.Frame
		err error
	}
	replies := make(chan reply, 1)
	go func() {
		f, err := k.read()
		replies <- reply{f, err}
	}()
	for {
		select {
		case err := <-pumpErr:
			if err != nil {
				// prefer the guest's own error if it already answered (it stops reading after a failure)
				select {
				case rp := <-replies:
					if rp.err == nil && rp.f.Type == proto.TypeError {
						return guestError(rp.f)
					}
				default:
				}
				return err
			}
			pumpErr = nil
		case rp := <-replies:
			if rp.err != nil {
				return rp.err
			}
			switch rp.f.Type {
			case proto.TypeError:
				return guestError(rp.f)
			case proto.TypeExit:
				if !sentEOF.Load() {
					return protoErr("write_file acknowledged before all content was sent")
				}
				var es proto.ExitStatus
				return decode(rp.f, &es)
			}
			return protoErr("unexpected frame type %d in write_file", rp.f.Type)
		}
	}
}

// Diff writes the patch to w. The summary is checked before any patch byte is accepted: its size must fit maxBytes
// and every path must be relative, clean and free of .git; the patch must then be exactly that size.
func (c *Client) Diff(ctx context.Context, maxBytes int64, w io.Writer) (proto.DiffSummary, error) {
	return c.DiffWith(ctx, proto.DiffRequest{MaxBytes: maxBytes}, w)
}

// DiffWith is Diff with the whole request (req.ExcludeDirs: directory names left out of the patch).
func (c *Client) DiffWith(ctx context.Context, req proto.DiffRequest, w io.Writer) (proto.DiffSummary, error) {
	req.Op = proto.OpDiff
	if req.MaxBytes <= 0 {
		req.MaxBytes = proto.DefaultMaxDiffBytes
	}
	maxBytes := req.MaxBytes
	if err := proto.CheckExcludeDirs(req.ExcludeDirs); err != nil {
		return proto.DiffSummary{}, fmt.Errorf("agentrpc: %w", err)
	}
	k, err := c.open(ctx)
	if err != nil {
		return proto.DiffSummary{}, err
	}
	defer k.close()
	if err := k.send(req); err != nil {
		return proto.DiffSummary{}, err
	}
	f, err := k.read()
	if err != nil {
		return proto.DiffSummary{}, err
	}
	switch f.Type {
	case proto.TypeJSON:
	case proto.TypeError:
		return proto.DiffSummary{}, guestError(f)
	default:
		return proto.DiffSummary{}, protoErr("unexpected frame type %d in diff", f.Type)
	}
	var sum proto.DiffSummary
	if err := decode(f, &sum); err != nil {
		return proto.DiffSummary{}, err
	}
	if sum.Bytes < 0 {
		return proto.DiffSummary{}, protoErr("negative patch size")
	}
	if sum.Bytes > maxBytes {
		return proto.DiffSummary{}, tooLarge("the guest's patch is %d bytes, over max_bytes %d", sum.Bytes, maxBytes)
	}
	for _, df := range sum.Files {
		if err := checkDiffPath(df.Path); err != nil {
			return proto.DiffSummary{}, err
		}
	}
	var n int64
	for {
		f, err := k.read()
		if err != nil {
			return proto.DiffSummary{}, err
		}
		switch f.Type {
		case proto.TypeStdout:
			n += int64(len(f.Payload))
			if n > sum.Bytes {
				return proto.DiffSummary{}, protoErr("patch longer than the %d bytes the summary declared", sum.Bytes)
			}
			if _, err := w.Write(f.Payload); err != nil {
				return proto.DiffSummary{}, fmt.Errorf("agentrpc: diff output: %w", err)
			}
		case proto.TypeExit:
			if n != sum.Bytes {
				return proto.DiffSummary{}, protoErr("patch is %d bytes, the summary declared %d", n, sum.Bytes)
			}
			var es proto.ExitStatus
			if err := decode(f, &es); err != nil {
				return proto.DiffSummary{}, err
			}
			return sum, nil
		case proto.TypeError:
			return proto.DiffSummary{}, guestError(f)
		default:
			return proto.DiffSummary{}, protoErr("unexpected frame type %d in diff", f.Type)
		}
	}
}

// checkDiffPath enforces proto.DiffFile.Path: relative, slash-separated, no empty, "." or ".." component, no NUL,
// never a .git component (any case).
func checkDiffPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.IndexByte(p, 0) >= 0 {
		return protoErr("bad path %q in diff summary", p)
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." || strings.EqualFold(c, ".git") {
			return protoErr("bad path %q in diff summary", p)
		}
	}
	return nil
}

func (c *Client) Shutdown(ctx context.Context) error {
	k, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer k.close()
	if err := k.send(proto.ShutdownRequest{Op: proto.OpShutdown}); err != nil {
		return err
	}
	f, err := k.read()
	if err != nil {
		return err
	}
	switch f.Type {
	case proto.TypeExit:
		var es proto.ExitStatus
		return decode(f, &es)
	case proto.TypeError:
		return guestError(f)
	}
	return protoErr("unexpected frame type %d in shutdown", f.Type)
}

var _ Guest = (*Client)(nil)
