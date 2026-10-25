package tracekit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// The 1.4.2 signer transport (tracekit/transport): one JSON object per line each way, `hello` first on every
// connection, identity from the socket's peer credentials (on Linux the kernel stamps each write with our real uid,
// so a plain write is enough). The signer answers a connection's frames in order and drops a connection idle for 30 s.

const (
	rpcVersion     = 19      // the protocol Box speaks (Tracekit 1.4.2)
	maxLine        = 1 << 20 // signer quotas.MAX_LINE: bytes of one frame, without its newline, both ways
	connectTimeout = 2 * time.Second
	defaultTimeout = 30 * time.Second
	sendTries      = 3                 // a call whose connection drops is sent at most this many times, same request_id
	maxWait        = 300 * time.Second // approval_wait's timeout_ms cap
	idleRedial     = 20 * time.Second  // a pooled connection idle this long is redialled (the signer drops it at 30 s)
	maxIdleConns   = 4
)

// Incompatible means the signer answered but its protocol range does not hold Box's (19).
type Incompatible struct {
	Where         string
	SignerVersion string
	Proto         []int
}

func (e *Incompatible) Error() string {
	fix := "run a Tracekit 1.4.2 signer (pip install tracekit-ai==1.4.2, then `tracekit up --replace` for a dev " +
		"signer, or restart the signer service)"
	if len(e.Proto) == 2 && e.Proto[1] < rpcVersion {
		fix = "the signer is older than Box's protocol: upgrade it to Tracekit 1.4.2 (pip install " +
			"tracekit-ai==1.4.2, then `tracekit up --replace` for a dev signer, or restart the signer service)"
	} else if len(e.Proto) == 2 && e.Proto[0] > rpcVersion {
		fix = "the signer no longer serves Box's protocol: run a Tracekit 1.4.2 signer for Box, or a Box release " +
			"built for this signer"
	}
	return fmt.Sprintf("tracekit signer at %s is Tracekit %s speaking protocol %s; Tracekit Box needs protocol %d "+
		"(Tracekit 1.4.2): %s", e.Where, orUnknown(e.SignerVersion), protoText(e.Proto), rpcVersion, fix)
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown version)"
	}
	return s
}

func protoText(p []int) string {
	if len(p) != 2 {
		return "(none named)"
	}
	return fmt.Sprintf("%d..%d", p[0], p[1])
}

type hello struct {
	Proto   []int  `json:"proto"`
	Version string `json:"version"`
	DataDir string `json:"data_dir"`
}

// conn is one signer connection, used by one call at a time.
type conn struct {
	nc   net.Conn
	r    *bufio.Reader
	used time.Time
}

func (c *conn) close() { _ = c.nc.Close() }

var errFrameTooLong = fmt.Errorf("frame longer than %d bytes", maxLine)

// readFrame reads one newline-terminated frame of at most maxLine bytes (without the newline).
func readFrame(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > maxLine+1 {
			return nil, errFrameTooLong
		}
		line = append(line, chunk...)
		if err == nil {
			return line[:len(line)-1], nil
		}
		if err != bufio.ErrBufferFull {
			if err == io.EOF && len(line) > 0 {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
}

// parseFrame decodes an answer: a JSON object, numbers kept exact.
func parseFrame(data []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil || m == nil {
		return nil, fmt.Errorf("the signer's answer is not a JSON object")
	}
	return m, nil
}

// dialSigner connects to the signer's socket and checks its hello.
func dialSigner(ctx context.Context, path string) (*conn, hello, error) {
	var h hello
	d := net.Dialer{Timeout: connectTimeout}
	nc, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, h, &Unavailable{Err: fmt.Errorf("no signer answering at %s: %w", path, err)}
	}
	c := &conn{nc: nc, r: bufio.NewReaderSize(nc, 64<<10)}
	deadline := time.Now().Add(connectTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = nc.SetDeadline(deadline)
	frame, err := func() ([]byte, error) {
		if _, err := nc.Write([]byte("{\"method\":\"hello\"}\n")); err != nil {
			return nil, err
		}
		return readFrame(c.r)
	}()
	if err != nil {
		c.close()
		return nil, h, &Unavailable{Err: fmt.Errorf("no signer answering at %s: %w", path, err)}
	}
	m, err := parseFrame(frame)
	if err != nil {
		c.close()
		return nil, h, &Unavailable{Err: fmt.Errorf("signer at %s: hello: %w", path, err)}
	}
	if e, ok := m["error"]; ok {
		c.close()
		return nil, h, &Unavailable{Err: fmt.Errorf("signer at %s refused hello: %v", path, rpcErrorOf(e))}
	}
	h.Version, _ = m["version"].(string)
	h.DataDir, _ = m["data_dir"].(string)
	if p, ok := m["proto"].([]any); ok && len(p) == 2 {
		lo, ok1 := intOf(p[0])
		hi, ok2 := intOf(p[1])
		if ok1 && ok2 {
			h.Proto = []int{int(lo), int(hi)}
		}
	}
	if len(h.Proto) != 2 || h.Proto[0] > rpcVersion || rpcVersion > h.Proto[1] {
		c.close()
		return nil, h, &Incompatible{Where: path, SignerVersion: h.Version, Proto: h.Proto}
	}
	_ = nc.SetDeadline(time.Time{})
	c.used = time.Now()
	return c, h, nil
}

func intOf(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func rpcErrorOf(v any) *RPCError {
	m, _ := v.(map[string]any)
	e := &RPCError{}
	e.Code, _ = m["code"].(string)
	e.Message, _ = m["message"].(string)
	if n, ok := intOf(m["retry_after_ms"]); ok {
		e.RetryAfterMS = n
	}
	if e.Code == "" {
		e.Code = "unknown"
	}
	return e
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported systems
	}
	return hex.EncodeToString(b[:])
}

// transport sends calls to one signer: a small pool of connections, each carrying one call at a time.
type transport struct {
	where   string
	timeout time.Duration
	mu      sync.Mutex
	idle    []*conn
	closed  bool
}

// encodeFrame is the frame of a request as sent, refused before sending when it is not canonical JSON or is over the
// signer's frame limit.
func encodeFrame(method string, req map[string]any) ([]byte, error) {
	req["method"] = method
	data, err := canonical(req, true)
	delete(req, "method")
	if err != nil {
		return nil, &RPCError{Code: "invalid_request", Message: fmt.Sprintf("the %s request is not JSON the signer "+
			"reads back the same (%v); it was not sent", method, err)}
	}
	if len(data) > maxLine {
		return nil, &RPCError{Code: "quota_exceeded", Message: fmt.Sprintf("the %s request is %d bytes, over the "+
			"signer's limit of %d bytes per request; it was not sent", method, len(data), maxLine)}
	}
	return data, nil
}

func (t *transport) get(ctx context.Context) (*conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, &Unavailable{Err: errors.New("the client is closed")}
	}
	for len(t.idle) > 0 {
		c := t.idle[len(t.idle)-1]
		t.idle = t.idle[:len(t.idle)-1]
		if time.Since(c.used) < idleRedial {
			t.mu.Unlock()
			return c, nil
		}
		c.close()
	}
	t.mu.Unlock()
	c, _, err := dialSigner(ctx, t.where)
	return c, err
}

func (t *transport) put(c *conn) {
	c.used = time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || len(t.idle) >= maxIdleConns {
		c.close()
		return
	}
	t.idle = append(t.idle, c)
}

func (t *transport) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	for _, c := range t.idle {
		c.close()
	}
	t.idle = nil
}

// send sends a frame and returns the answer: *RPCError for {"error": ...}, *Unavailable when no answer came. A call
// whose connection drops before its answer is sent again (same frame, so same request_id and client_seq) on a new
// connection, at most sendTries times; a call with no answer in time is not, as the signer may still be on it.
// `own`: a long poll, on a connection of its own closed after the answer, so it holds up no other call. `wait` is
// added to the call's timeout.
func (t *transport) send(ctx context.Context, method string, frame []byte, own bool, wait time.Duration) (map[string]any, error) {
	timeout := t.timeout + wait
	deadline := time.Now().Add(timeout)
	var lost error
	for try := 0; try < sendTries; try++ {
		if err := ctx.Err(); err != nil {
			return nil, &Unavailable{Err: fmt.Errorf("%s: %w", method, err)}
		}
		var c *conn
		var err error
		if own {
			c, _, err = dialSigner(ctx, t.where)
		} else {
			c, err = t.get(ctx)
		}
		if err != nil {
			return nil, err
		}
		m, err := exchange(ctx, c, frame, deadline)
		if err == nil {
			if own {
				c.close()
			} else {
				t.put(c)
			}
			if e, ok := m["error"]; ok {
				return nil, rpcErrorOf(e)
			}
			return m, nil
		}
		c.close()
		var ne net.Error
		switch {
		case ctx.Err() != nil:
			return nil, &Unavailable{Err: fmt.Errorf("%s: %w", method, ctx.Err())}
		case errors.As(err, &ne) && ne.Timeout():
			if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) { // ctx's deadline, a moment before ctx says so
				return nil, &Unavailable{Err: fmt.Errorf("%s: %w", method, context.DeadlineExceeded)}
			}
			return nil, &Unavailable{Err: fmt.Errorf("no answer to %s within %s", method, timeout)}
		case errors.Is(err, errFrameTooLong), errors.Is(err, errBadAnswer):
			return nil, &Unavailable{Err: fmt.Errorf("%s: %w", method, err)}
		}
		lost = err
	}
	return nil, &Unavailable{Err: fmt.Errorf("lost the connection to the signer %d times sending %s (last: %v)",
		sendTries, method, lost)}
}

var errBadAnswer = errors.New("the signer's answer is not a JSON object")

func exchange(ctx context.Context, c *conn, frame []byte, deadline time.Time) (map[string]any, error) {
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.nc.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.nc.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	buf := make([]byte, 0, len(frame)+1)
	buf = append(append(buf, frame...), '\n')
	if _, err := c.nc.Write(buf); err != nil {
		return nil, err
	}
	data, err := readFrame(c.r)
	if err != nil {
		return nil, err
	}
	m, err := parseFrame(data)
	if err != nil {
		return nil, errBadAnswer
	}
	_ = c.nc.SetDeadline(time.Time{})
	return m, nil
}
