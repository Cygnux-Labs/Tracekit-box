package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// client speaks the daemon API (internal/api) over the Unix socket.
type client struct {
	sock string
	hc   *http.Client
}

func newClient(sock string) *client {
	c := &client{sock: sock}
	c.hc = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return c.dial(ctx)
	}}}
	return c
}

// daemonDown is returned when nothing answers on the socket.
type daemonDown struct {
	sock string
	err  error
}

func (e *daemonDown) Error() string {
	return fmt.Sprintf("no tkbox daemon answering at %s (%v): start one with `tkbox daemon`, or pass --socket", e.sock, e.err)
}

func (c *client) dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.sock)
	if err != nil {
		return nil, &daemonDown{sock: c.sock, err: errors.Unwrap(err)}
	}
	return conn, nil
}

// do sends one JSON request; a non-2xx answer is returned as *api.ErrorDetail.
func (c *client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://tkbox"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var dd *daemonDown
		if errors.As(err, &dd) {
			return dd
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return decodeError(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func decodeError(resp *http.Response) error {
	var eb api.ErrorBody
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if json.Unmarshal(data, &eb) != nil || eb.Error.Code == "" {
		return &api.ErrorDetail{Code: api.CodeInternal, Message: fmt.Sprintf("daemon answered %s: %s", resp.Status, bytes.TrimSpace(data))}
	}
	return &eb.Error
}

func boxPath(box string, rest string) string { return "/v1/boxes/" + url.PathEscape(box) + rest }

// diff fetches a box's patch and its summary.
func (c *client) diff(ctx context.Context, box string) ([]byte, api.DiffSummary, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://tkbox"+boxPath(box, "/diff"), nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		var dd *daemonDown
		if errors.As(err, &dd) {
			return nil, api.DiffSummary{}, dd
		}
		return nil, api.DiffSummary{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, api.DiffSummary{}, decodeError(resp)
	}
	var sum api.DiffSummary
	if h := resp.Header.Get(api.DiffSummaryHeader); h != "" {
		json.Unmarshal([]byte(h), &sum)
	}
	patch, err := io.ReadAll(resp.Body)
	return patch, sum, err
}

// events reads a box's events.ndjson as it is now (nil on any error).
func (c *client) events(ctx context.Context, box string) []api.Event {
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://tkbox"+boxPath(box, "/events"), nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var out []api.Event
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var e api.Event
		json.Unmarshal(sc.Bytes(), &e) // a line that does not decode still counts
		out = append(out, e)
	}
	return out
}

// execIO is the client side of one exec.
type execIO struct {
	Stdin   io.Reader // nil: no stdin
	Stdout  io.Writer
	Stderr  io.Writer
	Signals <-chan string // signal names to forward
	OnEvent func(api.ExecEvent)
}

// exec runs a command over the tkbox-exec/1 upgrade. It returns the exit status, or an *api.ErrorDetail when the
// daemon refused or failed the command.
func (c *client) exec(ctx context.Context, box string, req api.ExecRequest, eio execIO) (proto.ExitStatus, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return proto.ExitStatus{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	req.Stdin = eio.Stdin != nil
	body, _ := json.Marshal(req)
	hreq, _ := http.NewRequest("POST", "http://tkbox"+boxPath(box, "/exec"), bytes.NewReader(body))
	hreq.Header.Set("Connection", "Upgrade")
	hreq.Header.Set("Upgrade", api.ExecUpgrade)
	hreq.Header.Set("Content-Type", "application/json")
	if err := hreq.Write(conn); err != nil {
		return proto.ExitStatus{}, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, hreq)
	if err != nil {
		return proto.ExitStatus{}, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		return proto.ExitStatus{}, decodeError(resp)
	}
	var wmu sync.Mutex
	write := func(typ byte, p []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return proto.WriteFrame(conn, typ, p)
	}
	if eio.Stdin != nil {
		go func() {
			buf := make([]byte, 32<<10)
			for {
				n, err := eio.Stdin.Read(buf)
				if n > 0 && write(proto.TypeStdin, buf[:n]) != nil {
					return
				}
				if err != nil {
					write(proto.TypeStdinEOF, nil)
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	defer close(done)
	if eio.Signals != nil {
		go func() {
			for {
				select {
				case s := <-eio.Signals:
					b, _ := json.Marshal(proto.Signal{Signal: s})
					write(proto.TypeSignal, b)
				case <-done:
					return
				}
			}
		}()
	}
	for {
		f, err := proto.ReadFrame(br)
		if err != nil {
			if ctx.Err() != nil {
				return proto.ExitStatus{}, ctx.Err()
			}
			return proto.ExitStatus{}, fmt.Errorf("the exec stream broke: %w", err)
		}
		switch f.Type {
		case proto.TypeJSON:
			var ev api.ExecEvent
			if json.Unmarshal(f.Payload, &ev) == nil && eio.OnEvent != nil {
				eio.OnEvent(ev)
			}
		case proto.TypeStdout:
			if eio.Stdout != nil {
				eio.Stdout.Write(f.Payload)
			}
		case proto.TypeStderr:
			if eio.Stderr != nil {
				eio.Stderr.Write(f.Payload)
			}
		case proto.TypeExit:
			var st proto.ExitStatus
			if err := json.Unmarshal(f.Payload, &st); err != nil {
				return st, fmt.Errorf("bad exit frame: %w", err)
			}
			return st, nil
		case proto.TypeError:
			var ed api.ErrorDetail
			if json.Unmarshal(f.Payload, &ed) != nil || ed.Code == "" {
				ed = api.ErrorDetail{Code: api.CodeInternal, Message: "malformed error frame"}
			}
			return proto.ExitStatus{}, &ed
		}
	}
}
