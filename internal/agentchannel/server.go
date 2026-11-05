package agentchannel

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"
)

type Dial func(context.Context) (net.Conn, error)

type runEntry struct {
	token  string
	closed bool
}

type activeConn struct {
	guest  net.Conn
	signer net.Conn
}

type refusal struct {
	code    string
	msg     string
	retryMS int64
	kind    limitType
}

func (e *refusal) Error() string { return e.msg }

// Server scopes one box's guest connections to its dedicated signer channel.
type Server struct {
	Dial         Dial
	BoxRun       string
	BoxToken     string
	FrameTimeout time.Duration
	OnLimit      func(string)

	mu           sync.Mutex
	connections  map[*activeConn]struct{}
	runs         map[string]runEntry
	reservations int
	approvals    map[string]bool
	frames       float64
	last         time.Time
	bytes        int64
	limitsSeen   map[string]bool
	closed       bool
	done         sync.WaitGroup
}

func New(dial Dial, runID, token string) *Server {
	return &Server{Dial: dial, BoxRun: runID, BoxToken: token, FrameTimeout: FrameStartTimeout,
		connections: map[*activeConn]struct{}{}, runs: map[string]runEntry{}, approvals: map[string]bool{}, frames: RateBurst, last: time.Now(), limitsSeen: map[string]bool{}}
}

func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.closed || len(s.connections) >= MaxConnections {
			s.mu.Unlock()
			go func() {
				_ = c.SetWriteDeadline(time.Now().Add(RefusalWriteTimeout))
				writeError(c, "quota_exceeded", "agent channel connection limit reached", 1000)
				_ = c.Close()
			}()
			continue
		}
		active := &activeConn{guest: c}
		s.connections[active] = struct{}{}
		s.done.Add(1)
		s.mu.Unlock()
		go func(c net.Conn, active *activeConn) {
			defer s.done.Done()
			defer func() { s.mu.Lock(); delete(s.connections, active); s.mu.Unlock(); c.Close() }()
			s.handle(active)
		}(c, active)
	}
}

func (s *Server) handle(active *activeConn) {
	guest := active.guest
	reserved := false
	defer func() {
		if reserved {
			s.releaseReservation()
		}
	}()
	ctx := context.Background()
	signer, err := s.Dial(ctx)
	if err != nil {
		guestWriteError(guest, "unavailable", "signer channel unavailable", 0)
		return
	}
	s.mu.Lock()
	active.signer = signer
	closing := s.closed
	s.mu.Unlock()
	if closing {
		_ = signer.Close()
		return
	}
	defer signer.Close()
	gr, sr := bufio.NewReaderSize(guest, 64<<10), bufio.NewReaderSize(signer, 64<<10)
	for {
		_ = guest.SetReadDeadline(time.Now().Add(IdleTimeout))
		first, err := gr.ReadByte()
		if err != nil {
			return
		}
		_ = guest.SetReadDeadline(time.Now().Add(s.FrameTimeout))
		frame, obj, err := ReadFramePrefix(gr, first)
		ok, retry := s.takeToken()
		if !ok {
			guestWriteError(guest, "quota_exceeded", "agent channel rate limit exceeded", retry)
			if err != nil {
				return
			}
			continue
		}
		if err != nil {
			if errors.Is(err, ErrInvalidFrame) {
				guestWriteError(guest, "forbidden", err.Error(), 0)
				continue
			}
			return
		}
		method, _ := obj["method"].(string)
		if err := s.check(method, obj, frame); err != nil {
			var r *refusal
			if errors.As(err, &r) {
				if r.kind != "" {
					s.limit(r.msg, r.kind)
				}
				guestWriteError(guest, r.code, r.msg, r.retryMS)
			} else {
				guestWriteError(guest, "forbidden", err.Error(), 0)
			}
			continue
		}
		if method == "register_run" {
			reserved = true
		}
		if method == "register_run" {
			clean := map[string]any{"method": "register_run"}
			if v, ok := obj["request_id"]; ok {
				clean["request_id"] = v
			}
			if v, ok := obj["agent"]; ok {
				clean["agent"] = v
			}
			frame, _ = json.Marshal(clean)
		}
		_ = signer.SetDeadline(time.Now().Add(SignerReplyTimeout))
		if _, err = signer.Write(append(frame, '\n')); err != nil {
			return
		}
		_ = signer.SetReadDeadline(time.Now().Add(SignerReplyTimeout))
		ans, err := readSignerFrame(sr)
		if err != nil {
			return
		}
		if err = s.record(method, ans, obj); err != nil {
			if method == "register_run" {
				reserved = false
			}
			guestWriteError(guest, "quota_exceeded", err.Error(), 0)
			continue
		}
		if method == "register_run" {
			reserved = false
		}
		if _, err = guestWrite(guest, append(ans, '\n')); err != nil {
			return
		}
	}
}

type limitType string

const (
	runLimit  limitType = "run_cap"
	byteLimit limitType = "byte_budget"
)

func (s *Server) limit(reason string, kind limitType) {
	s.mu.Lock()
	key := string(kind)
	first := !s.limitsSeen[key]
	s.limitsSeen[key] = true
	cb := s.OnLimit
	s.mu.Unlock()
	if first && cb != nil {
		cb(reason)
	}
}

func (s *Server) takeToken() (bool, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.frames += now.Sub(s.last).Seconds() * RatePerSecond
	if s.frames > RateBurst {
		s.frames = RateBurst
	}
	s.last = now
	if s.frames < 1 {
		return false, int64((1-s.frames)/RatePerSecond*1000) + 1
	}
	s.frames--
	return true, 0
}

func (s *Server) check(method string, m map[string]any, frame []byte) error {
	if method == "register_run" {
		for _, k := range []string{"parent", "principal", "principal_token", "caller", "source", "tenant", "analyzes", "replay_of", "investigation", "ext", "box"} {
			if _, ok := m[k]; ok {
				return fmt.Errorf("forbidden register_run field %s", k)
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.runs)+s.reservations >= MaxRuns {
			return &refusal{code: "quota_exceeded", msg: "run limit reached", retryMS: 1000, kind: runLimit}
		}
		s.reservations++
		return nil
	}
	if method == "hello" || method == "status" {
		return nil
	}
	if method == "approval_get" {
		id, _ := m["approval_id"].(string)
		s.mu.Lock()
		owned := s.approvals[id]
		s.mu.Unlock()
		if !owned {
			return fmt.Errorf("approval is not owned by this box")
		}
		return nil
	}
	rid, _ := m["run_id"].(string)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.runs[rid]
	if !ok || e.closed {
		return fmt.Errorf("run is not owned by this box")
	}
	if method == "model_event" || method == "complete" || method == "observe" {
		size := int64(len(frame))
		if s.bytes+size > ByteBudget {
			return &refusal{code: "quota_exceeded", msg: "agent channel byte budget exceeded", retryMS: 1000, kind: byteLimit}
		}
		s.bytes += size
	}
	return nil
}

func (s *Server) releaseReservation() {
	s.mu.Lock()
	if s.reservations > 0 {
		s.reservations--
	}
	s.mu.Unlock()
}
func (s *Server) record(method string, ans []byte, req map[string]any) error {
	var m map[string]any
	if json.Unmarshal(ans, &m) != nil {
		if method == "register_run" {
			s.releaseReservation()
		}
		return nil
	}
	result := m
	s.mu.Lock()
	defer s.mu.Unlock()
	if method == "register_run" {
		if s.reservations > 0 {
			s.reservations--
		}
		if _, failed := result["error"]; failed {
			return nil
		}
		id, _ := result["run_id"].(string)
		tok, _ := result["run_token"].(string)
		if id != "" && tok != "" && id != s.BoxRun {
			if _, exists := s.runs[id]; exists {
				return fmt.Errorf("signer reused a run id")
			}
			s.runs[id] = runEntry{token: tok}
		}
	}
	if method == "approval_request" {
		id, _ := result["approval_id"].(string)
		if id != "" {
			s.approvals[id] = true
		}
	}
	if method == "close_run" {
		if _, failed := result["error"]; !failed {
			id, _ := req["run_id"].(string)
			if e, ok := s.runs[id]; ok {
				e.closed = true
				s.runs[id] = e
			}
		}
	}
	return nil
}

// Close stops acceptance and closes all active guest streams before callers close the box run.
func (s *Server) Close(l net.Listener) {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}
	s.mu.Lock()
	for c := range s.connections {
		_ = c.guest.Close()
		if c.signer != nil {
			_ = c.signer.Close()
		}
	}
	s.mu.Unlock()
	s.done.Wait()
}

func (s *Server) CloseRuns(ctx context.Context) []error {
	s.mu.Lock()
	entries := make(map[string]runEntry, len(s.runs))
	ids := make([]string, 0, len(s.runs))
	for id, e := range s.runs {
		if !e.closed {
			entries[id] = e
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	slices.Sort(ids)
	var failures []error
	for _, id := range ids {
		e := entries[id]
		c, err := s.Dial(ctx)
		if err != nil {
			failures = append(failures, fmt.Errorf("close channel run %s: %w", id, err))
			continue
		}
		var rid [16]byte
		if _, err := rand.Read(rid[:]); err != nil {
			c.Close()
			failures = append(failures, err)
			continue
		}
		req, _ := json.Marshal(map[string]any{"method": "close_run", "request_id": hex.EncodeToString(rid[:]), "run_id": id, "run_token": e.token})
		c.SetDeadline(time.Now().Add(IdleTimeout))
		if _, err := c.Write(append(req, '\n')); err != nil {
			failures = append(failures, fmt.Errorf("close channel run %s: %w", id, err))
			c.Close()
			continue
		}
		r := bufio.NewReader(c)
		ans, err := readSignerFrame(r)
		if err != nil {
			failures = append(failures, fmt.Errorf("close channel run %s: %w", id, err))
		} else {
			var reply map[string]any
			if json.Unmarshal(ans, &reply) != nil {
				failures = append(failures, fmt.Errorf("close channel run %s: invalid signer reply", id))
			} else if refusal, ok := reply["error"]; ok {
				failures = append(failures, fmt.Errorf("close channel run %s: signer refused: %v", id, refusal))
			} else {
				s.mu.Lock()
				e := s.runs[id]
				e.closed = true
				s.runs[id] = e
				s.mu.Unlock()
			}
		}
		c.Close()
	}
	return failures
}

func writeError(w io.Writer, code, msg string, retry int64) {
	e := map[string]any{"error": map[string]any{"code": code, "message": msg}}
	if retry > 0 {
		e["error"].(map[string]any)["retry_after_ms"] = retry
	}
	b, _ := json.Marshal(e)
	_, _ = w.Write(append(b, '\n'))
}
func guestWrite(w net.Conn, b []byte) (int, error) {
	_ = w.SetWriteDeadline(time.Now().Add(GuestWriteTimeout))
	return w.Write(b)
}
func guestWriteError(w net.Conn, code, msg string, retry int64) {
	_ = w.SetWriteDeadline(time.Now().Add(GuestWriteTimeout))
	writeError(w, code, msg, retry)
}
func readSignerFrame(r *bufio.Reader) ([]byte, error) {
	var b []byte
	for {
		p, e := r.ReadSlice('\n')
		b = append(b, p...)
		if len(b) > MaxFrame+1 {
			return nil, ErrTooLarge
		}
		if e == nil {
			return b[:len(b)-1], nil
		}
		if e != bufio.ErrBufferFull {
			return nil, e
		}
	}
}
