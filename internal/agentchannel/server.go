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
	"strings"
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

// Refusal kinds, as a box's channel.refused events name them.
const (
	RefusedFrame       = "frame"       // not one strict JSON object, or over MaxFrame
	RefusedMethod      = "method"      // a method the channel doesn't pass
	RefusedField       = "field"       // a field the channel doesn't pass
	RefusedRun         = "run"         // a run this channel did not register, or one it closed
	RefusedApproval    = "approval"    // an approval this channel did not ask for
	RefusedRate        = "rate"        // over RatePerSecond frames a second
	RefusedRunCap      = "run_cap"     // MaxRuns reached
	RefusedByteBudget  = "byte_budget" // ByteBudget spent
	RefusedConnections = "connections" // MaxConnections open
)

// Refusal is one channel.refused event. A box gets at most one event of a kind a second: the refusals in between are
// counted into the kind's next event (Folded), and Close reports the count left over.
type Refusal struct {
	Kind   string // Refused*
	Method string // the refused frame's method when it is a plain name (a-z, 0-9, _; at most 64 bytes), else ""
	Reason string // the channel's own words, never the frame's content; "" when the event only reports Folded
	Folded int    // refusals of this kind since its last event, besides this one
}

// refusal is a frame the channel answers with an error: msg is what the agent reads (it may quote the agent's own
// frame); kind, reason and method are what the box's event says.
type refusal struct {
	code    string
	msg     string
	retryMS int64
	kind    string
	reason  string
	method  string
}

func (e *refusal) Error() string { return e.msg }

type refusalWindow struct {
	last   time.Time
	folded int
}

// Server scopes one box's guest connections to its dedicated signer channel.
type Server struct {
	Dial         Dial
	BoxRun       string
	BoxToken     string
	FrameTimeout time.Duration
	OnLimit      func(string)
	OnRefusal    func(Refusal)

	now          func() time.Time
	refused      map[string]*refusalWindow
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
		connections: map[*activeConn]struct{}{}, runs: map[string]runEntry{}, approvals: map[string]bool{}, frames: RateBurst, last: time.Now(), limitsSeen: map[string]bool{},
		now: time.Now, refused: map[string]*refusalWindow{}}
}

func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.closed || len(s.connections) >= MaxConnections {
			closed := s.closed
			s.mu.Unlock()
			if !closed {
				s.noteRefusal(RefusedConnections, "", fmt.Sprintf("%d connections already open", MaxConnections))
			}
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
		method, _ := obj["method"].(string)
		if ok, retry := s.takeToken(); !ok {
			s.refuse(guest, &refusal{code: "quota_exceeded", msg: "agent channel rate limit exceeded", retryMS: retry,
				kind: RefusedRate, reason: fmt.Sprintf("over %d frames a second", RatePerSecond), method: method})
			if err != nil {
				return
			}
			continue
		}
		if errors.Is(err, ErrTooLarge) {
			s.noteRefusal(RefusedFrame, "", "a frame over 1 MiB; connection closed")
			return
		}
		if errors.Is(err, ErrInvalidFrame) {
			r := &refusal{code: "forbidden", msg: err.Error(), kind: RefusedFrame, reason: "not one strict JSON object"}
			var why *refusal
			if errors.As(err, &why) {
				r.kind, r.reason, r.method = why.kind, why.reason, why.method
			}
			s.refuse(guest, r)
			continue
		}
		if err != nil {
			return
		}
		if r := s.check(method, obj, frame); r != nil {
			if r.kind == RefusedRunCap || r.kind == RefusedByteBudget {
				s.limit(r.msg, r.kind)
			}
			r.method = method
			s.refuse(guest, r)
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

// refuse notes r for the box's events, then answers the agent with it.
func (s *Server) refuse(guest net.Conn, r *refusal) {
	s.noteRefusal(r.kind, r.method, r.reason)
	guestWriteError(guest, r.code, r.msg, r.retryMS)
}

// noteRefusal calls OnRefusal for the first refusal of a kind in a second, folding the rest into the kind's next call.
func (s *Server) noteRefusal(kind, method, reason string) {
	s.mu.Lock()
	w := s.refused[kind]
	if w == nil {
		w = &refusalWindow{}
		s.refused[kind] = w
	}
	now := s.now()
	if !w.last.IsZero() && now.Sub(w.last) < time.Second {
		w.folded++
		s.mu.Unlock()
		return
	}
	ev := Refusal{Kind: kind, Method: plainName(method), Reason: reason, Folded: w.folded}
	w.last, w.folded = now, 0
	cb := s.OnRefusal
	s.mu.Unlock()
	if cb != nil {
		cb(ev)
	}
}

// flushRefusals reports the refusals folded since each kind's last event.
func (s *Server) flushRefusals() {
	s.mu.Lock()
	var left []Refusal
	for kind, w := range s.refused {
		if w.folded > 0 {
			left = append(left, Refusal{Kind: kind, Folded: w.folded})
			w.folded = 0
		}
	}
	cb := s.OnRefusal
	s.mu.Unlock()
	slices.SortFunc(left, func(a, b Refusal) int { return strings.Compare(a.Kind, b.Kind) })
	for _, r := range left {
		if cb != nil {
			cb(r)
		}
	}
}

// plainName is a method name fit for an event: the agent's own text only when it is a plain identifier.
func plainName(s string) string {
	if len(s) > 64 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return ""
		}
	}
	return s
}

func (s *Server) limit(reason, kind string) {
	s.mu.Lock()
	first := !s.limitsSeen[kind]
	s.limitsSeen[kind] = true
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

// check refuses a decoded frame the box's channel must not pass on (nil: pass it).
func (s *Server) check(method string, m map[string]any, frame []byte) *refusal {
	forbidden := func(kind, msg string) *refusal { return &refusal{code: "forbidden", msg: msg, kind: kind, reason: msg} }
	if method == "register_run" {
		for _, k := range []string{"parent", "principal", "principal_token", "caller", "source", "tenant", "analyzes", "replay_of", "investigation", "ext", "box"} {
			if _, ok := m[k]; ok {
				return forbidden(RefusedField, "forbidden register_run field "+k)
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.runs)+s.reservations >= MaxRuns {
			return &refusal{code: "quota_exceeded", msg: "run limit reached", retryMS: 1000, kind: RefusedRunCap,
				reason: fmt.Sprintf("%d runs registered", MaxRuns)}
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
			return forbidden(RefusedApproval, "approval is not owned by this box")
		}
		return nil
	}
	rid, _ := m["run_id"].(string)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.runs[rid]
	if !ok || e.closed {
		return forbidden(RefusedRun, "run is not owned by this box")
	}
	if method == "model_event" || method == "complete" || method == "observe" {
		size := int64(len(frame))
		if s.bytes+size > ByteBudget {
			return &refusal{code: "quota_exceeded", msg: "agent channel byte budget exceeded", retryMS: 1000,
				kind: RefusedByteBudget, reason: fmt.Sprintf("%d MiB of content sent", ByteBudget>>20)}
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

// Close stops acceptance and closes all active guest streams before callers close the box run, then reports the
// refusals still folded (OnRefusal).
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
	s.flushRefusals()
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
