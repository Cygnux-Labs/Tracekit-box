package agentchannel

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
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
	guest       net.Conn
	signer      net.Conn
	registering bool // a register_run is with the signer: Close waits for its reply (guarded by Server.mu)
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
	RefusedFrameCap    = "frame_cap"   // MaxForwardedFrames forwarded
	RefusedConnections = "connections" // MaxConnections open
	RefusedSigner      = "signer"      // the box's signer channel could not be opened for the connection
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
	ReadRate     int64 // bytes a second this box's connections may send together (DefaultReadRate)
	ReadBurst    int64 // bytes they may send at once (DefaultReadBurst)
	OnLimit      func(string)
	OnRefusal    func(Refusal)

	now          func() time.Time
	ctx          context.Context // ended by Close: a dial or a paced read stops waiting
	cancel       context.CancelFunc
	refused      map[string]*refusalWindow
	mu           sync.Mutex
	connections  map[*activeConn]struct{}
	runs         map[string]runEntry
	reservations int
	approvals    map[string]bool
	frames       float64
	last         time.Time
	bytes        int64
	forwarded    int64
	readTokens   float64   // bytes the box's connections may still read (ReadRate, ReadBurst)
	readLast     time.Time // when readTokens was last refilled
	limitsSeen   map[string]bool
	closed       bool
	done         sync.WaitGroup
}

func New(dial Dial, runID, token string) *Server {
	s := &Server{Dial: dial, BoxRun: runID, BoxToken: token, FrameTimeout: FrameStartTimeout,
		connections: map[*activeConn]struct{}{}, runs: map[string]runEntry{}, approvals: map[string]bool{}, frames: RateBurst, last: time.Now(), limitsSeen: map[string]bool{},
		now: time.Now, refused: map[string]*refusalWindow{}, ReadRate: DefaultReadRate, ReadBurst: DefaultReadBurst,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s
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
	// a connection costs a frame of the rate limit: each one makes the signer set up a connection of its own
	if ok, retry := s.takeToken(); !ok {
		s.refuse(guest, &refusal{code: "quota_exceeded", msg: "agent channel rate limit exceeded", retryMS: retry,
			kind: RefusedRate, reason: fmt.Sprintf("over %d frames a second", RatePerSecond)})
		return
	}
	signer, err := s.Dial(s.ctx)
	if err != nil {
		s.refuse(guest, &refusal{code: "unavailable", msg: "signer channel unavailable", kind: RefusedSigner,
			reason: "the signer channel could not be opened: " + err.Error()})
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
	defer func() { _ = signer.Close() }()
	lastSigner := time.Now() // the last exchange with the signer (channel_open, then each frame's reply)
	gr, sr := bufio.NewReaderSize(pacedConn{Conn: guest, s: s}, 64<<10), bufio.NewReaderSize(signer, 64<<10)
	for {
		_ = guest.SetReadDeadline(time.Now().Add(IdleTimeout))
		first, err := gr.ReadByte()
		if err != nil {
			return
		}
		_ = guest.SetReadDeadline(time.Now().Add(s.FrameTimeout))
		// a frame over the rate is passed over unread: neither kept nor checked
		if ok, retry := s.takeToken(); !ok {
			err := discardLine(gr, first)
			s.refuse(guest, &refusal{code: "quota_exceeded", msg: "agent channel rate limit exceeded", retryMS: retry,
				kind: RefusedRate, reason: fmt.Sprintf("over %d frames a second", RatePerSecond)})
			if err != nil {
				return
			}
			continue
		}
		frame, obj, err := ReadFramePrefix(gr, first)
		method := ""
		if obj != nil {
			method = obj.Str("method")
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
			if r.kind == RefusedRunCap || r.kind == RefusedByteBudget || r.kind == RefusedFrameCap {
				s.limit(r.msg, r.kind)
			}
			r.method = method
			s.refuse(guest, r)
			continue
		}
		reserved = method == "register_run"             // check took a place for it: every way out from here gives it back
		if time.Since(lastSigner) >= SignerQuietLimit { // the signer may have dropped the quiet link: a fresh one
			fresh, err := s.Dial(s.ctx)
			if err != nil {
				s.refuse(guest, &refusal{code: "unavailable", msg: "signer channel unavailable", kind: RefusedSigner,
					reason: "the signer channel could not be opened again: " + err.Error(), method: method})
				return
			}
			s.mu.Lock()
			closing := s.closed
			active.signer = fresh
			s.mu.Unlock()
			_ = signer.Close()
			signer, sr, lastSigner = fresh, bufio.NewReaderSize(fresh, 64<<10), time.Now()
			if closing {
				return
			}
		}
		if method == "register_run" {
			frame = registerFrame(obj) // never longer than the frame it came in (FuzzRegisterFrame)
			s.mu.Lock()
			closing := s.closed
			active.registering = !closing
			s.mu.Unlock()
			if closing {
				return
			}
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
		lastSigner = time.Now()
		err = s.record(method, ans, obj)
		if method == "register_run" {
			reserved = false
			s.mu.Lock()
			active.registering = false
			s.mu.Unlock()
		}
		if err != nil {
			guestWriteError(guest, "quota_exceeded", err.Error(), 0)
			continue
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

// pacedConn is a guest connection whose reads draw on its box's read budget: while the budget is spent a read waits,
// so the guest's bytes stay in vsock and its writer stalls, rather than the daemon reading them at the guest's speed.
// A read reserves its bytes first, from what the budget holds, and gives back what it did not read, so the box's
// connections together never read past the budget. It waits for a reservation of readChunk (or b, if smaller) rather
// than taking a few bytes at a time, which would wake the daemon for every scrap of budget.
type pacedConn struct {
	net.Conn
	s *Server
}

const readChunk = 64 << 10

func (c pacedConn) Read(b []byte) (int, error) {
	take := 0
	for {
		c.s.mu.Lock()
		c.s.refillRead()
		need := float64(min(len(b), readChunk, int(c.s.ReadBurst)))
		if c.s.readTokens >= need {
			take = min(len(b), int(c.s.readTokens))
			c.s.readTokens -= float64(take)
			c.s.mu.Unlock()
			break
		}
		wait := time.Duration((need - c.s.readTokens) / float64(c.s.ReadRate) * float64(time.Second))
		c.s.mu.Unlock()
		t := time.NewTimer(wait + time.Millisecond)
		select {
		case <-t.C:
		case <-c.s.ctx.Done():
			t.Stop()
			return 0, net.ErrClosed
		}
	}
	n, err := c.Conn.Read(b[:take])
	if n < take {
		c.s.mu.Lock()
		c.s.readTokens += float64(take - n)
		c.s.mu.Unlock()
	}
	return n, err
}

// refillRead adds the read budget earned since its last refill (caller holds mu).
func (s *Server) refillRead() {
	now := time.Now()
	if s.readLast.IsZero() {
		s.readTokens = float64(s.ReadBurst)
	} else {
		s.readTokens = min(float64(s.ReadBurst), s.readTokens+now.Sub(s.readLast).Seconds()*float64(s.ReadRate))
	}
	s.readLast = now
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

// check refuses a decoded frame the box's channel must not pass on (nil: pass it), and charges a passed frame to the
// box's limits: every forwarded frame counts towards MaxForwardedFrames, and every one but hello and status (whose
// answers record nothing) towards ByteBudget, as each may reach the signer's content vault.
func (s *Server) check(method string, f *Frame, frame []byte) *refusal {
	forbidden := func(kind, msg string) *refusal { return &refusal{code: "forbidden", msg: msg, kind: kind, reason: msg} }
	s.mu.Lock()
	defer s.mu.Unlock()
	switch method {
	case "register_run", "hello", "status":
	case "approval_get":
		if !s.approvals[f.Str("approval_id")] {
			return forbidden(RefusedApproval, "approval is not owned by this box")
		}
	default:
		if e, ok := s.runs[f.Str("run_id")]; !ok || e.closed {
			return forbidden(RefusedRun, "run is not owned by this box")
		}
	}
	if s.forwarded >= MaxForwardedFrames {
		// a lifetime cap: waiting frees nothing, so no retry_after_ms
		return &refusal{code: "quota_exceeded", msg: "this box's agent channel frame cap is spent: it forwards no more frames",
			kind: RefusedFrameCap, reason: fmt.Sprintf("%d frames forwarded", MaxForwardedFrames)}
	}
	charged := method != "hello" && method != "status"
	if size := int64(len(frame)); charged && s.bytes+size > ByteBudget { // a lifetime budget: no retry_after_ms
		return &refusal{code: "quota_exceeded", msg: "agent channel byte budget exceeded",
			kind: RefusedByteBudget, reason: fmt.Sprintf("%d MiB of frames sent", ByteBudget>>20)}
	}
	if method == "register_run" {
		if len(s.runs)+s.reservations >= MaxRuns {
			r := &refusal{code: "quota_exceeded", msg: "run limit reached", kind: RefusedRunCap,
				reason: fmt.Sprintf("%d runs registered", MaxRuns)}
			if s.reservations > 0 { // a registration in flight may fail and free its place; else none ever frees
				r.retryMS = 1000
			}
			return r
		}
		s.reservations++
	}
	s.forwarded++
	if charged {
		s.bytes += int64(len(frame))
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
func (s *Server) record(method string, ans []byte, req *Frame) error {
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
			id := req.Str("run_id")
			if e, ok := s.runs[id]; ok {
				e.closed = true
				s.runs[id] = e
			}
		}
	}
	return nil
}

// Close stops acceptance and closes every guest stream and signer connection, except that a connection whose
// register_run is with the signer gets CloseReplyWait for the reply (the run it registers then reaches the run table,
// for CloseRuns). Nothing else waits: a long poll's connection closes at once. Then it reports the refusals still
// folded (OnRefusal).
func (s *Server) Close(l net.Listener) {
	closeSigners := func(all bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		for c := range s.connections {
			if c.signer != nil && (all || !c.registering) {
				_ = c.signer.Close()
			}
		}
	}
	s.mu.Lock()
	s.cancel()
	s.closed = true
	s.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}
	s.mu.Lock()
	for c := range s.connections {
		_ = c.guest.Close()
	}
	s.mu.Unlock()
	closeSigners(false)
	handled := make(chan struct{})
	go func() { s.done.Wait(); close(handled) }()
	select {
	case <-handled:
	case <-time.After(CloseReplyWait):
		closeSigners(true)
		<-handled
	}
	s.flushRefusals()
}

// CloseRuns closes the channel's open runs, closeRunsAtOnce at a time; each close ends with ctx.
func (s *Server) CloseRuns(ctx context.Context) []error {
	s.mu.Lock()
	open := map[string]string{}
	for id, e := range s.runs {
		if !e.closed {
			open[id] = e.token
		}
	}
	s.mu.Unlock()
	var mu sync.Mutex
	var failures []error
	var wg sync.WaitGroup
	slots := make(chan struct{}, closeRunsAtOnce)
	for _, id := range slices.Sorted(maps.Keys(open)) {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			mu.Lock()
			failures = append(failures, fmt.Errorf("close channel run %s: %w", id, ctx.Err()))
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(id, token string) {
			defer wg.Done()
			defer func() { <-slots }()
			if err := s.closeRun(ctx, id, token); err != nil {
				mu.Lock()
				failures = append(failures, fmt.Errorf("close channel run %s: %w", id, err))
				mu.Unlock()
			}
		}(id, open[id])
	}
	wg.Wait()
	slices.SortFunc(failures, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })
	return failures
}

// closeRun closes one of the channel's runs on a signer connection of its own, which ends when ctx does.
func (s *Server) closeRun(ctx context.Context, id, token string) error {
	c, err := s.Dial(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	// ctx ends the close by closing its connection (then ctx.Err() is what failed); a signer that never answers is
	// cut off at SignerReplyTimeout
	defer context.AfterFunc(ctx, func() { _ = c.Close() })()
	_ = c.SetDeadline(time.Now().Add(SignerReplyTimeout))
	req, _ := json.Marshal(map[string]any{"method": "close_run", "request_id": rand.Text(), "run_id": id, "run_token": token})
	ans, err := func() ([]byte, error) {
		if _, err := c.Write(append(req, '\n')); err != nil {
			return nil, err
		}
		return readSignerFrame(bufio.NewReader(c))
	}()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	var reply map[string]any
	if json.Unmarshal(ans, &reply) != nil {
		return errors.New("invalid signer reply")
	}
	if refusal, ok := reply["error"]; ok {
		return fmt.Errorf("signer refused: %v", refusal)
	}
	s.mu.Lock()
	e := s.runs[id]
	e.closed = true
	s.runs[id] = e
	s.mu.Unlock()
	return nil
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
