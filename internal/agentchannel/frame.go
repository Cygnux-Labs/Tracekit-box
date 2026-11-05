// Package agentchannel validates the JSON frames accepted from an in-box agent.
package agentchannel

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	MaxFrame          = 1 << 20
	maxDepth          = 128
	FrameStartTimeout = 10 * time.Second
	// IdleTimeout is how long a guest connection may sit between frames.
	IdleTimeout = 15 * time.Second
	// SignerQuietLimit is how long a connection's signer link may go without an exchange before the proxy replaces it
	// for the next frame: the signer drops a connection silent for 30 s, and frames the channel refuses keep the guest
	// connection alive without reaching the signer.
	SignerQuietLimit    = 25 * time.Second
	SignerReplyTimeout  = 330 * time.Second
	GuestWriteTimeout   = 10 * time.Second
	RefusalWriteTimeout = time.Second
	// CloseReplyWait is how long a stopping channel waits for the reply to a register_run already with the signer
	// (the run it registers must reach the run table to be closed) before it closes that signer connection. A signer
	// answers it in milliseconds; every other connection, a long poll's (approval_wait) included, is closed at once.
	CloseReplyWait = 2 * time.Second
	MaxConnections = 16
	RatePerSecond  = 50
	RateBurst      = 200
	MaxRuns        = 256
	ByteBudget     = 64 << 20
	// MaxForwardedFrames caps what one box forwards to the signer over its life, hello and status included (each
	// other frame becomes at least one signed record). A long coding session sends a few frames per tool call and one
	// model_event per transcript line, tens of thousands; this is about 20 times that, and at RatePerSecond an agent
	// needs almost six hours of nonstop sending to reach it.
	MaxForwardedFrames = 1 << 20
	// DefaultReadRate and DefaultReadBurst pace the bytes a box's channel connections may send the daemon together (a
	// second, and at once): past them a read waits, and vsock backpressure stalls the guest's writer. A coding agent's
	// hook and tailer send a few KiB per tool call and model turn; their largest frames (a big Write's arguments, a long
	// tool result) stay under MaxFrame, and a box sends at most ByteBudget of them in its life, which this rate passes in
	// about a minute. A box flooding its channel is held to it instead of keeping daemon cores busy.
	DefaultReadRate  = 1 << 20
	DefaultReadBurst = 8 << 20
	// closeRunsAtOnce bounds the close_run calls a stop makes at once for the channel's open runs.
	closeRunsAtOnce = 8
)

var ErrTooLarge = errors.New("agent channel: frame larger than 1 MiB")
var ErrInvalidFrame = errors.New("agent channel: invalid frame")

// decodeSlots caps the strict checks running at once across every box of this daemon at half the CPUs: each is
// CPU-bound, so agents flooding frames keep half the host for everything else, and more checks at once would only
// raise the memory held by frames waiting for one.
var decodeSlots = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)/2))

var methods = map[string]bool{
	"hello": true, "register_run": true, "decide": true, "complete": true, "observe": true,
	"model_event": true, "state_write": true, "approval_request": true, "approval_wait": true,
	"approval_consume": true, "approval_get": true, "approval_abandon": true, "constraint_add": true,
	"close_run": true, "tailer_lost": true, "status": true,
}

// Field rules: the top-level fields refused in every frame, and in a register_run (which also refuses box, check).
var (
	deniedFields   = []string{"caller", "on_behalf", "amended", "tool_results", "ext"}
	deniedRegister = []string{"parent", "principal", "principal_token", "caller", "source", "tenant", "analyzes",
		"replay_of", "investigation", "ext", "box"}
)

// frameFields are the top-level fields the channel's rules read: a Frame records these and no other.
var frameFields = func() map[string]bool {
	m := map[string]bool{"method": true, "run_id": true, "approval_id": true, "request_id": true, "agent": true,
		"source": true}
	for _, k := range append(deniedFields, deniedRegister...) {
		m[k] = true
	}
	return m
}()

var agentFields = map[string]bool{"name": true}

// Frame is a frame that passed the strict check: the top-level fields the channel's rules read (frameFields), as the
// agent sent them. Nothing else of the frame is kept.
type Frame struct {
	raw   map[string][]byte // each field's value, a slice of the frame
	str   map[string]string // the fields whose value is a string, decoded
	agent string            // a register_run's agent name
}

// Has reports whether the frame has field k.
func (f *Frame) Has(k string) bool { _, ok := f.raw[k]; return ok }

// Str is field k's string value ("" when it is absent or not a string).
func (f *Frame) Str(k string) string { return f.str[k] }

// Raw is field k's value as sent (nil when absent).
func (f *Frame) Raw(k string) []byte { return f.raw[k] }

// ReadFrame reads one newline-delimited object, preserving its bytes for forwarding.
func ReadFrame(r *bufio.Reader) ([]byte, *Frame, error) {
	first, err := r.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	return ReadFramePrefix(r, first)
}

// ReadFramePrefix continues a frame after its first byte was read under the idle deadline.
func ReadFramePrefix(r *bufio.Reader, first byte) ([]byte, *Frame, error) {
	line, err := readLine(r, first)
	if err != nil {
		return nil, nil, err
	}
	f, err := DecodeLimited(line)
	if err != nil {
		return nil, nil, err
	}
	return line, f, nil
}

// readLine reads the rest of a frame's line, without its newline.
func readLine(r *bufio.Reader, first byte) ([]byte, error) {
	line := []byte{first}
	if first == '\n' {
		return line[:0], fmt.Errorf("%w: empty frame", ErrInvalidFrame)
	}
	for {
		p, err := r.ReadSlice('\n')
		if len(line)+len(p) > MaxFrame+1 {
			return nil, ErrTooLarge
		}
		line = append(line, p...)
		if err == nil {
			return line[:len(line)-1], nil
		}
		if err != bufio.ErrBufferFull {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
}

// discardLine reads the rest of a frame's line without keeping it (a frame refused before it is read).
func discardLine(r *bufio.Reader, first byte) error {
	n := 1
	for first != '\n' {
		p, err := r.ReadSlice('\n')
		if n += len(p); n > MaxFrame+1 {
			return ErrTooLarge
		}
		if err == nil {
			return nil
		}
		if err != bufio.ErrBufferFull {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

// DecodeLimited is Decode under the daemon-wide cap on checks running at once, its error wrapping ErrInvalidFrame.
func DecodeLimited(line []byte) (*Frame, error) {
	decodeSlots <- struct{}{}
	f, err := Decode(line)
	<-decodeSlots
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFrame, err)
	}
	return f, nil
}

// Decode applies Tracekit's strict rules (one JSON object, valid UTF-8, no duplicate names at any level, nesting at
// most 128) and the channel's method and field rules. It checks the frame without building its value.
func Decode(data []byte) (*Frame, error) {
	f, err := parseFrame(data, frameFields)
	if err != nil {
		return nil, err
	}
	method, ok := f.str["method"]
	refuse := func(kind, msg, reason string) (*Frame, error) {
		return nil, &refusal{code: "forbidden", msg: msg, kind: kind, reason: reason, method: method}
	}
	if !ok || !methods[method] {
		return refuse(RefusedMethod, fmt.Sprintf("method %q is not allowed", method), "method not allowed")
	}
	if k := denied(f, deniedFields...); k != "" {
		return refuse(RefusedField, "forbidden field", "field "+k+" is not passed")
	}
	if method == "register_run" {
		if k := denied(f, deniedRegister...); k != "" {
			return refuse(RefusedField, "forbidden register_run field", "register_run field "+k+" is not passed")
		}
		if a := f.raw["agent"]; len(a) > 0 && a[0] == '{' {
			agent, err := parseFrame(a, agentFields)
			if err != nil {
				return nil, err
			}
			f.agent = agent.str["name"]
		}
		if !plainASCII(f.agent, "._ -") {
			return refuse(RefusedField, "agent name may hold only letters, digits, '.', '_', ' ' and '-'",
				"agent name not plain")
		}
		if reservedName(f.agent) {
			return refuse(RefusedField, "agent name is reserved", "agent name tkbox… is Box's own")
		}
	}
	if method == "observe" {
		if src := f.str["source"]; !plainASCII(src, "._ -:/") || reservedName(src) {
			return refuse(RefusedField, "observe source may hold only letters, digits, '.', '_', ' ', '-', ':' and '/', and tkbox… is Box's own",
				"observe source not plain, or tkbox… (Box's own)")
		}
	}
	return f, nil
}

// plainASCII reports whether s holds only ASCII letters, digits and the punctuation in punct: no lookalike (a
// zero-width or fullwidth character, a one-dot leader, a Cyrillic letter) can then read as a name Box reserves.
func plainASCII(s, punct string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.IndexByte(punct, c) >= 0:
		default:
			return false
		}
	}
	return true
}

// reservedName reports whether a plain name reads as Box's own: tkbox… in any case, past leading spaces.
func reservedName(s string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "tkbox")
}

// registerFrame is the register_run the channel forwards: only the agent's request_id and agent, copied as sent (so
// it is never longer than the frame they came in).
func registerFrame(f *Frame) []byte {
	b := []byte(`{"method":"register_run"`)
	for _, k := range []string{"request_id", "agent"} {
		if v := f.raw[k]; v != nil {
			b = append(append(b, `,"`+k+`":`...), v...)
		}
	}
	return append(b, '}')
}

// denied is the first of keys that f holds, or "".
func denied(f *Frame, keys ...string) string {
	for _, k := range keys {
		if f.Has(k) {
			return k
		}
	}
	return ""
}

var errSyntax = errors.New("not valid JSON")

// parseFrame checks that data is one strict JSON object and returns the top-level fields keep names.
func parseFrame(data []byte, keep map[string]bool) (*Frame, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	s := &scanner{b: data, keep: keep}
	s.ws()
	if s.i >= len(s.b) || s.b[s.i] != '{' {
		return nil, errors.New("frame must be a JSON object")
	}
	f := &Frame{raw: map[string][]byte{}, str: map[string]string{}}
	if err := s.object(0, f); err != nil {
		return nil, err
	}
	if s.ws(); s.i != len(s.b) {
		return nil, errors.New("trailing JSON data")
	}
	return f, nil
}

// span is an object name: bytes start:end of the frame, or of the scanner's arena when start has arenaBit (a name
// with escapes, decoded).
type span struct{ start, end uint32 }

const arenaBit = 1 << 31

// scanner checks RFC 8259 JSON in place. For the duplicate check it keeps the names of the objects it is inside, one
// reused list per depth; nothing else of a value is kept.
type scanner struct {
	b     []byte
	i     int
	keep  map[string]bool
	names [][]span // names of the open object at each depth
	arena []byte   // decoded names that had escapes
}

func (s *scanner) name(n span) []byte {
	if n.start&arenaBit != 0 {
		return s.arena[n.start&^arenaBit : n.end]
	}
	return s.b[n.start:n.end]
}

func (s *scanner) ws() {
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return
		}
	}
}

// value checks the value at s.i, at nesting depth (the frame's object is 0).
func (s *scanner) value(depth int) error {
	if depth > maxDepth {
		return errors.New("JSON nesting exceeds 128")
	}
	if s.ws(); s.i >= len(s.b) {
		return errSyntax
	}
	switch s.b[s.i] {
	case '{':
		return s.object(depth, nil)
	case '[':
		s.i++
		if s.ws(); s.i < len(s.b) && s.b[s.i] == ']' {
			s.i++
			return nil
		}
		for {
			if err := s.value(depth + 1); err != nil {
				return err
			}
			if s.ws(); s.i >= len(s.b) {
				return errSyntax
			}
			switch s.b[s.i] {
			case ',':
				s.i++
			case ']':
				s.i++
				return nil
			default:
				return errSyntax
			}
		}
	case '"':
		_, _, _, err := s.str()
		return err
	case 't':
		return s.lit("true")
	case 'f':
		return s.lit("false")
	case 'n':
		return s.lit("null")
	}
	return s.number()
}

// object checks the object at s.i; with top, it records there the fields s.keep names.
func (s *scanner) object(depth int, top *Frame) error {
	s.i++ // {
	if s.ws(); s.i < len(s.b) && s.b[s.i] == '}' {
		s.i++
		return nil
	}
	for len(s.names) <= depth {
		s.names = append(s.names, nil)
	}
	names := s.names[depth][:0]
	for {
		if s.ws(); s.i >= len(s.b) || s.b[s.i] != '"' {
			return errors.New("object key is not a string")
		}
		start, end, escaped, err := s.str()
		if err != nil {
			return err
		}
		n := span{uint32(start), uint32(end)}
		if escaped {
			a := len(s.arena)
			s.arena = unescape(s.arena, s.b[start:end])
			n = span{uint32(a) | arenaBit, uint32(len(s.arena))}
		}
		if len(names) < 16 { // past 16 names, a sort finds duplicates when the object ends
			for _, m := range names {
				if bytes.Equal(s.name(m), s.name(n)) {
					return fmt.Errorf("duplicate key %q", s.name(n))
				}
			}
		}
		if len(names) == cap(names) { // doubling: append's 1.25x growth of a long list allocates four times its size
			names = append(make([]span, 0, max(16, 2*cap(names))), names...)
		}
		names = append(names, n)
		if s.ws(); s.i >= len(s.b) || s.b[s.i] != ':' {
			return errSyntax
		}
		s.i++
		s.ws()
		vstart := s.i
		if err := s.value(depth + 1); err != nil {
			return err
		}
		if top != nil && s.keep[string(s.name(n))] {
			k := string(s.name(n))
			top.raw[k] = s.b[vstart:s.i]
			if s.b[vstart] == '"' {
				top.str[k] = string(unescape(nil, s.b[vstart+1:s.i-1]))
			}
		}
		if s.ws(); s.i >= len(s.b) {
			return errSyntax
		}
		switch s.b[s.i] {
		case ',':
			s.i++
		case '}':
			s.i++
			if len(names) > 16 {
				slices.SortFunc(names, func(a, b span) int { return bytes.Compare(s.name(a), s.name(b)) })
				for i := 1; i < len(names); i++ {
					if bytes.Equal(s.name(names[i-1]), s.name(names[i])) {
						return fmt.Errorf("duplicate key %q", s.name(names[i]))
					}
				}
			}
			s.names[depth] = names[:0] // the list's room is reused by the next object at this depth
			return nil
		default:
			return errSyntax
		}
	}
}

// str checks the string at s.i and returns its body's bounds in the frame (inside the quotes) and whether it has
// escapes. It decodes nothing.
func (s *scanner) str() (start, end int, escaped bool, err error) {
	s.i++ // "
	start = s.i
	for s.i < len(s.b) {
		switch c := s.b[s.i]; {
		case c == '"':
			end = s.i
			s.i++
			return start, end, escaped, nil
		case c < 0x20:
			return 0, 0, false, errors.New("control character in string")
		case c != '\\':
			s.i++
			continue
		}
		escaped = true
		if s.i+1 >= len(s.b) {
			return 0, 0, false, errSyntax
		}
		switch s.b[s.i+1] {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			s.i += 2
		case 'u':
			if hex4(s.b[s.i:]) < 0 {
				return 0, 0, false, errors.New("invalid \\u escape")
			}
			s.i += 6
		default:
			return 0, 0, false, errors.New("invalid escape in string")
		}
	}
	return 0, 0, false, errSyntax
}

// unescape appends the value of a checked string body to dst, as encoding/json decodes it (an unpaired surrogate is
// U+FFFD).
func unescape(dst, body []byte) []byte {
	for i := 0; i < len(body); {
		c := body[i]
		if c != '\\' {
			dst = append(dst, c)
			i++
			continue
		}
		switch e := body[i+1]; e {
		case 'b':
			dst = append(dst, '\b')
		case 'f':
			dst = append(dst, '\f')
		case 'n':
			dst = append(dst, '\n')
		case 'r':
			dst = append(dst, '\r')
		case 't':
			dst = append(dst, '\t')
		case 'u':
			r := hex4(body[i:])
			i += 6
			if utf16.IsSurrogate(r) {
				if d := utf16.DecodeRune(r, hex4(body[i:])); d != utf8.RuneError {
					i += 6
					r = d
				} else {
					r = utf8.RuneError
				}
			}
			dst = utf8.AppendRune(dst, r)
			continue
		default: // " \ /
			dst = append(dst, e)
		}
		i += 2
	}
	return dst
}

// hex4 is the rune of a \uXXXX escape at the start of b, or -1.
func hex4(b []byte) rune {
	if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
		return -1
	}
	var r rune
	for _, c := range b[2:6] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return -1
		}
		r = r*16 + rune(c)
	}
	return r
}

func (s *scanner) lit(word string) error {
	if !bytes.HasPrefix(s.b[s.i:], []byte(word)) {
		return errSyntax
	}
	s.i += len(word)
	return nil
}

func (s *scanner) number() error {
	if s.i < len(s.b) && s.b[s.i] == '-' {
		s.i++
	}
	switch {
	case s.i < len(s.b) && s.b[s.i] == '0':
		s.i++
	case s.digits() == 0:
		return errSyntax
	}
	if s.i < len(s.b) && s.b[s.i] == '.' {
		s.i++
		if s.digits() == 0 {
			return errSyntax
		}
	}
	if s.i < len(s.b) && (s.b[s.i] == 'e' || s.b[s.i] == 'E') {
		s.i++
		if s.i < len(s.b) && (s.b[s.i] == '+' || s.b[s.i] == '-') {
			s.i++
		}
		if s.digits() == 0 {
			return errSyntax
		}
	}
	return nil
}

func (s *scanner) digits() int {
	n := 0
	for s.i < len(s.b) && s.b[s.i] >= '0' && s.b[s.i] <= '9' {
		s.i++
		n++
	}
	return n
}
