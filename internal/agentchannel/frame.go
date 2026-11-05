// Package agentchannel validates the JSON frames accepted from an in-box agent.
package agentchannel

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	MaxFrame          = 1 << 20
	maxDepth          = 128
	FrameStartTimeout = 10 * time.Second
	// IdleTimeout is how long a guest connection may sit between frames. The signer drops a connection idle for 30 s,
	// and the proxy's signer connection is idle whenever its guest is: closing the guest first, under the signer's
	// limit, makes the agent's client reconnect instead of sending a frame into a connection the signer has dropped.
	IdleTimeout         = 25 * time.Second
	SignerReplyTimeout  = 330 * time.Second
	GuestWriteTimeout   = 10 * time.Second
	RefusalWriteTimeout = time.Second
	// CloseReplyWait is how long a stopping channel waits for signer replies already on their way (a register_run the
	// signer has written, whose run must reach the run table to be closed) before it closes the signer connections. A
	// signer answers in milliseconds; this does not hold a stop for a long poll (approval_wait).
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
	// closeRunsAtOnce bounds the close_run calls a stop makes at once for the channel's open runs.
	closeRunsAtOnce = 8
)

var ErrTooLarge = errors.New("agent channel: frame larger than 1 MiB")
var ErrInvalidFrame = errors.New("agent channel: invalid frame")

// decodeSlots caps the strict checks running at once across every box of this daemon: each is CPU-bound, so more
// than the CPUs only raise the memory held by frames waiting for one.
var decodeSlots = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))

var methods = map[string]bool{
	"hello": true, "register_run": true, "decide": true, "complete": true, "observe": true,
	"model_event": true, "state_write": true, "approval_request": true, "approval_wait": true,
	"approval_consume": true, "approval_get": true, "approval_abandon": true, "constraint_add": true,
	"close_run": true, "tailer_lost": true, "status": true,
}

// Frame is a frame that passed the strict check: its top-level fields as the agent sent them. Nothing below the top
// level is kept.
type Frame struct {
	raw map[string][]byte // each field's value, a slice of the frame
	str map[string]string // the fields whose value is a string, decoded
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
	line := []byte{first}
	if first == '\n' {
		line = line[:0]
		return line, nil, fmt.Errorf("%w: empty frame", ErrInvalidFrame)
	}
	for {
		p, err := r.ReadSlice('\n')
		if len(line)+len(p) > MaxFrame+1 {
			return nil, nil, ErrTooLarge
		}
		line = append(line, p...)
		if err == nil {
			line = line[:len(line)-1]
			break
		}
		if err != bufio.ErrBufferFull {
			if err == io.EOF && len(line) > 0 {
				err = io.ErrUnexpectedEOF
			}
			return nil, nil, err
		}
	}
	if len(line) > MaxFrame {
		return nil, nil, ErrTooLarge
	}
	decodeSlots <- struct{}{}
	f, err := Decode(line)
	<-decodeSlots
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidFrame, err)
	}
	return line, f, nil
}

// Decode applies Tracekit's strict rules (one JSON object, valid UTF-8, no duplicate names at any level, nesting at
// most 128) and the channel's method and field rules. It checks the frame without building its value.
func Decode(data []byte) (*Frame, error) {
	f, err := parseFrame(data)
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
	if k := denied(f, "caller", "on_behalf", "amended", "tool_results", "ext"); k != "" {
		return refuse(RefusedField, "forbidden field", "field "+k+" is not passed")
	}
	if method == "register_run" {
		if k := denied(f, "parent", "principal", "principal_token", "source", "tenant", "analyzes", "replay_of", "investigation"); k != "" {
			return refuse(RefusedField, "forbidden register_run field", "register_run field "+k+" is not passed")
		}
		if a := f.raw["agent"]; len(a) > 0 && a[0] == '{' {
			if agent, err := parseFrame(a); err == nil && reservedAgent(agent.str["name"]) {
				return refuse(RefusedField, "agent name is reserved", "agent name tkbox… is Box's own")
			}
		}
	}
	if method == "observe" {
		if s := f.str["source"]; len(s) >= 6 && s[:6] == "tkbox." {
			return refuse(RefusedField, "tkbox observe source is reserved", "observe source tkbox.* is Box's own")
		}
	}
	return f, nil
}

// reservedAgent reports whether an agent run's name could be taken for Box's own (its runs are named tkbox, or the
// operator's --agent).
func reservedAgent(name string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(name)), "tkbox")
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

// parseFrame checks that data is one strict JSON object and returns its top-level fields.
func parseFrame(data []byte) (*Frame, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	s := &scanner{b: data}
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

// scanner checks RFC 8259 JSON in place: it keeps each object's names while that object is read, for the duplicate
// check, and nothing else.
type scanner struct {
	b []byte
	i int
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
		_, err := s.str()
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

// object checks the object at s.i; with top, it records the object's fields there.
func (s *scanner) object(depth int, top *Frame) error {
	s.i++ // {
	var names [][]byte
	var index map[string]bool // past a few names, a map
	if s.ws(); s.i < len(s.b) && s.b[s.i] == '}' {
		s.i++
		return nil
	}
	for {
		if s.ws(); s.i >= len(s.b) || s.b[s.i] != '"' {
			return errors.New("object key is not a string")
		}
		name, err := s.str()
		if err != nil {
			return err
		}
		if index != nil {
			if index[string(name)] {
				return fmt.Errorf("duplicate key %q", name)
			}
			index[string(name)] = true
		} else {
			for _, n := range names {
				if bytes.Equal(n, name) {
					return fmt.Errorf("duplicate key %q", name)
				}
			}
			if names = append(names, name); len(names) > 16 {
				index = make(map[string]bool, 2*len(names))
				for _, n := range names {
					index[string(n)] = true
				}
				names = nil
			}
		}
		if s.ws(); s.i >= len(s.b) || s.b[s.i] != ':' {
			return errSyntax
		}
		s.i++
		s.ws()
		start := s.i
		if top != nil && s.i < len(s.b) && s.b[s.i] == '"' {
			v, err := s.str()
			if err != nil {
				return err
			}
			top.str[string(name)] = string(v)
		} else if err := s.value(depth + 1); err != nil {
			return err
		}
		if top != nil {
			top.raw[string(name)] = s.b[start:s.i]
		}
		if s.ws(); s.i >= len(s.b) {
			return errSyntax
		}
		switch s.b[s.i] {
		case ',':
			s.i++
		case '}':
			s.i++
			return nil
		default:
			return errSyntax
		}
	}
}

// str checks the string at s.i and returns its value: a slice of the frame when it has no escapes, else decoded as
// encoding/json decodes it (an unpaired surrogate is U+FFFD).
func (s *scanner) str() ([]byte, error) {
	s.i++ // "
	start := s.i
	for s.i < len(s.b) {
		switch c := s.b[s.i]; {
		case c == '"':
			v := s.b[start:s.i]
			s.i++
			return v, nil
		case c == '\\':
			return s.escaped(start)
		case c < 0x20:
			return nil, errors.New("control character in string")
		default:
			s.i++
		}
	}
	return nil, errSyntax
}

// escaped finishes a string that has an escape at s.i, decoding it from start.
func (s *scanner) escaped(start int) ([]byte, error) {
	out := append([]byte(nil), s.b[start:s.i]...)
	for s.i < len(s.b) {
		c := s.b[s.i]
		switch {
		case c == '"':
			s.i++
			return out, nil
		case c < 0x20:
			return nil, errors.New("control character in string")
		case c != '\\':
			out = append(out, c)
			s.i++
			continue
		}
		if s.i+1 >= len(s.b) {
			return nil, errSyntax
		}
		switch e := s.b[s.i+1]; e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r := hex4(s.b[s.i:])
			if r < 0 {
				return nil, errors.New("invalid \\u escape")
			}
			s.i += 6
			if utf16.IsSurrogate(r) {
				if d := utf16.DecodeRune(r, hex4(s.b[s.i:])); d != utf8.RuneError {
					s.i += 6
					r = d
				} else {
					r = utf8.RuneError
				}
			}
			out = utf8.AppendRune(out, r)
			continue
		default:
			return nil, errors.New("invalid escape in string")
		}
		s.i += 2
	}
	return nil, errSyntax
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
