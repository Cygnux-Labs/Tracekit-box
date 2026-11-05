// Package agentchannel validates the JSON frames accepted from an in-box agent.
package agentchannel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"
)

const (
	MaxFrame            = 1 << 20
	maxDepth            = 128
	FrameStartTimeout   = 10 * time.Second
	IdleTimeout         = 300 * time.Second
	SignerReplyTimeout  = 330 * time.Second
	GuestWriteTimeout   = 10 * time.Second
	RefusalWriteTimeout = time.Second
	MaxConnections      = 16
	RatePerSecond       = 50
	RateBurst           = 200
	MaxRuns             = 256
	ByteBudget          = 64 << 20
)

var ErrTooLarge = errors.New("agent channel: frame larger than 1 MiB")
var ErrInvalidFrame = errors.New("agent channel: invalid frame")

var methods = map[string]bool{
	"hello": true, "register_run": true, "decide": true, "complete": true, "observe": true,
	"model_event": true, "state_write": true, "approval_request": true, "approval_wait": true,
	"approval_consume": true, "approval_get": true, "approval_abandon": true, "constraint_add": true,
	"close_run": true, "tailer_lost": true, "status": true,
}

// ReadFrame reads one newline-delimited object, preserving its bytes for forwarding.
func ReadFrame(r *bufio.Reader) ([]byte, map[string]any, error) {
	first, err := r.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	return ReadFramePrefix(r, first)
}

// ReadFramePrefix continues a frame after its first byte was read under the idle deadline.
func ReadFramePrefix(r *bufio.Reader, first byte) ([]byte, map[string]any, error) {
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
	if !utf8.Valid(line) {
		return nil, nil, fmt.Errorf("%w: invalid UTF-8", ErrInvalidFrame)
	}
	m, err := Decode(line)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidFrame, err)
	}
	return line, m, nil
}

// Decode applies strict structural checks while retaining numeric literals exactly.
func Decode(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := value(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return nil, errors.New("frame must be a JSON object")
	}
	method, ok := m["method"].(string)
	if !ok || !methods[method] {
		return nil, fmt.Errorf("method %q is not allowed", method)
	}
	if denied(m, "caller", "on_behalf", "amended", "tool_results", "ext") {
		return nil, errors.New("forbidden field")
	}
	if method == "register_run" && denied(m, "parent", "principal", "principal_token", "source", "tenant", "analyzes", "replay_of", "investigation") {
		return nil, errors.New("forbidden register_run field")
	}
	if method == "observe" {
		if s, _ := m["source"].(string); len(s) >= 6 && s[:6] == "tkbox." {
			return nil, errors.New("tkbox observe source is reserved")
		}
	}
	return m, nil
}

func denied(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func value(d *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("JSON nesting exceeds 128")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			m := map[string]any{}
			for d.More() {
				kt, err := d.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, found := m[k]; found {
					return nil, fmt.Errorf("duplicate key %q", k)
				}
				v, err := value(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			_, err := d.Token()
			return m, err
		case '[':
			a := []any{}
			for d.More() {
				v, err := value(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := d.Token()
			return a, err
		}
	case json.Number, string, bool, nil:
		return x, nil
	}
	return nil, errors.New("invalid JSON token")
}
