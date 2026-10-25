// Package proto is the wire contract between the host (tkbox) and the guest agent (tkbox-guest): the frame format
// used on the agent RPC port and the boot-config port, the operations, and their JSON payloads.
//
// A frame is [type u8][len u32 big-endian][payload]. A payload is at most MaxFrame bytes. One vsock connection carries
// exactly one request and its response; either side closes it when done.
package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Frame types.
const (
	TypeJSON     byte = 0 // a JSON request, response header or summary
	TypeStdin    byte = 1 // host → guest data (exec stdin, write_file content)
	TypeStdout   byte = 2 // guest → host data (exec stdout, read_file content, diff patch)
	TypeStderr   byte = 3 // guest → host exec stderr
	TypeExit     byte = 4 // JSON ExitStatus; the last frame of a successful exchange
	TypeError    byte = 5 // JSON Error; the last frame of a failed exchange
	TypeStdinEOF byte = 6 // host → guest: no more TypeStdin frames (empty payload)
	TypeSignal   byte = 7 // host → guest: JSON Signal for a running exec
)

// MaxFrame is the largest payload of one frame.
const MaxFrame = 1 << 20

// vsock ports. The host dials the guest on PortAgent (Firecracker's "CONNECT <port>\n" handshake on the vsock UDS);
// the guest dials the host (CID 2) on PortEgress and PortConfig, which Firecracker forwards to "<uds>_<port>".
const (
	PortAgent  uint32 = 1024
	PortEgress uint32 = 1025
	PortConfig uint32 = 1026
)

// ErrFrameTooLarge is returned for a frame whose declared length exceeds MaxFrame.
var ErrFrameTooLarge = errors.New("proto: frame larger than 1 MiB")

// Frame is one decoded frame.
type Frame struct {
	Type    byte
	Payload []byte
}

// WriteFrame writes one frame. Payloads over MaxFrame are refused (split data before writing).
func WriteFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > MaxFrame {
		return ErrFrameTooLarge
	}
	var hdr [5]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	// one Write so a frame is never interleaved with another writer's frame on the same conn
	buf := make([]byte, 0, len(hdr)+len(payload))
	buf = append(buf, hdr[:]...)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame. io.EOF means the peer closed cleanly between frames; io.ErrUnexpectedEOF means it closed
// mid-frame.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > MaxFrame {
		return Frame{}, ErrFrameTooLarge
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	return Frame{Type: hdr[0], Payload: p}, nil
}

// WriteJSON marshals v and writes it as one frame of type typ.
func WriteJSON(w io.Writer, typ byte, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("proto: marshal: %w", err)
	}
	return WriteFrame(w, typ, b)
}

// Decode unmarshals a frame's JSON payload strictly (unknown fields are an error).
func (f Frame) Decode(v any) error {
	dec := json.NewDecoder(bytes.NewReader(f.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("proto: decode frame type %d: %w", f.Type, err)
	}
	if dec.More() {
		return fmt.Errorf("proto: decode frame type %d: trailing data", f.Type)
	}
	return nil
}

// AsError decodes a TypeError frame into an *Error.
func (f Frame) AsError() *Error {
	var e Error
	if err := json.Unmarshal(f.Payload, &e); err != nil || e.Code == "" {
		return &Error{Code: CodeInternal, Message: "malformed error frame"}
	}
	return &e
}

// ChunkWriter turns Write calls into frames of type Type, each at most MaxFrame bytes.
type ChunkWriter struct {
	W    io.Writer
	Type byte
}

func (c ChunkWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		k := min(len(p), MaxFrame)
		if err := WriteFrame(c.W, c.Type, p[:k]); err != nil {
			return n, err
		}
		n += k
		p = p[k:]
	}
	return n, nil
}
