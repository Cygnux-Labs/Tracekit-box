package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, TypeJSON, ExecRequest{Op: OpExec, Argv: []string{"echo", "hi"}}); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, TypeStdout, []byte("out")); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&buf)
	if err != nil || f.Type != TypeJSON {
		t.Fatalf("frame %v %v", f, err)
	}
	var req ExecRequest
	if err := f.Decode(&req); err != nil || req.Argv[1] != "hi" {
		t.Fatalf("decode %v %v", req, err)
	}
	f, err = ReadFrame(&buf)
	if err != nil || f.Type != TypeStdout || string(f.Payload) != "out" {
		t.Fatalf("frame %v %v", f, err)
	}
	if _, err := ReadFrame(&buf); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestFrameLimits(t *testing.T) {
	if err := WriteFrame(io.Discard, TypeStdout, make([]byte, MaxFrame+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized write: %v", err)
	}
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[1:], MaxFrame+1)
	if _, err := ReadFrame(bytes.NewReader(hdr[:])); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized read: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{2, 0, 0, 0, 9, 'x'})); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated: %v", err)
	}
}

func TestDecodeStrict(t *testing.T) {
	f := Frame{Type: TypeJSON, Payload: []byte(`{"op":"ping","evil":1}`)}
	var p PingRequest
	if err := f.Decode(&p); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestChunkWriter(t *testing.T) {
	var buf bytes.Buffer
	data := bytes.Repeat([]byte("a"), MaxFrame*2+10)
	if n, err := (ChunkWriter{W: &buf, Type: TypeStdout}).Write(data); err != nil || n != len(data) {
		t.Fatal(n, err)
	}
	var got []byte
	for {
		f, err := ReadFrame(&buf)
		if err == io.EOF {
			break
		}
		if err != nil || len(f.Payload) > MaxFrame {
			t.Fatal(err)
		}
		got = append(got, f.Payload...)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("chunked data differs")
	}
}
