package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"runtime"
	"testing"
)

// countingReader counts what ReadFrame consumed, so the frame can be compared with its re-encoding.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// FuzzReadFrame: any byte stream decodes to frames of at most MaxFrame bytes, allocates at most one payload of the
// declared (bounded) size per frame, re-encodes to exactly the bytes it consumed, and every JSON payload that decodes
// strictly into a request type re-encodes and decodes to the same value.
func FuzzReadFrame(f *testing.F) {
	var buf bytes.Buffer
	WriteJSON(&buf, TypeJSON, ExecRequest{Op: OpExec, Argv: []string{"echo", "hi"}})
	WriteFrame(&buf, TypeStdout, []byte("out"))
	f.Add(buf.Bytes())
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[1:], MaxFrame+1)
	f.Add(hdr[:])
	f.Add([]byte{2, 0, 0, 0, 9, 'x'})
	f.Add([]byte("\x00\x00\x00\x00\x16{\"op\":\"ping\",\"evil\":1}"))
	f.Add([]byte("\x00\x00\x00\x00\x0f{\"op\":\"ping\"}  "))
	f.Add([]byte("\x05\x00\x00\x00\x1c{\"code\":\"x\",\"message\":\"m\"}"))
	binary.BigEndian.PutUint32(hdr[1:], MaxFrame)
	f.Add(hdr[:])
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &countingReader{r: bytes.NewReader(data)}
		for i := 0; i < 64; i++ {
			start := r.n
			var ms0, ms1 runtime.MemStats
			if i == 0 && len(data) < 64 {
				runtime.ReadMemStats(&ms0)
			}
			fr, err := ReadFrame(r)
			if i == 0 && len(data) < 64 {
				runtime.ReadMemStats(&ms1)
				// one payload of at most MaxFrame plus small change, whatever the length prefix says
				if got := ms1.TotalAlloc - ms0.TotalAlloc; got > MaxFrame+64<<10 {
					t.Fatalf("ReadFrame allocated %d bytes for a %d-byte input", got, len(data))
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, ErrFrameTooLarge) {
					t.Fatalf("unexpected error %v", err)
				}
				if errors.Is(err, io.EOF) && r.n != start {
					t.Fatalf("io.EOF after consuming %d bytes of a frame", r.n-start)
				}
				return
			}
			if len(fr.Payload) > MaxFrame {
				t.Fatalf("payload %d > MaxFrame", len(fr.Payload))
			}
			var out bytes.Buffer
			if err := WriteFrame(&out, fr.Type, fr.Payload); err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			if !bytes.Equal(out.Bytes(), data[start:r.n]) {
				t.Fatalf("re-encoded frame differs from the bytes read")
			}
			if fr.Type == TypeJSON || fr.Type == TypeExit || fr.Type == TypeError || fr.Type == TypeSignal {
				for _, v := range []any{&ExecRequest{}, &ReadFileRequest{}, &WriteFileRequest{}, &DiffRequest{}, &ExitStatus{},
					&DiffSummary{}, &FileInfo{}, &PingResponse{}, &Signal{}, &BootConfig{}, &Error{}} {
					if fr.Decode(v) != nil {
						continue
					}
					b, err := json.Marshal(v)
					if err != nil {
						t.Fatalf("marshal %T: %v", v, err)
					}
					w := reflect.New(reflect.TypeOf(v).Elem()).Interface()
					if err := (Frame{Type: fr.Type, Payload: b}).Decode(w); err != nil {
						t.Fatalf("%T: decode of re-encoded %s: %v", v, b, err)
					}
					if !reflect.DeepEqual(normNil(v), normNil(w)) {
						t.Fatalf("%T round trip: %+v != %+v", v, v, w)
					}
				}
				e := fr.AsError()
				if e == nil || e.Code == "" {
					t.Fatalf("AsError returned %v", e)
				}
			}
		}
	})
}

// normNil compares nil and empty slices alike (omitempty drops an empty slice).
func normNil(v any) any {
	b, _ := json.Marshal(v)
	var m any
	json.Unmarshal(b, &m)
	return m
}

// FuzzChunkWriter: any write splits into frames of at most MaxFrame bytes that concatenate back to the input.
func FuzzChunkWriter(f *testing.F) {
	f.Add([]byte("hello"), uint16(3))
	f.Fuzz(func(t *testing.T, data []byte, rep uint16) {
		if rep > 40 {
			rep = 40
		}
		in := bytes.Repeat(data, int(rep)+1)
		if len(in) > 3*MaxFrame {
			in = in[:3*MaxFrame]
		}
		var buf bytes.Buffer
		if n, err := (ChunkWriter{W: &buf, Type: TypeStdout}).Write(in); err != nil || n != len(in) {
			t.Fatal(n, err)
		}
		var got []byte
		for {
			fr, err := ReadFrame(&buf)
			if err == io.EOF {
				break
			}
			if err != nil || len(fr.Payload) > MaxFrame || fr.Type != TypeStdout || len(fr.Payload) == 0 {
				t.Fatalf("frame %d %v", len(fr.Payload), err)
			}
			got = append(got, fr.Payload...)
		}
		if !bytes.Equal(got, in) {
			t.Fatal("chunked data differs")
		}
	})
}
