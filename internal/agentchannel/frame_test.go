package agentchannel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeRefusals(t *testing.T) {
	for _, s := range []string{
		`{"method":"approval_decide"}`,
		`{"method":"decide","caller":"other"}`,
		`{"method":"register_run","parent":"x"}`,
		`{"method":"observe","source":"tkbox.box","trust":"trusted"}`,
		`{"method":"status","x":1,"x":2}`,
		"{\"method\":\"status\",\"x\":\"\xff\"}",
	} {
		if _, err := Decode([]byte(s)); err == nil {
			t.Errorf("Decode(%q) accepted", s)
		}
	}
}

func TestDecodeDepth129(t *testing.T) {
	data := []byte(`{"method":"status","x":` + strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129) + `}`)
	if _, err := Decode(data); err == nil {
		t.Fatal("accepted JSON nested to depth 129")
	}
}

func TestDecodePreservesNumberAndObserveTrust(t *testing.T) {
	m, err := Decode([]byte(`{"method":"observe","source":"agent.prompt","trust":"trusted","n":9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	if m["n"].(json.Number).String() != "9007199254740993" || m["trust"] != "trusted" {
		t.Fatalf("decoded %#v", m)
	}
}

func TestReadFrameLimitAndVerbatim(t *testing.T) {
	want := []byte(`{"method":"status"}`)
	got, _, err := ReadFrame(bufio.NewReader(bytes.NewReader(append(append([]byte{}, want...), '\n'))))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("ReadFrame = %q, %v", got, err)
	}
	if _, _, err := ReadFrame(bufio.NewReader(strings.NewReader(strings.Repeat("x", MaxFrame+2) + "\n"))); err != ErrTooLarge {
		t.Fatalf("oversize: %v", err)
	}
}

func FuzzReadAgentFrame(f *testing.F) {
	for _, s := range []string{`{"method":"status"}`, `{"method":"observe","source":"a"}`, `{}`, "\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > MaxFrame {
			return
		}
		_, _, _ = ReadFrame(bufio.NewReader(strings.NewReader(s + "\n")))
	})
}

func FuzzAgentFields(f *testing.F) {
	for _, s := range []string{`{"method":"status"}`, `{"method":"register_run","run_id":"discard"}`, `{"method":"decide","caller":"x"}`, `{"method":"observe","source":"tkbox.test"}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) <= MaxFrame {
			_, _ = Decode([]byte(s))
		}
	})
}
