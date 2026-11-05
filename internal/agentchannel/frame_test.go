package agentchannel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
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
	if string(m.Raw("n")) != "9007199254740993" || m.Str("trust") != "trusted" {
		t.Fatalf("decoded %#v", m)
	}
}

// strictReference is the strict check as encoding/json reads it (the channel's first implementation, which built the
// whole value): FuzzAgentFields holds the scanner to it.
func strictReference(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(depth int) (any, error)
	value = func(depth int) (any, error) {
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
						return nil, errors.New("duplicate key")
					}
					if m[k], err = value(depth + 1); err != nil {
						return nil, err
					}
				}
				_, err := d.Token()
				return m, err
			case '[':
				a := []any{}
				for d.More() {
					v, err := value(depth + 1)
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
	v, err := value(0)
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
	return m, nil
}

// sameAsReference: the scanner accepts exactly what encoding/json's strict reading accepts, with the same top-level
// names and string values.
func sameAsReference(t *testing.T, data []byte) {
	t.Helper()
	ref, rerr := strictReference(data)
	f, err := parseFrame(data)
	if (rerr == nil) != (err == nil) {
		t.Fatalf("%q: encoding/json says %v, the scanner %v", data, rerr, err)
	}
	if err != nil {
		return
	}
	if len(ref) != len(f.raw) {
		t.Fatalf("%q: names %v, the scanner %v", data, slices.Sorted(maps.Keys(ref)), slices.Sorted(maps.Keys(f.raw)))
	}
	for k, v := range ref {
		s, isStr := v.(string)
		got, ok := f.str[k]
		if !f.Has(k) || isStr != ok || s != got {
			t.Fatalf("%q: field %q is %#v, the scanner %q (string %v)", data, k, v, got, ok)
		}
	}
}

func TestScannerMatchesEncodingJSON(t *testing.T) {
	for _, s := range []string{
		`{}`, ` {"a":1} `, `{"a":1}x`, `{"a":1,}`, `{"a" 1}`, `{"a":01}`, `{"a":-0.5e+10}`, `{"a":1.}`, `{"a":-}`,
		`{"a":tru}`, `{"a":[1,]}`, `{"a":[,1]}`, `[]`, `"x"`, ``, `{"a":"é","b":"😀"}`,
		`{"a":"\ud800","\ud800":1,"\udc00":2}`, `{"a":1,"a":2}`, `{"a":"\x"}`, `{"a":"\u12"}`, "{\"a\":\"\t\"}",
		`{"a":{"b":1,"b":2}}`, `{"a":[{"b":1},{"b":1}]}`, `{"a":"\ud83dA"}`, `{"a":"\ud83d"}`, `{"a":null,"b":true,"c":false}`,
		`{"a":1}{}`, `{"a":"x"`, `{"a":1e5,"b":1E-5,"c":0}`, `{"method":"status","x":` + strings.Repeat("[", 128) + strings.Repeat("]", 128) + `}`,
		`{"a":` + strings.Repeat("[", 129) + strings.Repeat("]", 129) + `}`, `{"a":"` + strings.Repeat("\\u0041", 40) + `"}`,
		`{"k1":1,"k2":1,"k3":1,"k4":1,"k5":1,"k6":1,"k7":1,"k8":1,"k9":1,"k10":1,"k11":1,"k12":1,"k13":1,"k14":1,"k15":1,"k16":1,"k17":1,"k18":1,"k1":2}`,
	} {
		sameAsReference(t, []byte(s))
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
	for _, s := range []string{`{"a":"\ud800","𐀀":[1,{"b":null}]}`, `{"caller":1,"x":-1.5e3}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) <= MaxFrame {
			_, _ = Decode([]byte(s))
			sameAsReference(t, []byte(s))
		}
	})
}

// fieldsOf is the frame's fields, for tests that call check and record directly.
func fieldsOf(t testing.TB, frame string) *Frame {
	t.Helper()
	f, err := parseFrame([]byte(frame))
	if err != nil {
		t.Fatal(err)
	}
	return f
}
