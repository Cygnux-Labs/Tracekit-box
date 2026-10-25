package tracekit

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

// testdata/jcs_vectors.json is the output of testdata/jcs_vectors.py run with the 1.4.2 venv (rfc8785 0.1.4 and
// tracekit.format.canon.event_hash): `python internal/tracekit/testdata/jcs_vectors.py > .../jcs_vectors.json`.
func TestCanonicalMatchesPythonVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/jcs_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct{ In, Canon, Hash string }
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 10 {
		t.Fatalf("only %d vectors", len(vectors))
	}
	for _, v := range vectors {
		d := json.NewDecoder(strings.NewReader(v.In))
		d.UseNumber()
		var x any
		if err := d.Decode(&x); err != nil {
			t.Fatalf("%s: %v", v.In, err)
		}
		got, err := Canonical(x)
		if err != nil {
			t.Errorf("Canonical(%s): %v", v.In, err)
			continue
		}
		if string(got) != v.Canon {
			t.Errorf("Canonical(%s)\n got %s\nwant %s", v.In, got, v.Canon)
		}
		h, _ := EventHash(x)
		if h != v.Hash {
			t.Errorf("EventHash(%s) = %s, want %s", v.In, h, v.Hash)
		}
	}
}

func TestArgsDigestOfGoValues(t *testing.T) {
	// the same values as the first vectors, built the way Box builds them
	h, err := ArgsDigest(ToolBash, BashArgs([]string{"ls"}))
	if err != nil || h != "sha256:3c4c0234f3fd581a998c6c92ee8487a3bf04eca566ab7e58f0a5f67dbd9fc504" {
		t.Fatalf("ArgsDigest(Bash ls) = %s, %v", h, err)
	}
	h, _ = ArgsDigest(ToolBash, BashArgs([]string{"ls", "-la", "/workspace"}))
	if h != "sha256:959d7c776113e82aa064a8646f7f805372c4c8b6ae07ddc9360edb8ee66c31d3" {
		t.Fatalf("ArgsDigest(Bash ls -la) = %s", h)
	}
	h, _ = ArgsDigest(ToolWebFetch, WebFetchArgs("https://pypi.org:443"))
	if h != "sha256:79a2aa2f0effc5963b2eb9e4d1c6c9fdbda96c7891c6e6aa45c327ddc5687258" {
		t.Fatalf("ArgsDigest(WebFetch) = %s", h)
	}
}

func TestCanonicalGoTypes(t *testing.T) {
	type inner struct {
		B string `json:"b"`
		A int    `json:"a"`
	}
	for _, c := range []struct {
		in   any
		want string
	}{
		{map[string]any{"z": 1, "a": []any{true, nil, "x"}}, `{"a":[true,null,"x"],"z":1}`},
		{map[string]int{"b": 2, "a": 1}, `{"a":1,"b":2}`},
		{[]string{"x", "y"}, `["x","y"]`},
		{inner{B: "<&>", A: 3}, `{"a":3,"b":"<&>"}`},
		{float64(1), `1`},
		{addFloats(0.1, 0.2), `0.30000000000000004`},
		{math.Copysign(0, -1), `0`},
		{float32(0.5), `0.5`},
		{int64(maxSafeInt), `9007199254740991`},
		{int64(-maxSafeInt), `-9007199254740991`},
		{uint8(7), `7`},
		{"  \x7f", "\"  \x7f\""},
		{"\x00\x1f\b\f\n\r\t\"\\", `"\u0000\u001f\b\f\n\r\t\"\\"`},
		{map[string]any(nil), `null`},
		{json.Number("1e2"), `100`},
		{json.Number("-0"), `0`},
		{json.RawMessage(`{"b":1, "a":[1.50]}`), `{"a":[1.5],"b":1}`},
		{1e21, `1e+21`},
		{1e-7, `1e-7`},
		{123e-20, `1.23e-18`},
	} {
		got, err := Canonical(c.in)
		if err != nil || string(got) != c.want {
			t.Errorf("Canonical(%#v) = %s, %v; want %s", c.in, got, err, c.want)
		}
	}
}

func TestCanonicalRefuses(t *testing.T) {
	deep := any("x")
	for i := 0; i < maxDepth+1; i++ {
		deep = []any{deep}
	}
	for name, v := range map[string]any{
		"int past 2^53":       int64(maxSafeInt + 1),
		"negative past 2^53":  int64(-maxSafeInt - 1),
		"uint past 2^53":      uint64(1 << 60),
		"number past 2^53":    json.Number("9007199254740992"),
		"NaN":                 math.NaN(),
		"infinity":            math.Inf(1),
		"invalid UTF-8":       "a\xffb",
		"lone surrogate":      "\xed\xa0\x80", // U+D800 in WTF-8
		"invalid UTF-8 key":   map[string]any{"\xff": 1},
		"nesting past 128":    deep,
		"invalid raw message": json.RawMessage(`{"a":`),
	} {
		if _, err := Canonical(v); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// JCS writes 1e20 as an integer literal, which the signer's frame parser refuses: allowed in a digest, refused in
	// a frame
	if got, err := Canonical(1e20); err != nil || string(got) != "100000000000000000000" {
		t.Errorf("Canonical(1e20) = %s, %v", got, err)
	}
	if _, err := canonical(1e20, true); err == nil {
		t.Error("strict canonical(1e20): no error")
	}
	if _, err := encodeFrame("observe", map[string]any{"value": 1e20}); err == nil {
		t.Error("a frame with 1e20 was encoded")
	}
}

func TestUTF16KeyOrder(t *testing.T) {
	// U+1F600 (UTF-16 D83D DE00) sorts before U+FB33 by code units, after it by bytes or code points
	got, _ := Canonical(map[string]any{"דּ": 1, "\U0001F600": 2})
	if !bytes.Equal(got, []byte("{\"\U0001F600\":2,\"דּ\":1}")) {
		t.Fatalf("got %s", got)
	}
}

func TestESNumber(t *testing.T) {
	for f, want := range map[float64]string{
		1: "1", 1.5: "1.5", 100: "100", 1e21: "1e+21", 1e20: "100000000000000000000", 1e-6: "0.000001",
		1e-7: "1e-7", 5e-324: "5e-324", 1.7976931348623157e308: "1.7976931348623157e+308", -2.5e-10: "-2.5e-10",
		123456789012345680000: "123456789012345680000", 0.000001234: "0.000001234", 12345678901234.568: "12345678901234.568",
	} {
		if got := esNumber(f); got != want {
			t.Errorf("esNumber(%v) = %s, want %s", f, got, want)
		}
	}
}

func addFloats(a, b float64) float64 { return a + b } // at run time: constants would add exactly
