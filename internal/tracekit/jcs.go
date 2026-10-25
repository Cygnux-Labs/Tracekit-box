package tracekit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// RFC 8785 (JCS), as tracekit/format/canon.py computes it with the `rfc8785` package: object keys sorted by their
// UTF-16 code units, strings escaped as ECMAScript's JSON.stringify does, numbers in ECMAScript Number form, integers
// only within ±(2^53-1). The signer reads frames with a strict parser (loads_strict) and recomputes digests from what
// it read, so anything this refuses is something the signer would refuse or hash differently.

const (
	maxSafeInt = 1<<53 - 1
	maxDepth   = 128 // canon.MAX_DEPTH: containers nested deeper are refused by the signer's strict parser
)

// CanonError is a value JCS cannot encode the way the signer would.
type CanonError struct{ Msg string }

func (e *CanonError) Error() string { return "not canonical JSON: " + e.Msg }

// Canonical returns the RFC 8785 canonical JSON of v. v is built from nil, bool, string, float64/float32, Go integer
// types, json.Number, map[string]any, []any (and other maps with string keys, slices and arrays); any other value
// (a struct, a json.Marshaler) goes through encoding/json first and is canonicalised from that.
func Canonical(v any) ([]byte, error) { return canonical(v, false) }

// canonical with strict refuses what JCS encodes but the signer's frame parser would not read back the same: an
// integral float past ±(2^53-1), which JCS writes as an integer literal.
func canonical(v any, strict bool) ([]byte, error) {
	var b bytes.Buffer
	if err := writeJCS(&b, v, 0, strict); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// EventHash is tracekit's event_hash: "sha256:" + hex(sha256(JCS(v))).
func EventHash(v any) (string, error) {
	c, err := Canonical(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ArgsDigest is complete's args_digest of a call: event_hash({"tool": tool, "args": args}).
func ArgsDigest(tool string, args map[string]any) (string, error) {
	return EventHash(map[string]any{"tool": tool, "args": argsValue(args)})
}

// argsValue is the args as sent: a nil map goes as {} so the frame and the digest agree.
func argsValue(args map[string]any) map[string]any {
	if args == nil {
		return map[string]any{}
	}
	return args
}

func writeJCS(b *bytes.Buffer, v any, depth int, strict bool) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
		return nil
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
		return nil
	case string:
		return writeJCSString(b, x)
	case json.Number:
		return writeJCSNumber(b, x, strict)
	case float64:
		return writeJCSFloat(b, x, strict)
	case float32:
		return writeJCSFloat(b, float64(x), strict)
	case int:
		return writeJCSInt(b, int64(x))
	case int8:
		return writeJCSInt(b, int64(x))
	case int16:
		return writeJCSInt(b, int64(x))
	case int32:
		return writeJCSInt(b, int64(x))
	case int64:
		return writeJCSInt(b, x)
	case uint:
		return writeJCSUint(b, uint64(x))
	case uint8:
		return writeJCSUint(b, uint64(x))
	case uint16:
		return writeJCSUint(b, uint64(x))
	case uint32:
		return writeJCSUint(b, uint64(x))
	case uint64:
		return writeJCSUint(b, x)
	case map[string]any:
		if depth >= maxDepth {
			return &CanonError{fmt.Sprintf("nesting deeper than %d", maxDepth)}
		}
		if x == nil {
			b.WriteString("null")
			return nil
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		return writeJCSObject(b, keys, func(k string) any { return x[k] }, depth, strict)
	case []any:
		if depth >= maxDepth {
			return &CanonError{fmt.Sprintf("nesting deeper than %d", maxDepth)}
		}
		if x == nil {
			b.WriteString("null")
			return nil
		}
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeJCS(b, e, depth+1, strict); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	case json.RawMessage:
		return writeJCSJSON(b, x, depth, strict)
	case json.Marshaler:
		raw, err := x.MarshalJSON()
		if err != nil {
			return &CanonError{err.Error()}
		}
		return writeJCSJSON(b, raw, depth, strict)
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			break
		}
		if depth >= maxDepth {
			return &CanonError{fmt.Sprintf("nesting deeper than %d", maxDepth)}
		}
		if rv.IsNil() {
			b.WriteString("null")
			return nil
		}
		keys := make([]string, 0, rv.Len())
		vals := make(map[string]any, rv.Len())
		for it := rv.MapRange(); it.Next(); {
			k := it.Key().String()
			keys = append(keys, k)
			vals[k] = it.Value().Interface()
		}
		return writeJCSObject(b, keys, func(k string) any { return vals[k] }, depth, strict)
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8 {
			break // []byte: encoding/json's base64 string
		}
		if depth >= maxDepth {
			return &CanonError{fmt.Sprintf("nesting deeper than %d", maxDepth)}
		}
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			b.WriteString("null")
			return nil
		}
		b.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeJCS(b, rv.Index(i).Interface(), depth+1, strict); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			b.WriteString("null")
			return nil
		}
		return writeJCS(b, rv.Elem().Interface(), depth, strict)
	case reflect.String:
		return writeJCSString(b, rv.String())
	case reflect.Bool:
		return writeJCS(b, rv.Bool(), depth, strict)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return writeJCSInt(b, rv.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return writeJCSUint(b, rv.Uint())
	case reflect.Float32, reflect.Float64:
		return writeJCSFloat(b, rv.Float(), strict)
	}
	// structs and the rest: what encoding/json makes of them
	raw, err := json.Marshal(v)
	if err != nil {
		return &CanonError{err.Error()}
	}
	return writeJCSJSON(b, raw, depth, strict)
}

// writeJCSJSON canonicalises JSON text (numbers kept exact).
func writeJCSJSON(b *bytes.Buffer, raw []byte, depth int, strict bool) error {
	if !utf8.Valid(raw) {
		return &CanonError{"invalid UTF-8"}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return &CanonError{err.Error()}
	}
	return writeJCS(b, v, depth, strict)
}

func writeJCSObject(b *bytes.Buffer, keys []string, get func(string) any, depth int, strict bool) error {
	for _, k := range keys {
		if !utf8.ValidString(k) {
			return &CanonError{fmt.Sprintf("object key %q is not valid UTF-8 (or holds a lone surrogate)", k)}
		}
	}
	slices.SortFunc(keys, compareUTF16)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		_ = writeJCSString(b, k)
		b.WriteByte(':')
		if err := writeJCS(b, get(k), depth+1, strict); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

// compareUTF16 orders strings by their UTF-16 code units (RFC 8785 3.2.3), which differs from byte order for
// characters past U+FFFF against U+E000..U+FFFF.
func compareUTF16(a, b string) int {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	return slices.Compare(ua, ub)
}

const hexDigits = "0123456789abcdef"

func writeJCSString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return &CanonError{"a string is not valid UTF-8 (or holds a lone surrogate)"}
	}
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0xf])
			} else {
				b.WriteByte(c) // every other byte as is: U+007F, U+2028/2029 and non-ASCII included
			}
		}
	}
	b.WriteByte('"')
	return nil
}

func writeJCSInt(b *bytes.Buffer, n int64) error {
	if n > maxSafeInt || n < -maxSafeInt {
		return &CanonError{fmt.Sprintf("%d exceeds the safe integer domain (±(2^53-1))", n)}
	}
	b.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func writeJCSUint(b *bytes.Buffer, n uint64) error {
	if n > maxSafeInt {
		return &CanonError{fmt.Sprintf("%d exceeds the safe integer domain (±(2^53-1))", n)}
	}
	b.WriteString(strconv.FormatUint(n, 10))
	return nil
}

// writeJCSNumber writes a JSON number literal as the signer reads it: an integer literal (no fraction or exponent) as
// a Python int, anything else as a float.
func writeJCSNumber(b *bytes.Buffer, n json.Number, strict bool) error {
	s := string(n)
	if !strings.ContainsAny(s, ".eE") {
		digits := strings.TrimPrefix(s, "-")
		if len(digits) > 16 {
			return &CanonError{fmt.Sprintf("%s exceeds the safe integer domain (±(2^53-1))", s)}
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return &CanonError{fmt.Sprintf("bad number %q", s)}
		}
		return writeJCSInt(b, i)
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return &CanonError{fmt.Sprintf("bad number %q", s)}
	}
	return writeJCSFloat(b, f, strict)
}

func writeJCSFloat(b *bytes.Buffer, f float64, strict bool) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return &CanonError{"NaN and infinities are not JSON"}
	}
	s := esNumber(f)
	// in a frame, an integral float past 2^53 comes out as an integer literal, which the signer's strict parser
	// refuses (int_range): refuse it here rather than send what the signer can't read back
	if strict && !strings.ContainsAny(s, ".e") && math.Abs(f) > maxSafeInt {
		return &CanonError{fmt.Sprintf("%s would be read back as an integer outside ±(2^53-1)", s)}
	}
	b.WriteString(s)
	return nil
}

// esNumber is ECMA-262 Number::toString of a finite float (RFC 8785 3.2.2.3), as canon.py's _number computes it from
// the shortest round-trip digits.
func esNumber(f float64) string {
	if f == 0 {
		return "0" // -0 too
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// shortest digits d1.d2d3...e±x: f = 0.<digits> * 10^n with n = x+1
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(exp)
	n := x + 1
	digits = strings.TrimRight(digits, "0")
	if digits == "" {
		digits = "0"
	}
	k := len(digits)
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	ex := n - 1
	out := sign + digits[:1]
	if k > 1 {
		out += "." + digits[1:]
	}
	if ex > 0 {
		return out + "e+" + strconv.Itoa(ex)
	}
	return out + "e-" + strconv.Itoa(-ex)
}
