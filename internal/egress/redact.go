package egress

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Pattern kinds.
const (
	patPlaceholder = iota
	patValue
)

// pattern is one byte string the proxy looks for.
type pattern struct {
	s    []byte
	rule *secretRule
	kind int
	fold bool // matched without regard to ASCII case (secret values: a host may echo one upper- or lower-cased)
}

// at reports whether b starts with the pattern.
func (p *pattern) at(b []byte) bool {
	if len(b) < len(p.s) {
		return false
	}
	if !p.fold {
		return bytes.Equal(b[:len(p.s)], p.s)
	}
	return asciiEqualFold(b[:len(p.s)], p.s)
}

// startsWith reports whether the pattern starts with b.
func (p *pattern) startsWith(b []byte) bool {
	if !p.fold {
		return bytes.HasPrefix(p.s, b)
	}
	return len(b) <= len(p.s) && asciiEqualFold(p.s[:len(b)], b)
}

// asciiEqualFold compares equal-length byte strings without regard to ASCII case (never Unicode folding, which would
// match look-alikes such as the Kelvin sign).
func asciiEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lowerByte(a[i]) != lowerByte(b[i]) {
			return false
		}
	}
	return true
}

func lowerByte(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func upperByte(c byte) byte {
	if 'a' <= c && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

// matcher finds any of a set of patterns in one pass: patterns are indexed by their first byte.
type matcher struct {
	pats   []pattern
	first  [256][]int
	maxLen int
	// Markers carry markerText when no pattern can match across it (text), and are a run of fill, a byte no
	// pattern holds, otherwise.
	text bool
	fill byte
}

func newMatcher(pats []pattern) *matcher {
	m := &matcher{}
	seen := map[string]bool{}
	for _, p := range pats {
		key := string(p.s)
		if p.fold {
			key = "\x00" + asciiLower(key)
		}
		if len(p.s) == 0 || seen[key] {
			continue
		}
		seen[key] = true
		c := p.s[0]
		if p.fold {
			c = lowerByte(c)
			if u := upperByte(c); u != c {
				m.first[u] = append(m.first[u], len(m.pats))
			}
		}
		m.first[c] = append(m.first[c], len(m.pats))
		m.pats = append(m.pats, p)
		m.maxLen = max(m.maxLen, len(p.s))
	}
	m.chooseMarkers()
	return m
}

func (m *matcher) empty() bool { return m == nil || len(m.pats) == 0 }

// index returns the first position at or after from where a pattern starts (the longest one starting there), or -1.
func (m *matcher) index(b []byte, from int) (int, *pattern) {
	if m.empty() {
		return -1, nil
	}
	for i := from; i < len(b); i++ {
		var best *pattern
		for _, pi := range m.first[b[i]] {
			p := &m.pats[pi]
			if p.at(b[i:]) && (best == nil || len(p.s) > len(best.s)) {
				best = p
			}
		}
		if best != nil {
			return i, best
		}
	}
	return -1, nil
}

// hold returns the length of the longest suffix of b[from:] that is a proper prefix of a pattern: the bytes that may
// still become a match when more arrive. Values never hold control characters, so text ending in a newline holds
// nothing back and streamed (SSE) responses flow undelayed.
func (m *matcher) hold(b []byte, from int) int {
	if m.empty() {
		return 0
	}
	for i := max(from, len(b)-m.maxLen+1); i < len(b); i++ {
		for _, pi := range m.first[b[i]] {
			if p := &m.pats[pi]; len(p.s) > len(b)-i && p.startsWith(b[i:]) {
				return len(b) - i
			}
		}
	}
	return 0
}

// findString returns every distinct secret whose pattern occurs in s.
func (m *matcher) findString(s string) []*pattern {
	if m.empty() || s == "" {
		return nil
	}
	b := []byte(s)
	var out []*pattern
	for i := 0; ; {
		j, p := m.index(b, i)
		if j < 0 {
			return out
		}
		if !slices.ContainsFunc(out, func(q *pattern) bool { return q.rule == p.rule }) {
			out = append(out, p)
		}
		i = j + 1
	}
}

// valueForms returns a secret value as it may travel: verbatim, percent-encoded, JSON-escaped, hex and base64
// (standard and URL alphabets, at each of the three byte alignments, so the value is found inside a longer encoded
// string such as Basic credentials; also with "/" JSON-escaped and percent-encoded). The proxy matches every form
// without regard to ASCII case, so an upper- or lower-cased echo and upper-case hex are caught too. Other encodings
// are not: HTML or XML character references, a value split across lines (MIME or PEM wrapping), the base64 or hex
// of a case-changed value, and any encoding a host invents. A value shorter than minRedactLen can't be told apart
// from ordinary text and has none.
func valueForms(v string) []string {
	if len(v) < minRedactLen {
		return nil
	}
	forms := []string{v}
	add := func(s string) {
		if len(s) >= minRedactLen && !slices.Contains(forms, s) {
			forms = append(forms, s)
		}
	}
	for _, e := range []string{url.QueryEscape(v), url.PathEscape(v)} {
		add(e)
		add(lowerPercentHex(e))
	}
	for _, html := range []bool{true, false} {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(html)
		if enc.Encode(v) == nil {
			s := strings.TrimSuffix(b.String(), "\n")
			s = s[1 : len(s)-1]
			add(s)
			add(strings.ReplaceAll(s, "/", `\/`))
		}
	}
	add(hex.EncodeToString([]byte(v)))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for o := 0; o < 3; o++ {
			e := enc.EncodeToString(append(make([]byte, o), v...))
			// Only the characters whose 6 bits all come from the value.
			start, end := (8*o+5)/6, 8*(o+len(v))/6
			add(e[start:end])
			add(strings.ReplaceAll(e[start:end], "/", `\/`)) // inside JSON from PHP and others that escape "/"
			add(url.QueryEscape(e[start:end]))               // in a URL query: "+" and "/" percent-encoded
		}
	}
	return forms
}

func lowerPercentHex(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			for j := i + 1; j <= i+2; j++ {
				if 'A' <= b[j] && b[j] <= 'F' {
					b[j] += 'a' - 'A'
				}
			}
		}
	}
	return string(b)
}

// markerText is what a marker says between its brackets, padded with "*" (or cut to "redacted", or to nothing) to
// the length it stands in for.
const markerText = "tkbox: redacted"

// fillBytes are the bytes a marker may be made of instead, in order of preference: no letters (patterns match
// without regard to case), and control bytes last, which no value holds and so no form of one either.
var fillBytes = func() []byte {
	b := []byte("*#~")
	for c := byte('!'); c <= '~'; c++ {
		if lowerByte(c) == upperByte(c) && !bytes.Contains(b, []byte{c}) {
			b = append(b, c)
		}
	}
	for c := byte(1); c < ' '; c++ {
		b = append(b, c)
	}
	return b
}()

// chooseMarkers makes sure no marker can complete a pattern with the bytes around it, or be one: value "]abc…"
// followed by its own tail would become "[tkbox: redacted]abc…", and a value of "*"s would stand in for itself. A
// bracketed marker can take part in a match only if a pattern holds "[" or "]" or lies within the text between
// them; then markers are a run of a byte that no pattern holds.
func (m *matcher) chooseMarkers() {
	inner := markerText + strings.Repeat("*", m.maxLen)
	m.text = !slices.ContainsFunc(m.pats, func(p pattern) bool {
		return bytes.ContainsAny(p.s, "[]") || strings.Contains(inner, asciiLower(string(p.s)))
	})
	for _, c := range fillBytes {
		if !slices.ContainsFunc(m.pats, func(p pattern) bool { return bytes.IndexByte(p.s, c) >= 0 }) {
			m.fill = c
			return
		}
	}
}

// marker stands in for n bytes of a secret value: the same length, so Content-Length and Content-Range stay right,
// and never part of a match (see chooseMarkers).
func (m *matcher) marker(n int) string {
	if !m.text || n < 2 {
		return strings.Repeat(string([]byte{m.fill}), n)
	}
	text := markerText
	if n < len(text)+2 {
		text = "redacted"
	}
	if n < len(text)+2 {
		text = ""
	}
	return "[" + text + strings.Repeat("*", n-len(text)-2) + "]"
}

// redactReader passes a response body through, overwriting every secret value form with a marker of the same
// length. It holds back only a tail that may still turn into a value.
type redactReader struct {
	m      *matcher
	r      io.Reader
	buf    []byte // [ready | held]
	ready  int
	tmp    []byte
	srcErr error
}

func newRedactReader(m *matcher, r io.Reader) *redactReader {
	return &redactReader{m: m, r: r, tmp: make([]byte, 32<<10)}
}

func (x *redactReader) Read(b []byte) (int, error) {
	for {
		if x.ready > 0 {
			n := copy(b, x.buf[:x.ready])
			x.buf, x.ready = x.buf[n:], x.ready-n
			return n, nil
		}
		if x.srcErr != nil {
			return 0, x.srcErr
		}
		n, err := x.r.Read(x.tmp)
		if n > 0 {
			x.buf = append(x.buf, x.tmp[:n]...)
			end := 0
			for i := 0; ; {
				j, p := x.m.index(x.buf, i)
				if j < 0 {
					break
				}
				copy(x.buf[j:], x.m.marker(len(p.s)))
				i = j + len(p.s)
				end = i
			}
			x.ready = len(x.buf) - x.m.hold(x.buf, end)
		}
		if err != nil {
			x.srcErr = err
			x.ready = len(x.buf)
		}
	}
}

// contentCodings returns a response's content codings in the order they were applied, without identity.
func contentCodings(h http.Header) []string {
	var out []string
	for _, v := range h.Values("Content-Encoding") {
		for _, c := range strings.Split(v, ",") {
			if c = strings.ToLower(strings.TrimSpace(c)); c != "" && c != "identity" {
				out = append(out, c)
			}
		}
	}
	return out
}

var errTrailingData = errors.New("data after the compressed body")

// decodeBody undoes gzip and deflate codings so a body can be checked for secret values. Any other coding is an
// error naming it.
func decodeBody(body io.Reader, codings []string) (io.Reader, error) {
	for _, c := range codings {
		if c != "gzip" && c != "x-gzip" && c != "deflate" {
			return nil, fmt.Errorf("content coding %q", printable(c, 40))
		}
	}
	r := body
	for i := len(codings) - 1; i >= 0; i-- {
		var dec io.Reader
		switch codings[i] {
		case "gzip", "x-gzip":
			zr, err := gzip.NewReader(r)
			if errors.Is(err, io.EOF) {
				return http.NoBody, nil // an empty body
			}
			if err != nil {
				return nil, errors.New("a gzip body that does not decode")
			}
			dec = zr // reads its source to EOF (multistream)
		case "deflate":
			br := bufio.NewReader(r)
			h, err := br.Peek(2)
			if len(h) == 0 && errors.Is(err, io.EOF) {
				return http.NoBody, nil
			}
			if len(h) == 2 && h[0]&0x0f == 8 && (uint16(h[0])<<8|uint16(h[1]))%31 == 0 {
				zr, err := zlib.NewReader(br)
				if err != nil {
					return nil, errors.New("a deflate body that does not decode")
				}
				dec = &tailCheck{dec: zr, src: br}
			} else {
				dec = &tailCheck{dec: flate.NewReader(br), src: br} // raw deflate, as some servers send
			}
		}
		r = dec
	}
	return r, nil
}

// tailCheck makes sure nothing follows a compressed stream (and reads its source to EOF so trailers are parsed).
type tailCheck struct {
	dec, src io.Reader
	done     bool
}

func (t *tailCheck) Read(b []byte) (int, error) {
	if t.done {
		return 0, io.EOF
	}
	n, err := t.dec.Read(b)
	if err == io.EOF {
		t.done = true
		if m, _ := io.CopyN(io.Discard, t.src, 1); m > 0 {
			return n, errTrailingData
		}
	}
	return n, err
}
