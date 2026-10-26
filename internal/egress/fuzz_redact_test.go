package egress

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// chunkReader returns data in pieces whose sizes come from sizes (cycled; 0 means 1).
type chunkReader struct {
	data  []byte
	sizes []byte
	i     int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := len(c.data)
	if len(c.sizes) > 0 {
		n = int(c.sizes[c.i%len(c.sizes)])%61 + 1
		c.i++
	}
	n = min(n, len(p), len(c.data))
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

// readSmall reads r with read buffers whose sizes come from sizes.
func readSmall(t *testing.T, r io.Reader, sizes []byte) []byte {
	var out []byte
	buf := make([]byte, 64)
	for i := 0; ; i++ {
		n := len(buf)
		if len(sizes) > 0 {
			n = int(sizes[(i*7)%len(sizes)])%64 + 1
		}
		k, err := r.Read(buf[:n])
		out = append(out, buf[:k]...)
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if i > 1<<20 {
			t.Fatal("reader makes no progress")
		}
	}
}

// fuzzRules builds secret rules from a fuzzed value and two fixed ones. The fixed ones hold no "[" or "]", so whether
// markers keep their text depends on the fuzzed value alone.
func fuzzRules(t *testing.T, v string) []*secretRule {
	var out []*secretRule
	for i, val := range []string{v, "ghp_Q7xV9mK2pL4nR8sT1wZ3", "p@ss w0rd/+=%x\"\\é"} {
		name := []string{"FZ", "GH", "PW"}[i]
		ph, _ := NewPlaceholder(name)
		r, err := newSecretRule(Secret{Name: name, Placeholder: ph, Value: val, Hosts: []string{"api.example.com"}})
		if err != nil {
			if i == 0 {
				continue // the fuzzed value is not a valid secret
			}
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// FuzzRedactReader: a response body carrying secret values in any of the forms valueForms claims, split at any read
// boundaries on either side, comes out the same length, the same as when read in one piece, and with none of those
// forms left in it; gzip and deflate bodies of a bound host are decoded and redacted the same way.
func FuzzRedactReader(f *testing.F) {
	f.Add("s3cr3t-Value", []byte("x {0} y {1} z"), []byte{3, 1, 7}, uint8(0))
	f.Add("ghp_abcdef", []byte("{4}{4}{5}"), []byte{1}, uint8(1))
	f.Add("aaaaaa", []byte("aaaaaaaaa{0}a"), []byte{2, 5}, uint8(2))
	f.Add("tok/en+val=ue", []byte("{2}{3}{6}{7}{8}"), []byte{9}, uint8(3))
	// F4: a marker that rebuilds the value with the bytes around it, or is the value
	f.Add("a*****", []byte("aa*****"), []byte{1}, uint8(0))
	f.Add("******", []byte("******"), []byte(nil), uint8(0))
	f.Add("[redacted]", []byte("x[redacted]y"), []byte{4}, uint8(1))
	f.Add("]abcdefghijklmnop", []byte("]abcdefghijklmnopabcdefghijklmnop"), []byte{2, 9}, uint8(0))
	f.Fuzz(func(t *testing.T, v string, tmpl []byte, sizes []byte, mode uint8) {
		if len(tmpl) > 4096 || len(v) > 80 {
			return
		}
		rules := fuzzRules(t, v)
		var forms []string
		for _, r := range rules {
			forms = append(forms, r.forms...)
		}
		m := newMatcher((&Proxy{secrets: rules}).valuePatterns())
		// {k} inserts form k (over all rules' forms), <k> the form in upper case
		body := tmpl
		for k := len(forms) - 1; k >= 0; k-- {
			body = bytes.ReplaceAll(body, []byte("{"+strconv.Itoa(k)+"}"), []byte(forms[k]))
			body = bytes.ReplaceAll(body, []byte("<"+strconv.Itoa(k)+">"), bytes.Map(func(r rune) rune {
				if 'a' <= r && r <= 'z' {
					return r - ('a' - 'A')
				}
				return r
			}, []byte(forms[k])))
		}
		whole, _ := io.ReadAll(newRedactReader(m, bytes.NewReader(body)))
		var got []byte
		switch mode % 4 {
		case 0:
			got = readSmall(t, newRedactReader(m, &chunkReader{data: body, sizes: sizes}), sizes)
		default:
			var zb bytes.Buffer
			var w io.WriteCloser
			coding := ""
			switch mode % 4 {
			case 1:
				w, coding = gzip.NewWriter(&zb), "gzip"
			case 2:
				w, coding = zlib.NewWriter(&zb), "deflate"
			case 3:
				w, _ = flate.NewWriter(&zb, 1)
				coding = "deflate"
			}
			w.Write(body)
			w.Close()
			p := &Proxy{secrets: rules, valMatch: m}
			resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {coding}},
				Body: io.NopCloser(&chunkReader{data: zb.Bytes(), sizes: sizes})}
			if r := p.guardBody(resp, http.MethodGet, true); r != nil {
				t.Fatalf("guardBody refused a valid %s body: %s", coding, r.reason)
			}
			if resp.Header.Get("Content-Encoding") != "" {
				t.Fatal("Content-Encoding kept on a decoded body")
			}
			got = readSmall(t, resp.Body, sizes)
		}
		if len(got) != len(body) {
			t.Fatalf("redacted body is %d bytes, input %d", len(got), len(body))
		}
		if !bytes.Equal(got, whole) {
			t.Fatalf("read boundaries change the output:\n got %q\nwant %q", got, whole)
		}
		// Values are matched without regard to ASCII case, so no form may be left in any case.
		low := asciiLower(string(got))
		for _, fm := range forms {
			if i := strings.Index(low, asciiLower(fm)); i >= 0 {
				t.Fatalf("form %q of a secret value is in the redacted body at %d: %q (input %q)", fm, i, got, body)
			}
		}
	})
}
