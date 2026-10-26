//go:build unix

package egress

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// bufClientConn is the guest side of an exchange: writes are recorded, reads see EOF.
type bufClientConn struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *bufClientConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(b)
}
func (c *bufClientConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *bufClientConn) Close() error                     { return nil }
func (c *bufClientConn) CloseWrite() error                { return nil }
func (c *bufClientConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *bufClientConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *bufClientConn) SetDeadline(time.Time) error      { return nil }
func (c *bufClientConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufClientConn) SetWriteDeadline(time.Time) error { return nil }
func (c *bufClientConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

// socketPair is a connected pair of Unix stream sockets (buffered, with half-close), the proxy's upstream link.
func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "sp")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	return mk(fds[0]), mk(fds[1])
}

const (
	fzValGH  = "ghp_Q7xV9mK2pL4nR8sT1wZ3"
	fzValOAI = "sk-proj-Z9y8X7w6V5u4T3s2"
	fzValPW  = "p@ss w0rd/+=%x\"y"
)

type fwdCase struct {
	t       target
	overTLS bool
}

var fwdTargets = []fwdCase{
	{target{scheme: "https", host: "api.github.com", port: 443}, true},
	{target{scheme: "https", host: "api.openai.com", port: 443}, true},
	{target{scheme: "https", host: "evil.example", port: 443}, true},
	{target{scheme: "https", host: "api.github.com", port: 8443}, true},
	{target{scheme: "https", host: "1.2.3.4", addr: netip.MustParseAddr("1.2.3.4"), port: 443}, true},
	{target{scheme: "https", host: "pw.example", port: 443}, true},
	{target{scheme: "http", host: "api.github.com", port: 80}, false},
	{target{scheme: "http", host: "evil.example", port: 80}, false},
}

func hostHeaderFor(c fwdCase) string {
	h := c.t.host
	if c.t.addr.IsValid() && c.t.addr.Is6() {
		h = "[" + h + "]"
	}
	if (c.overTLS && c.t.port != 443) || (!c.overTLS && c.t.port != 80) {
		h = hostPort(c.t.host, c.t.port)
	}
	return h
}

// FuzzForward drives one request through exchange.forward (the code that swaps secrets in, checks the request and
// relays the answer) with an in-memory guest and a scripted upstream. Invariants:
//   - a real secret value reaches the upstream only in its bound header, on a request to a bound host over TLS;
//   - no placeholder reaches the upstream;
//   - the upstream sees Host: the tunnel's host and a request target naming no other host, and exactly one request;
//   - on an inspected connection the guest never sees a secret value (in a form valueForms covers) that a bound host
//     echoed back.
func FuzzForward(f *testing.F) {
	ca, err := NewCA("fuzz")
	if err != nil {
		f.Fatal(err)
	}
	seeds := []struct {
		sel        uint8
		req, resp  string
		chunkSizes []byte
	}{
		{0, "GET /user HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {PHGH}\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n{\"tok\":\"{VGH}\"}", nil},
		{0, "POST /x HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Basic {B64GH}\r\nContent-Length: 5\r\n\r\nhello", "HTTP/1.1 200 OK\r\nX-Echo: {VGH}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{VGH}\r\n0\r\nX-T: {VGH}\r\n\r\n", []byte{3}},
		{2, "GET / HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {PHGH}\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", nil},
		{2, "POST / HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ntkb\r\n4\r\nox_G\r\n0\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", []byte{1, 2}},
		{1, "GET /v1 HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {PHOAI}\r\nX-Api-Key: {PHGH}\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n{VOAI}", nil},
		{3, "GET https://{HOST}/a HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: token {PHGH}\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n{VGH}", nil},
		{5, "GET / HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: {PHPW}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n", nil},
		{6, "GET http://{HOST}/ HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {PHGH}\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", nil},
		{0, "GET //evil.example/x HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", nil},
		{0, "GET https:evil.example HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "HTTP/1.1 204 No Content\r\n\r\n", nil},
		{0, "PUT /x HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 40\r\n\r\n{PHGH}", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", []byte{5, 9}},
		// F3: an opaque https: target names another host past the tunnel's check
		{0, "GET https:http://evil.example/x HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {PHGH}\r\n\r\n", "HTTP/1.1 204 No Content\r\n\r\n", nil},
		// F2: a status below 100 carries a bound host's echo past the body redaction
		{0, "GET /user HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {PHGH}\r\n\r\n", "HTTP/1.1 099 Echo\r\nContent-Length: 24\r\n\r\n{VGH}", nil},
	}
	for _, s := range seeds {
		f.Add(s.sel, s.req, s.resp, s.chunkSizes)
	}
	f.Fuzz(func(t *testing.T, sel uint8, reqT, respT string, sizes []byte) {
		if len(reqT) > 8<<10 || len(respT) > 8<<10 {
			return
		}
		phGH, _ := NewPlaceholder("GH")
		phOAI, _ := NewPlaceholder("OAI")
		phPW, _ := NewPlaceholder("PW")
		ghHeader := "Authorization"
		if sel&0x80 != 0 {
			ghHeader = "X-Api-Key"
		}
		secrets := []Secret{
			{Name: "GH", Placeholder: phGH, Value: fzValGH, Hosts: []string{"api.github.com"}, Header: ghHeader},
			{Name: "OAI", Placeholder: phOAI, Value: fzValOAI, Hosts: []string{"api.openai.com"}},
			{Name: "PW", Placeholder: phPW, Value: fzValPW, Hosts: []string{"pw.example"}},
		}
		inspect := InspectBound
		if sel&0x40 != 0 {
			inspect = InspectAll
		}
		p, err := New(Config{Decider: nopDecider{}, Sink: nopSink{}, CA: ca, Secrets: secrets, Inspect: inspect,
			Allow: []string{"api.github.com", "api.openai.com", "evil.example", "pw.example"}})
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		c := fwdTargets[int(sel&0x3f)%len(fwdTargets)]
		vals := map[string]string{fzValGH: "GH", fzValOAI: "OAI", fzValPW: "PW"}
		sub := strings.NewReplacer("{HOST}", hostHeaderFor(c), "{PHGH}", phGH, "{PHOAI}", phOAI, "{PHPW}", phPW,
			"{B64GH}", base64.StdEncoding.EncodeToString([]byte("x-access-token:"+phGH)))
		reqBytes := []byte(sub.Replace(reqT))
		for v := range vals {
			for _, fm := range valueForms(v) {
				if bytes.Contains(reqBytes, []byte(fm)) {
					return // the guest never holds a value; FuzzForward checks what Box itself puts in
				}
			}
		}
		respSub := strings.NewReplacer("{VGH}", fzValGH, "{VOAI}", fzValOAI, "{VPW}", fzValPW,
			"{B64VGH}", base64.StdEncoding.EncodeToString([]byte(fzValGH)), "{PCTVPW}", url.QueryEscape(fzValPW),
			"{PHGH}", phGH)
		respBytes := []byte(respSub.Replace(respT))

		br := bufio.NewReaderSize(&chunkReader{data: reqBytes, sizes: sizes}, 4096)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method == http.MethodConnect {
			return
		}
		if !c.overTLS && req.URL.Host == "" {
			return // plain HTTP reaches forward only in absolute form (servePlain)
		}
		if !c.overTLS {
			// servePlain's own checks before forward: a placeholder anywhere in a plain request is a leak
			if p.find(req.Method, true) != nil || p.findTarget(req.RequestURI) != nil {
				return
			}
			if _, l := p.swapHeaders(req.Header, c.t.host, false); l != nil {
				return
			}
		}

		upBox, upHost := socketPair(t)
		defer upBox.Close()
		defer upHost.Close()
		deadline := time.Now().Add(3 * time.Second)
		upBox.SetDeadline(deadline)
		upHost.SetDeadline(deadline)
		var captured bytes.Buffer
		upDone := make(chan struct{})
		go func() {
			defer close(upDone)
			io.Copy(&captured, upHost)
		}()
		go func() {
			upHost.Write(respBytes)
			upHost.CloseWrite()
		}()
		cli := &bufClientConn{}
		s := &session{p: p, raw: cli, closers: []io.Closer{upBox}}
		s.watch = newIdleWatch(time.Minute, func() {})
		s.client = &meteredConn{Conn: cli, w: s.watch}
		uhl := &headLimiter{r: upBox, norec: true}
		x := &exchange{p: p, s: s, t: c.t, cliOut: &countWriter{w: cli}, upOut: &countWriter{w: upBox}, cr: br,
			ur: bufio.NewReaderSize(uhl, 32<<10), uhl: uhl, upRaw: upBox, cli: cli, up: upBox}
		x.forward(req, c.overTLS)
		s.watch.stop()
		upBox.Close()
		<-upDone
		up := captured.Bytes()
		toGuest := cli.bytes()

		// placeholders never leave
		for _, ph := range []string{phGH, phOAI, phPW} {
			if bytes.Contains(up, []byte(ph)) {
				t.Fatalf("placeholder %q reached the upstream %s:\n%q", ph, c.t.host, up)
			}
		}
		// what the upstream reads
		if len(up) > 0 {
			ur := bufio.NewReader(bytes.NewReader(up))
			ureq, err := http.ReadRequest(ur)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// Box cut the request off (the scripted upstream answered before reading it): check the raw lines
				for _, line := range strings.Split(string(up), "\r\n") {
					for v, name := range vals {
						for _, sr := range p.secrets {
							if sr.Name != name {
								continue
							}
							hdr, _, _ := strings.Cut(line, ":")
							if c.overTLS && sr.boundTo(c.t.host) && http.CanonicalHeaderKey(hdr) == sr.Header {
								continue
							}
							for _, fm := range append([]string{v}, valueForms(v)...) {
								if strings.Contains(line, fm) {
									t.Fatalf("secret %s (form %q) reached %s in a cut-off request line %q", name, fm, c.t.host, line)
								}
							}
						}
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("the upstream cannot read what Box sent: %v\n%q", err, up)
			}
			body, _ := io.ReadAll(ureq.Body)
			if rest, _ := io.ReadAll(ur); len(rest) > 0 && ureq.ContentLength >= 0 {
				t.Fatalf("bytes after the request Box sent (a second request?): %q\nall: %q", rest, up)
			}
			if ureq.Host != hostHeaderFor(c) {
				t.Fatalf("upstream Host %q, want %q", ureq.Host, hostHeaderFor(c))
			}
			if ureq.URL.Host != "" {
				t.Fatalf("upstream request target %q names a host", ureq.RequestURI)
			}
			if i := strings.Index(ureq.RequestURI, "://"); i >= 0 && !strings.HasPrefix(ureq.RequestURI, "/") {
				t.Fatalf("upstream request target %q is absolute", ureq.RequestURI)
			}
			if !strings.HasPrefix(ureq.RequestURI, "/") && ureq.RequestURI != "*" {
				t.Fatalf("upstream request target %q is not origin form (guest sent %q)", ureq.RequestURI, req.RequestURI)
			}
			for v, name := range vals {
				r := p.secrets[0]
				for _, sr := range p.secrets {
					if sr.Name == name {
						r = sr
					}
				}
				bound := c.overTLS && r.boundTo(c.t.host)
				where := []string{ureq.Method + " " + ureq.RequestURI, string(body)}
				for k, vs := range ureq.Header {
					where = append(where, k)
					for _, hv := range vs {
						if bound && http.CanonicalHeaderKey(k) == r.Header {
							continue // the one place a value may go
						}
						where = append(where, hv)
						if http.CanonicalHeaderKey(k) == "Authorization" && len(hv) > 6 && strings.EqualFold(hv[:6], "basic ") {
							if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(hv[6:])); err == nil {
								where = append(where, string(dec))
							}
						}
					}
				}
				for _, w := range where {
					for _, fm := range append([]string{v}, valueForms(v)...) {
						if strings.Contains(w, fm) {
							t.Fatalf("secret %s (form %q) reached %s:%d over TLS=%v in %q\nupstream: %q", name, fm, c.t.host, c.t.port, c.overTLS, w, up)
						}
					}
				}
			}
		}
		// the guest's view of a bound host's echo
		if c.overTLS {
			for v, name := range vals {
				var r *secretRule
				for _, sr := range p.secrets {
					if sr.Name == name {
						r = sr
					}
				}
				if !r.boundTo(c.t.host) {
					continue
				}
				for _, fm := range valueForms(v) {
					if bytes.Contains(toGuest, []byte(fm)) {
						t.Fatalf("the guest saw secret %s (form %q) echoed by %s:\n%q", name, fm, c.t.host, toGuest)
					}
				}
			}
		}
	})
}
