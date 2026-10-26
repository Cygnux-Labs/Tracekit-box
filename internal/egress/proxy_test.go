package egress_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress/egressfake"
)

// ---- helpers ----

func mkSecret(t *testing.T, name, header string, hosts ...string) Secret {
	t.Helper()
	ph, err := NewPlaceholder(name)
	if err != nil {
		t.Fatal(err)
	}
	return Secret{Name: name, Placeholder: ph, Value: "real-" + strings.ToLower(name) + "-value-0123456789", Hosts: hosts, Header: header}
}

var (
	upCAOnce sync.Once
	upCA     *CA
)

// upstreamCA plays the public web PKI for test upstreams.
func upstreamCA(t *testing.T) *CA {
	upCAOnce.Do(func() {
		var err error
		if upCA, err = NewCA("upstream-pki"); err != nil {
			panic(err)
		}
	})
	return upCA
}

func caCert(t *testing.T, ca *CA) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(ca.CertPEM())
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// startTLS starts an HTTPS upstream on 127.0.0.1 that presents certificates for names only and returns its port.
func startTLS(t *testing.T, h http.Handler, names ...string) string {
	t.Helper()
	ca := upstreamCA(t)
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		for _, n := range names {
			if hello.ServerName == n {
				return MintLeaf(ca, n)
			}
		}
		return nil, fmt.Errorf("no certificate for %q", hello.ServerName)
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return port(t, srv.Listener.Addr())
}

// bufConn reads through a bufio.Reader that already holds bytes from the connection.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func startHTTP(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return port(t, srv.Listener.Addr())
}

// startHold starts a TCP upstream that accepts and holds connections (for idle and Close tests).
func startHold(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-done
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
	})
	return port(t, l.Addr())
}

func port(t *testing.T, a net.Addr) string {
	_, p, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// checkGoroutines fails the test if goroutines outlive it. Call it first so its cleanup runs last.
func checkGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			n := runtime.NumGoroutine()
			if n <= before {
				return
			}
			if time.Now().After(deadline) {
				buf := make([]byte, 1<<20)
				buf = buf[:runtime.Stack(buf, true)]
				t.Errorf("goroutine leak: %d before, %d after\n%s", before, n, buf)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

type fakeResolver struct {
	mu    sync.Mutex
	m     map[string][]netip.Addr
	calls []string
}

func (r *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	host = strings.TrimSuffix(host, ".")
	r.calls = append(r.calls, host)
	if a, ok := r.m[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (r *fakeResolver) set(host string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var as []netip.Addr
	for _, a := range addrs {
		as = append(as, netip.MustParseAddr(a))
	}
	r.m[host] = as
}

func (r *fakeResolver) lookups() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// teeSink records into egressfake.Sink and keeps a copy that is safe to read while the proxy runs.
type teeSink struct {
	fake *egressfake.Sink
	mu   sync.Mutex
	ev   []Event
}

func (s *teeSink) Emit(e Event) {
	s.fake.Emit(e)
	s.mu.Lock()
	s.ev = append(s.ev, e)
	s.mu.Unlock()
}

func (s *teeSink) events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.ev...)
}

type env struct {
	t        *testing.T
	p        *Proxy
	cfg      Config
	addr     string
	dec      *egressfake.Decider
	sink     *teeSink
	res      *fakeResolver
	boxCA    *CA
	serveErr chan error
	stopOnce sync.Once
}

func newEnv(t *testing.T, mutate func(*Config)) *env {
	t.Helper()
	e := &env{t: t, dec: &egressfake.Decider{}, sink: &teeSink{fake: &egressfake.Sink{}}, res: &fakeResolver{m: map[string][]netip.Addr{}}}
	var err error
	if e.boxCA, err = NewCA("box-test"); err != nil {
		t.Fatal(err)
	}
	e.res.set("example.com", "127.0.0.1")
	e.res.set("other.example", "127.0.0.1")
	roots := x509.NewCertPool()
	roots.AddCert(caCert(t, upstreamCA(t)))
	e.cfg = Config{BoxID: "box-test", Decider: e.dec, Sink: e.sink, Resolver: e.res, CA: e.boxCA, UpstreamRoots: roots,
		AllowPrivate: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	if mutate != nil {
		mutate(&e.cfg)
	}
	if e.p, err = New(e.cfg); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = l.Addr().String()
	e.serveErr = make(chan error, 1)
	go func() { e.serveErr <- e.p.Serve(l) }()
	t.Cleanup(func() {
		e.stop()
		e.checkEvents()
	})
	return e
}

// stop closes the proxy and waits for Serve; afterwards the fakes may be read directly.
func (e *env) stop() {
	e.stopOnce.Do(func() {
		if err := e.p.Close(); err != nil {
			e.t.Errorf("Close: %v", err)
		}
		select {
		case err := <-e.serveErr:
			if err != nil {
				e.t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			e.t.Error("Serve did not return after Close")
		}
	})
}

// checkEvents: no event carries a secret value or placeholder, and nothing panicked.
func (e *env) checkEvents() {
	for _, ev := range e.sink.events() {
		fields := strings.ToLower(strings.Join([]string{ev.Host, ev.Method, ev.Path, ev.Reason, ev.Secret}, "\x00"))
		for _, s := range e.cfg.Secrets {
			if strings.Contains(fields, strings.ToLower(s.Placeholder)) || strings.Contains(fields, strings.ToLower(s.Value)) {
				e.t.Errorf("event %+v holds secret %s", ev, s.Name)
			}
		}
		if strings.Contains(ev.Reason, "internal error") {
			e.t.Errorf("proxy panicked: %+v", ev)
		}
		if ev.Time.IsZero() {
			e.t.Errorf("event without time: %+v", ev)
		}
	}
}

func (e *env) waitKind(kind string) Event {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, ev := range e.sink.events() {
			if ev.Kind == kind {
				return ev
			}
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("no %s event; have %v", kind, e.sink.fake.Kinds())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (e *env) kinds() []string {
	var out []string
	for _, ev := range e.sink.events() {
		out = append(out, ev.Kind)
	}
	return out
}

func (e *env) clientPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(caCert(e.t, e.boxCA))
	pool.AddCert(caCert(e.t, upstreamCA(e.t)))
	return pool
}

func (e *env) client() *http.Client {
	tr := &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: e.addr}),
		TLSClientConfig:   &tls.Config{RootCAs: e.clientPool()},
		DisableKeepAlives: true,
	}
	e.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (e *env) dialProxy() net.Conn {
	e.t.Helper()
	c, err := net.Dial("tcp", e.addr)
	if err != nil {
		e.t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	e.t.Cleanup(func() { c.Close() })
	return c
}

func (e *env) rawConnect(target string) (net.Conn, *bufio.Reader, *http.Response) {
	e.t.Helper()
	c := e.dialProxy()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic eDp5\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		e.t.Fatalf("CONNECT %s: %v", target, err)
	}
	return c, br, resp
}

// tunnelTLS opens a CONNECT tunnel and a TLS session over it.
func (e *env) tunnelTLS(target, sni string) (*tls.Conn, *bufio.Reader) {
	e.t.Helper()
	c, br, resp := e.rawConnect(target)
	if resp.StatusCode != 200 {
		e.t.Fatalf("CONNECT %s: %s", target, resp.Status)
	}
	tc := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{ServerName: sni, RootCAs: e.clientPool(), NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		e.t.Fatalf("TLS over tunnel: %v", err)
	}
	return tc, bufio.NewReader(tc)
}

func body(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func hasKind(kinds []string, k string) bool {
	for _, x := range kinds {
		if x == k {
			return true
		}
	}
	return false
}

// ---- tests ----

func TestTunnelPlain(t *testing.T) {
	checkGoroutines(t)
	port := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") }), "example.com")
	e := newEnv(t, func(c *Config) { c.Allow = []string{"example.com:" + port} })
	resp, err := e.client().Get("https://example.com:" + port + "/x")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); b != "hello" {
		t.Fatalf("body %q", b)
	}
	if got := resp.TLS.PeerCertificates[0].Issuer.CommonName; !strings.Contains(got, "upstream-pki") {
		t.Errorf("tunnel was intercepted: issuer %q", got)
	}
	closed := e.waitKind(EventClosed)
	e.stop()
	if k := e.kinds(); len(k) != 2 || k[0] != EventAllowed || k[1] != EventClosed {
		t.Errorf("events %v", k)
	}
	if closed.BytesIn == 0 || closed.BytesOut == 0 || closed.Host != "example.com" {
		t.Errorf("closed event %+v", closed)
	}
	if len(e.dec.Requests) != 1 {
		t.Fatalf("decider asked %d times", len(e.dec.Requests))
	}
	r := e.dec.Requests[0]
	p, _ := strconv.Atoi(port)
	// Not port 443: recorded as a TCP tunnel to that port (TestDecisionSchemeByPort).
	if r.BoxID != "box-test" || r.Scheme != "tcp" || r.Host != "example.com" || r.Port != p || !r.OnAllowlist ||
		r.URL != "tcp://example.com:"+port || len(r.Addrs) != 1 || r.Addrs[0] != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("decider request %+v", r)
	}
}

// The decision is made before the tunnel's first byte, so its url names only what is known then: a CONNECT to 443
// is https (the tunnel must carry TLS), any other port a TCP tunnel to that port (an allow entry naming the port
// lets SSH or any other protocol through), and an absolute-form request is http.
func TestDecisionSchemeByPort(t *testing.T) {
	checkGoroutines(t)
	e := newEnv(t, func(c *Config) { c.Allow = []string{"example.com", "example.com:22", "other.example:8443"} })
	e.dec.Func = func(context.Context, Request) (Verdict, error) {
		return Verdict{Reason: "test refuses everything"}, nil
	}
	for _, target := range []string{"example.com:443", "example.com:22", "other.example:8443", "[2606:4700::1111]:5432"} {
		_, _, resp := e.rawConnect(target)
		resp.Body.Close()
	}
	c := e.dialProxy()
	fmt.Fprintf(c, "GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	e.stop()
	want := map[string]string{
		"example.com:443":      "https://example.com:443",
		"example.com:22":       "tcp://example.com:22",
		"other.example:8443":   "tcp://other.example:8443",
		"2606:4700::1111:5432": "tcp://[2606:4700::1111]:5432",
		"example.com:80":       "http://example.com:80",
	}
	got := map[string]string{}
	for _, r := range e.dec.Requests {
		k := r.Host + ":" + strconv.Itoa(r.Port)
		got[k] = r.URL
		if scheme, _, _ := strings.Cut(r.URL, "://"); scheme != r.Scheme {
			t.Errorf("%s: Scheme %q but URL %q", k, r.Scheme, r.URL)
		}
	}
	for k, u := range want {
		if got[k] != u {
			t.Errorf("%s: url %q, want %q", k, got[k], u)
		}
	}
}

func TestDenyBody(t *testing.T) {
	checkGoroutines(t)
	e := newEnv(t, nil)
	_, _, resp := e.rawConnect("Example.COM.:443")
	b := body(t, resp)
	if resp.StatusCode != 403 || resp.Header.Get("X-Tkbox-Reason") != "not on the allowlist" {
		t.Fatalf("got %s %q", resp.Status, resp.Header.Get("X-Tkbox-Reason"))
	}
	want := "tkbox: example.com:443 refused: not on the allowlist. If the job needs this host, add it to the box's allow list (tkbox.yaml or --allow) or ask the operator to approve it with `tkbox approve`.\n"
	if b != want {
		t.Errorf("body\n%q\nwant\n%q", b, want)
	}
	ev := e.waitKind(EventDenied)
	if ev.Host != "example.com" || ev.Port != 443 || ev.Reason != "not on the allowlist" {
		t.Errorf("denied event %+v", ev)
	}
	if l := e.res.lookups(); len(l) != 0 {
		t.Errorf("a name off the allowlist was resolved before the decision: %v", l)
	}
}

func TestAllowlistPorts(t *testing.T) {
	checkGoroutines(t)
	var mu sync.Mutex
	seen := map[string]bool{}
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com", "*.wild.example", "other.example:8443"}
		c.Decider = &egressfake.Decider{Func: func(ctx context.Context, r Request) (Verdict, error) {
			mu.Lock()
			seen[net.JoinHostPort(r.Host, strconv.Itoa(r.Port))] = r.OnAllowlist
			mu.Unlock()
			return Verdict{Reason: "test refuses everything"}, nil
		}}
	})
	e.res.set("a.wild.example", "127.0.0.1")
	e.res.set("wild.example", "127.0.0.1")
	want := map[string]bool{
		"example.com:443": true, "example.com:80": true, "example.com:8443": false,
		"a.wild.example:443": true, "wild.example:443": false,
		"other.example:8443": true, "other.example:443": false,
	}
	for target := range want {
		var resp *http.Response
		if strings.HasSuffix(target, ":80") {
			// Port 80 is plain HTTP in absolute form (a CONNECT to it is refused before the Decider).
			c := e.dialProxy()
			fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
			var err error
			if resp, err = http.ReadResponse(bufio.NewReader(c), nil); err != nil {
				t.Fatal(err)
			}
		} else {
			_, _, resp = e.rawConnect(target)
		}
		if resp.StatusCode != 403 {
			t.Errorf("%s: %s", target, resp.Status)
		}
		resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	for target, on := range want {
		if got, ok := seen[target]; !ok || got != on {
			t.Errorf("%s: OnAllowlist = %v (asked %v), want %v", target, got, ok, on)
		}
	}
}

func TestAddressRefusals(t *testing.T) {
	checkGoroutines(t)
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"internal.example", "mixed.example", "loop2.example", "meta.example", "[::ffff:10.0.0.1]:443",
			"169.254.169.254", "6to4.example", "nat64.example", "teredo.example"}
		c.AllowPrivate = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("169.254.0.0/16")}
	})
	e.res.set("internal.example", "10.0.0.7")
	e.res.set("mixed.example", "93.184.216.34", "192.168.1.5") // rebinding: one public, one private answer
	e.res.set("loop2.example", "127.0.0.1", "127.0.0.2")
	e.res.set("meta.example", "169.254.169.254")
	e.res.set("6to4.example", "2002:a00:1::1")
	e.res.set("nat64.example", "64:ff9b::a00:1")
	e.res.set("teredo.example", "2001:0:4136:e378:8000:63bf:3fff:fdd2")
	cases := map[string]string{
		"internal.example:443":   "private",
		"mixed.example:443":      "private",
		"loop2.example:443":      "loopback",
		"meta.example:443":       "metadata",
		"[::ffff:10.0.0.1]:443":  "private",
		"169.254.169.254:443":    "metadata",
		"6to4.example:443":       "6to4",
		"nat64.example:443":      "NAT64",
		"teredo.example:443":     "Teredo",
		"[::ffff:127.0.0.2]:443": "loopback", // never asked: refused before the Decider, allowlist or not
	}
	for target, why := range cases {
		_, _, resp := e.rawConnect(target)
		b := body(t, resp)
		if resp.StatusCode != 403 || !strings.Contains(resp.Header.Get("X-Tkbox-Reason"), why) {
			t.Errorf("%s: %s %q, want 403 mentioning %q", target, resp.Status, resp.Header.Get("X-Tkbox-Reason"), why)
		}
		for _, ip := range []string{"10.0.0.7", "192.168.1.5"} {
			if strings.Contains(b, ip) {
				t.Errorf("%s: refusal tells the guest the private address %s", target, ip)
			}
		}
	}
	found := false
	for _, ev := range e.sink.events() {
		if ev.Kind == EventDenied && ev.Host == "internal.example" && strings.Contains(ev.Reason, "10.0.0.7") {
			found = true
		}
	}
	if !found {
		t.Error("the denied event does not record the refused address")
	}
	e.stop()
	if len(e.dec.Requests) != 0 {
		t.Errorf("the Decider was asked about refused addresses: %+v", e.dec.Requests)
	}
}

func TestOffAllowlistResolvedAfterDecision(t *testing.T) {
	checkGoroutines(t)
	port := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), "example.com")
	e := newEnv(t, func(c *Config) {
		c.Decider = &egressfake.Decider{Func: func(ctx context.Context, r Request) (Verdict, error) {
			if r.OnAllowlist || len(r.Addrs) != 0 {
				return Verdict{Reason: "unexpected request"}, nil
			}
			return Verdict{Allow: true, Reason: "approved by a person"}, nil
		}}
	})
	e.res.set("private.example", "10.1.1.1")
	resp, err := e.client().Get("https://example.com:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); b != "ok" {
		t.Fatalf("body %q", b)
	}
	// Approved, but it resolves privately: still refused.
	_, _, r2 := e.rawConnect("private.example:443")
	if r2.StatusCode != 403 || !strings.Contains(r2.Header.Get("X-Tkbox-Reason"), "private") {
		t.Errorf("approved private host: %s %q", r2.Status, r2.Header.Get("X-Tkbox-Reason"))
	}
	r2.Body.Close()
}

func TestIPv4MappedAnswerExempted(t *testing.T) {
	checkGoroutines(t)
	port := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "mapped") }), "mapped.example")
	e := newEnv(t, func(c *Config) { c.Allow = []string{"mapped.example:" + port} })
	e.res.set("mapped.example", "::ffff:127.0.0.1")
	resp, err := e.client().Get("https://mapped.example:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); b != "mapped" {
		t.Fatalf("body %q", b)
	}
	e.stop()
	if a := e.dec.Requests[0].Addrs; len(a) != 1 || a[0] != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("Addrs %v, want the unmapped address", a)
	}
}

// An IPv4-mapped literal is matched on the allowlist as its IPv4 address, so the Decider (and the signer's WebFetch
// url) must name the IPv4 address too: a rule keyed on 127.0.0.1 would otherwise not see [::ffff:127.0.0.1].
func TestIPv4MappedLiteralReachesDeciderUnmapped(t *testing.T) {
	checkGoroutines(t)
	e := newEnv(t, func(c *Config) { c.Allow = []string{"127.0.0.1:8443"} })
	e.dec.Func = func(context.Context, Request) (Verdict, error) {
		return Verdict{Reason: "test refuses everything"}, nil
	}
	for _, target := range []string{"[::ffff:127.0.0.1]:8443", "[::FFFF:7f00:1]:8443"} {
		_, _, resp := e.rawConnect(target)
		if b := body(t, resp); resp.StatusCode != 403 || strings.Contains(b, "ffff") {
			t.Errorf("%s: %s %q", target, resp.Status, b)
		}
	}
	e.stop()
	if len(e.dec.Requests) != 2 {
		t.Fatalf("decider asked %d times", len(e.dec.Requests))
	}
	for _, r := range e.dec.Requests {
		if r.Host != "127.0.0.1" || !strings.HasSuffix(r.URL, "://127.0.0.1:8443") || !r.OnAllowlist {
			t.Errorf("decider request %+v, want host 127.0.0.1 on the allowlist", r)
		}
	}
	for _, ev := range e.sink.events() {
		if strings.Contains(ev.Host, "ffff") {
			t.Errorf("event names the mapped form: %+v", ev)
		}
	}
}

func TestMetadataRefusedOverPlainHTTP(t *testing.T) {
	checkGoroutines(t)
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"169.254.169.254"}
		c.AllowPrivate = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	})
	c := e.dialProxy()
	io.WriteString(c, "GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 || !strings.Contains(body(t, resp), "metadata") {
		t.Errorf("metadata over plain HTTP: %s", resp.Status)
	}
}

// secretEnv runs an upstream that records what it receives, with GH bound to example.com in Authorization.
type recorder struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []string
}

func (r *recorder) handler(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.body = append(r.body, string(b))
	r.mu.Unlock()
	w.Header().Set("X-Echo-Auth", req.Header.Get("Authorization"))
	io.WriteString(w, "ok")
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

func secretEnv(t *testing.T, mutate func(*Config, *Secret, *Secret)) (*env, *recorder, string, Secret, Secret) {
	t.Helper()
	rec := &recorder{}
	port := startTLS(t, http.HandlerFunc(rec.handler), "example.com", "other.example")
	gh := mkSecret(t, "GH", "Authorization", "example.com")
	other := mkSecret(t, "OTHER", "", "other.example")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + port, "other.example:" + port}
		if mutate != nil {
			mutate(c, &gh, &other)
		}
		c.Secrets = []Secret{gh, other}
	})
	return e, rec, port, gh, other
}

func TestSecretSwapInBoundHeader(t *testing.T) {
	checkGoroutines(t)
	e, rec, port, gh, _ := secretEnv(t, nil)
	cl := e.client()
	req, _ := http.NewRequest("GET", "https://example.com:"+port+"/repos/x?page=2", nil)
	req.Header.Set("Authorization", "Bearer "+gh.Placeholder)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); b != "ok" || resp.StatusCode != 200 {
		t.Fatalf("%s %q", resp.Status, b)
	}
	if !strings.Contains(resp.TLS.PeerCertificates[0].Issuer.CommonName, "box-test") {
		t.Error("bound host was not intercepted")
	}
	if got := rec.reqs[0].Header.Get("Authorization"); got != "Bearer "+gh.Value {
		t.Errorf("upstream got Authorization %q", got)
	}
	if echo := resp.Header.Get("X-Echo-Auth"); echo != "Bearer "+gh.Placeholder {
		t.Errorf("echoed value not redacted back to the placeholder: %q", echo)
	}
	if h := rec.reqs[0].Header.Get("Proxy-Authorization"); h != "" {
		t.Error("Proxy-Authorization forwarded")
	}

	// git's form: Basic base64("x-access-token:<token>").
	req, _ = http.NewRequest("GET", "https://example.com:"+port+"/info/refs", nil)
	req.SetBasicAuth("x-access-token", gh.Placeholder)
	resp, err = cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
	u, p, ok := rec.reqs[1].BasicAuth()
	if !ok || u != "x-access-token" || p != gh.Value {
		t.Errorf("upstream basic auth %q %q %v", u, p, ok)
	}
	use := e.waitKind(EventSecretUse)
	if use.Secret != "GH" || use.Host != "example.com" || use.Path != "/repos/x" {
		t.Errorf("secret.use %+v", use)
	}
}

func TestSecretLeakRefused(t *testing.T) {
	checkGoroutines(t)
	e, rec, port, gh, other := secretEnv(t, nil)
	cases := []struct {
		name   string
		build  func() *http.Request
		secret string
		reason string
	}{
		{"unbound host", func() *http.Request {
			r, _ := http.NewRequest("GET", "https://example.com:"+port+"/", nil)
			r.Header.Set("X-Key", other.Placeholder)
			return r
		}, "OTHER", "not bound to this host"},
		{"wrong header", func() *http.Request {
			r, _ := http.NewRequest("GET", "https://example.com:"+port+"/", nil)
			r.Header.Set("X-Api-Key", gh.Placeholder)
			return r
		}, "GH", "only sent in the Authorization header"},
		{"bound header to unbound host", func() *http.Request {
			r, _ := http.NewRequest("GET", "https://other.example:"+port+"/", nil)
			r.Header.Set("Authorization", "token "+gh.Placeholder)
			return r
		}, "GH", "not bound to this host"},
		{"query", func() *http.Request {
			r, _ := http.NewRequest("GET", "https://example.com:"+port+"/?access_token="+gh.Placeholder, nil)
			return r
		}, "GH", "in the URL"},
		{"percent-encoded path", func() *http.Request {
			r, _ := http.NewRequest("GET", "https://example.com:"+port+"/", nil)
			r.URL.RawPath = "/" + strings.Replace(gh.Placeholder, "t", "%74", 1)
			r.URL.Path = "/" + gh.Placeholder
			return r
		}, "GH", "in the URL"},
		{"body", func() *http.Request {
			r, _ := http.NewRequest("POST", "https://example.com:"+port+"/", strings.NewReader(strings.Repeat("x", 50000)+gh.Placeholder+"tail"))
			return r
		}, "GH", "request body"},
		{"basic auth unbound", func() *http.Request {
			r, _ := http.NewRequest("GET", "https://other.example:"+port+"/", nil)
			r.SetBasicAuth("u", gh.Placeholder)
			return r
		}, "GH", "not bound to this host"},
	}
	for _, c := range cases {
		resp, err := e.client().Do(c.build())
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		b := body(t, resp)
		if resp.StatusCode != 403 || !strings.Contains(b, c.reason) || !strings.Contains(resp.Header.Get("X-Tkbox-Reason"), c.reason) {
			t.Errorf("%s: %s %q", c.name, resp.Status, b)
		}
		if strings.Contains(b, gh.Value) || strings.Contains(b, other.Value) {
			t.Errorf("%s: refusal carries a value", c.name)
		}
	}
	rec.mu.Lock()
	for i, r := range rec.reqs {
		all := r.URL.String() + fmt.Sprint(r.Header) + rec.body[i]
		for _, s := range []Secret{gh, other} {
			if strings.Contains(all, s.Placeholder) || strings.Contains(all, s.Value) {
				t.Errorf("upstream received secret %s: %s", s.Name, r.URL)
			}
		}
	}
	rec.mu.Unlock()
	leaks := 0
	for _, ev := range e.sink.events() {
		if ev.Kind == EventSecretLeak {
			leaks++
			if ev.Secret == "" || ev.Reason == "" {
				t.Errorf("leak event %+v", ev)
			}
		}
		if ev.Kind == EventSecretUse {
			t.Errorf("secret used during leak tests: %+v", ev)
		}
	}
	if leaks != len(cases) {
		t.Errorf("%d leak events for %d cases", leaks, len(cases))
	}
}

func TestPlaceholderInConnectHost(t *testing.T) {
	checkGoroutines(t)
	e, _, _, gh, _ := secretEnv(t, nil)
	for _, h := range []string{gh.Placeholder + ".evil.com:443", strings.ToUpper(gh.Placeholder) + ".evil.com:443"} {
		_, _, resp := e.rawConnect(h)
		b := body(t, resp)
		if resp.StatusCode != 403 || !strings.Contains(b, "CONNECT host") || strings.Contains(strings.ToLower(b), strings.ToLower(gh.Placeholder)) {
			t.Errorf("%s: %s %q", h, resp.Status, b)
		}
	}
	ev := e.waitKind(EventSecretLeak)
	if ev.Secret != "GH" || !strings.Contains(ev.Host, "[secret GH]") {
		t.Errorf("leak event %+v", ev)
	}
	for _, l := range e.res.lookups() {
		if strings.Contains(strings.ToLower(l), "tkbox_") {
			t.Errorf("placeholder host was resolved: %s", l)
		}
	}
}

func TestSNIMismatch(t *testing.T) {
	checkGoroutines(t)
	e, rec, port, _, _ := secretEnv(t, nil)
	for _, sni := range []string{"other.example", ""} {
		c, br, resp := e.rawConnect("example.com:" + port)
		if resp.StatusCode != 200 {
			t.Fatal(resp.Status)
		}
		tc := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err := tc.Handshake(); err == nil {
			t.Errorf("SNI %q: handshake succeeded", sni)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := 0
		for _, ev := range e.sink.events() {
			if ev.Kind == EventDenied && (strings.Contains(ev.Reason, "is not the CONNECT host") || strings.Contains(ev.Reason, "no server name")) {
				n++
			}
		}
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SNI refusals not recorded: %+v", e.sink.events())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if rec.count() != 0 {
		t.Error("upstream reached")
	}
}

func TestHostHeaderMismatch(t *testing.T) {
	checkGoroutines(t)
	e, rec, port, _, _ := secretEnv(t, nil)
	tc, br := e.tunnelTLS("example.com:"+port, "example.com")
	for _, host := range []string{"other.example:" + port, "example.com:1"} {
		fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		b := body(t, resp)
		if resp.StatusCode != 403 || !strings.Contains(b, "does not match the tunnel's host") {
			t.Errorf("Host %s: %s %q", host, resp.Status, b)
		}
		tc, br = e.tunnelTLS("example.com:"+port, "example.com")
	}
	// The right Host, with and without the port, works on one keep-alive tunnel.
	for _, host := range []string{"example.com:" + port, "EXAMPLE.com.:" + port} {
		fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		if b := body(t, resp); resp.StatusCode != 200 || b != "ok" {
			t.Errorf("Host %s: %s %q", host, resp.Status, b)
		}
	}
	tc.Close()
	if rec.count() != 2 {
		t.Errorf("upstream saw %d requests, want 2", rec.count())
	}
}

func TestStreamingAndModelCall(t *testing.T) {
	checkGoroutines(t)
	release := make(chan struct{})
	port := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		io.WriteString(w, "data: two\n\n")
	}), "example.com")
	key := mkSecret(t, "ANTHROPIC_API_KEY", "X-Api-Key", "example.com")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + port}
		c.ModelHosts = []string{"example.com"}
		c.Secrets = []Secret{key}
	})
	req, _ := http.NewRequest("POST", "https://example.com:"+port+"/v1/messages?beta=true", strings.NewReader(`{"stream":true}`))
	req.Header.Set("X-Api-Key", key.Placeholder)
	resp, err := e.client().Do(req)
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
			t.Fatalf("first line %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the first event did not arrive before the upstream finished: response is buffered")
	}
	close(release)
	rest, _ := io.ReadAll(r)
	resp.Body.Close()
	if !strings.Contains(string(rest), "data: two") {
		t.Fatalf("rest %q", rest)
	}
	mc := e.waitKind(EventModelCall)
	if mc.Host != "example.com" || mc.Path != "/v1/messages" || mc.Status != 200 || mc.BytesIn == 0 || mc.BytesOut == 0 || mc.Method != "POST" {
		t.Errorf("model.call %+v", mc)
	}
}

func TestPlainHTTP(t *testing.T) {
	checkGoroutines(t)
	rec := &recorder{}
	port := startHTTP(t, http.HandlerFunc(rec.handler))
	gh := mkSecret(t, "GH", "", "example.com")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + port}
		c.Secrets = []Secret{gh}
	})
	c := e.dialProxy()
	fmt.Fprintf(c, "GET http://example.com:%s/p/a?q=1 HTTP/1.1\r\nHost: evil.example\r\nProxy-Authorization: Basic eDp5\r\nConnection: keep-alive, X-Drop\r\nX-Drop: 1\r\nUser-Agent: apt\r\n\r\n", port)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 200 || b != "ok" || !resp.Close {
		t.Fatalf("%s %q close=%v", resp.Status, b, resp.Close)
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Errorf("connection not closed after one request: %v", err)
	}
	got := rec.reqs[0]
	if got.Host != "example.com:"+port || got.RequestURI != "/p/a?q=1" || got.Header.Get("Proxy-Authorization") != "" ||
		got.Header.Get("X-Drop") != "" || got.UserAgent() != "apt" {
		t.Errorf("upstream got Host %q URI %q headers %v", got.Host, got.RequestURI, got.Header)
	}
	closed := e.waitKind(EventClosed)
	if closed.Method != "GET" || closed.Path != "/p/a" || closed.Status != 200 || closed.BytesIn == 0 {
		t.Errorf("closed %+v", closed)
	}

	// A placeholder in plain HTTP is a leak, bound host or not.
	c = e.dialProxy()
	fmt.Fprintf(c, "GET http://example.com:%s/ HTTP/1.1\r\nAuthorization: Bearer %s\r\n\r\n", port, gh.Placeholder)
	resp, err = http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 403 || !strings.Contains(b, "plain HTTP") {
		t.Errorf("plain leak: %s %q", resp.Status, b)
	}
	// In the body too.
	c = e.dialProxy()
	payload := gh.Placeholder + strings.Repeat("y", 10)
	fmt.Fprintf(c, "POST http://example.com:%s/ HTTP/1.1\r\nContent-Length: %d\r\n\r\n%s", port, len(payload), payload)
	resp, err = http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 403 || !strings.Contains(b, "plain-HTTP request body") {
		t.Errorf("plain body leak: %s %q", resp.Status, b)
	}
	// The body leak's head may reach the upstream (bodies stream); the placeholder itself never does.
	rec.mu.Lock()
	for i, b := range rec.body {
		if strings.Contains(b, gh.Placeholder) || strings.Contains(fmt.Sprint(rec.reqs[i].Header), gh.Placeholder) {
			t.Errorf("upstream received the placeholder in request %d", i)
		}
	}
	n := len(rec.reqs)
	rec.mu.Unlock()
	if n > 2 {
		t.Errorf("upstream saw %d requests, want at most 2", n)
	}

	// Origin form and https:// in absolute form are refused with directions.
	for _, line := range []string{"GET / HTTP/1.1\r\nHost: example.com", "GET https://example.com/ HTTP/1.1\r\nHost: example.com"} {
		c = e.dialProxy()
		io.WriteString(c, line+"\r\n\r\n")
		resp, err = http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		if b := body(t, resp); resp.StatusCode != 400 || !(strings.Contains(b, "HTTP_PROXY") || strings.Contains(b, "HTTPS_PROXY")) {
			t.Errorf("%q: %s %q", line, resp.Status, b)
		}
	}
}

func TestIdleTimeout(t *testing.T) {
	checkGoroutines(t)
	port := startHold(t)
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + port}
		c.IdleTimeout = 200 * time.Millisecond
	})
	c, br, resp := e.rawConnect("example.com:" + port)
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	start := time.Now()
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("read data from a silent upstream")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("idle connection closed after %v", d)
	}
	c.Close()
	ev := e.waitKind(EventClosed)
	if !strings.Contains(ev.Reason, "IdleTimeout") {
		t.Errorf("closed reason %q", ev.Reason)
	}
}

func TestMaxConns(t *testing.T) {
	checkGoroutines(t)
	asked := make(chan struct{}, 1)
	e := newEnv(t, func(c *Config) {
		c.MaxConns = 1
		c.Decider = &egressfake.Decider{Func: func(ctx context.Context, r Request) (Verdict, error) {
			asked <- struct{}{}
			<-ctx.Done()
			return Verdict{}, ctx.Err()
		}}
	})
	c1 := e.dialProxy()
	io.WriteString(c1, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	<-asked
	c2 := e.dialProxy()
	io.WriteString(c2, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c2), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 503 || !strings.Contains(b, "MaxConns") || !strings.Contains(b, "1 open connections") || strings.Contains(b, "max_conns") {
		t.Errorf("%s %q", resp.Status, b)
	}
	e.waitKind(EventDenied)
	c1.Close()
}

func TestDecideTimeoutAndError(t *testing.T) {
	checkGoroutines(t)
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com", "other.example"}
		c.DecideTimeout = 150 * time.Millisecond
		c.Decider = &egressfake.Decider{Func: func(ctx context.Context, r Request) (Verdict, error) {
			if r.Host == "other.example" {
				return Verdict{Allow: true}, errors.New("signer unreachable")
			}
			<-ctx.Done() // a person who never answers
			return Verdict{Allow: true}, nil
		}}
	})
	_, _, resp := e.rawConnect("example.com:443")
	if b := body(t, resp); resp.StatusCode != 403 || !strings.Contains(b, "no decision within 150ms") {
		t.Errorf("timeout: %s %q", resp.Status, b)
	}
	_, _, resp = e.rawConnect("other.example:443")
	if b := body(t, resp); resp.StatusCode != 403 || !strings.Contains(b, "could not get a decision") || strings.Contains(b, "signer unreachable") {
		t.Errorf("error: %s %q", resp.Status, b)
	}
	found := false
	for _, ev := range e.sink.events() {
		if ev.Kind == EventDenied && strings.Contains(ev.Reason, "signer unreachable") {
			found = true
		}
	}
	if !found {
		t.Error("decider error not recorded")
	}
}

func TestClientGoneCancelsDecision(t *testing.T) {
	checkGoroutines(t)
	cancelled := make(chan time.Duration, 1)
	asked := make(chan struct{}, 1)
	e := newEnv(t, func(c *Config) {
		c.DecideTimeout = time.Minute
		c.Decider = &egressfake.Decider{Func: func(ctx context.Context, r Request) (Verdict, error) {
			start := time.Now()
			asked <- struct{}{}
			<-ctx.Done()
			cancelled <- time.Since(start)
			return Verdict{}, ctx.Err()
		}}
	})
	c := e.dialProxy()
	io.WriteString(c, "CONNECT unknown.example:443 HTTP/1.1\r\nHost: unknown.example:443\r\n\r\n")
	<-asked
	c.Close()
	select {
	case d := <-cancelled:
		if d > 5*time.Second {
			t.Errorf("decision cancelled after %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("decision not cancelled when the client hung up")
	}
	ev := e.waitKind(EventDenied)
	if !strings.Contains(ev.Reason, "disconnected") {
		t.Errorf("denied reason %q", ev.Reason)
	}
}

func TestCloseEndsLiveConnections(t *testing.T) {
	checkGoroutines(t)
	port := startHold(t)
	e := newEnv(t, func(c *Config) { c.Allow = []string{"example.com:" + port} })
	_, br, resp := e.rawConnect("example.com:" + port)
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	done := make(chan error, 1)
	go func() {
		_, err := br.ReadByte()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	e.stop()
	select {
	case err := <-done:
		if err == nil {
			t.Error("read succeeded after Close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close left the tunnel open")
	}
}

func TestHeadTooLarge(t *testing.T) {
	checkGoroutines(t)
	e := newEnv(t, func(c *Config) { c.MaxHeaderBytes = 2048 })
	c := e.dialProxy()
	fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\nX-Big: %s\r\n\r\n", strings.Repeat("a", 4096))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 431 || !strings.Contains(b, "2048 bytes (MaxHeaderBytes)") {
		t.Errorf("%s %q", resp.Status, b)
	}
}

func TestInspectAll(t *testing.T) {
	checkGoroutines(t)
	e, rec, port, _, other := secretEnv(t, func(c *Config, gh, other *Secret) {
		c.Inspect = InspectAll
		gh.Hosts = []string{"api.github.com"}
	})
	resp, err := e.client().Get("https://example.com:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
	if !strings.Contains(resp.TLS.PeerCertificates[0].Issuer.CommonName, "box-test") {
		t.Error("inspect all did not intercept")
	}
	req, _ := http.NewRequest("GET", "https://example.com:"+port+"/", nil)
	req.Header.Set("Cookie", "k="+other.Placeholder)
	resp, err = e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 403 || !strings.Contains(b, "not bound") {
		t.Errorf("%s %q", resp.Status, b)
	}
	if rec.count() != 1 {
		t.Errorf("upstream saw %d requests", rec.count())
	}
}

func TestUpstreamUntrusted(t *testing.T) {
	checkGoroutines(t)
	e, rec, port, gh, _ := secretEnv(t, func(c *Config, _, _ *Secret) { c.UpstreamRoots = x509.NewCertPool() })
	req, _ := http.NewRequest("GET", "https://example.com:"+port+"/", nil)
	req.Header.Set("Authorization", gh.Placeholder)
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 502 || !strings.Contains(b, "TLS to the host failed") {
		t.Errorf("%s %q", resp.Status, b)
	}
	if rec.count() != 0 {
		t.Error("request reached an unverified upstream")
	}
}

func TestUpgradeSplice(t *testing.T) {
	checkGoroutines(t)
	port := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "echo" {
			http.Error(w, "bad upgrade", 400)
			return
		}
		c, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		buf := make([]byte, 4)
		if _, err := io.ReadFull(brw, buf); err == nil {
			c.Write(buf)
		}
	}), "example.com")
	// An inspected host with no bound secret (upgrades to a bound host are refused: TestUpgradeToBoundHostRefused).
	gh := mkSecret(t, "GH", "Authorization", "api.github.com")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + port}
		c.Secrets = []Secret{gh}
		c.Inspect = InspectAll
	})
	tc, br := e.tunnelTLS("example.com:"+port, "example.com")
	fmt.Fprintf(tc, "GET /ws HTTP/1.1\r\nHost: example.com:%s\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n", port)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 || resp.Header.Get("Upgrade") != "echo" {
		t.Fatalf("%s %v", resp.Status, resp.Header)
	}
	io.WriteString(tc, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q %v", buf, err)
	}
	tc.Close()
	e.waitKind(EventClosed)
}

func TestNonTLSOnBoundHostTunnels(t *testing.T) {
	checkGoroutines(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 8)
		n, _ := c.Read(buf)
		c.Write(buf[:n])
	}()
	port := port(t, l.Addr())
	gh := mkSecret(t, "GH", "", "example.com")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + port}
		c.Secrets = []Secret{gh}
	})
	c, br, resp := e.rawConnect("example.com:" + port)
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	io.WriteString(c, "SSH-2.0\n")
	line, err := br.ReadString('\n')
	if err != nil || line != "SSH-2.0\n" {
		t.Fatalf("got %q %v", line, err)
	}
}

func TestEchoedValueNeverReachesGuestOrEvents(t *testing.T) {
	checkGoroutines(t)
	port := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		// A broken upstream that quotes the credential where net/http's parse error quotes it back.
		io.WriteString(c, "HTTP/1.1 "+r.Header.Get("Authorization")+" OK\r\n\r\n")
	}), "example.com")
	gh := mkSecret(t, "GH", "Authorization", "example.com")
	e := newEnv(t, func(c *Config) {
		c.Allow = []string{"example.com:" + port}
		c.Secrets = []Secret{gh}
	})
	tc, br := e.tunnelTLS("example.com:"+port, "example.com")
	fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: example.com:%s\r\nAuthorization: %s\r\n\r\n", port, gh.Placeholder)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := body(t, resp)
	if resp.StatusCode != 502 || strings.Contains(b, gh.Value) || strings.Contains(fmt.Sprint(resp.Header), gh.Value) {
		t.Errorf("%s %q", resp.Status, b)
	}
	e.waitKind(EventClosed) // checkEvents verifies no event holds the value
}

func TestPlaceholderInInnerHostIsLeak(t *testing.T) {
	checkGoroutines(t)
	e, rec, port, gh, _ := secretEnv(t, nil)
	tc, br := e.tunnelTLS("example.com:"+port, "example.com")
	fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: %s.example.com\r\n\r\n", gh.Placeholder)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 403 || !strings.Contains(b, "Host header") {
		t.Errorf("%s %q", resp.Status, b)
	}
	if ev := e.waitKind(EventSecretLeak); ev.Secret != "GH" {
		t.Errorf("leak %+v", ev)
	}
	if rec.count() != 0 {
		t.Error("upstream reached")
	}
}
