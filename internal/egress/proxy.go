package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Limits the proxy enforces beyond Config.
const (
	maxResponseHeadBytes = 1 << 20         // an upstream response head
	maxInterim           = 8               // 1xx responses before the final one
	tlsPeekTimeout       = 5 * time.Second // waiting for a tunnel's TLS ClientHello
	maxHelloBytes        = 96 << 10        // the most Box reads to see a ClientHello whole
	lingerTimeout        = 250 * time.Millisecond
	busyEventEvery       = time.Second // at most one egress.denied per second for MaxConns refusals
	eventWindow          = time.Second // the window for the two limits below
	deniedPerWindow      = 20          // egress.denied events recorded one by one per window; the rest are summed
)

var errClosed = errors.New("egress: proxy is closed")

// Proxy is one box's egress proxy.
type Proxy struct {
	cfg           Config
	allow         patterns
	models        patterns
	secrets       []*secretRule
	reqMatch      *matcher // placeholders and secret values, for request bodies
	valMatch      *matcher // secret values, for responses and request heads
	resolver      Resolver
	blockPrefixes []netip.Prefix
	allowPrivate  []netip.Prefix
	sem           chan struct{}
	lim           eventLimiter

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	closed    bool
	listeners map[net.Listener]struct{}
	sessions  map[*session]struct{}
	wg        sync.WaitGroup

	busyMu   sync.Mutex
	busyLast time.Time
	busyN    int
}

// New validates cfg and returns a proxy. A missing Decider or Sink, a secret without hosts, or a missing CA when
// MITM is needed is an error.
func New(cfg Config) (*Proxy, error) {
	if cfg.Decider == nil {
		return nil, errors.New("egress: Config.Decider is required")
	}
	if cfg.Sink == nil {
		return nil, errors.New("egress: Config.Sink is required")
	}
	switch cfg.Inspect {
	case "":
		cfg.Inspect = InspectBound
	case InspectBound, InspectAll:
	default:
		return nil, fmt.Errorf("egress: inspect %q: want %q or %q", cfg.Inspect, InspectBound, InspectAll)
	}
	for _, d := range []struct {
		v   *time.Duration
		def time.Duration
		n   string
	}{
		{&cfg.DialTimeout, DefaultDialTimeout, "DialTimeout"},
		{&cfg.IdleTimeout, DefaultIdleTimeout, "IdleTimeout"},
		{&cfg.DecideTimeout, DefaultDecideTimeout, "DecideTimeout"},
	} {
		if *d.v < 0 {
			return nil, fmt.Errorf("egress: %s is negative", d.n)
		}
		if *d.v == 0 {
			*d.v = d.def
		}
	}
	if cfg.MaxConns < 0 || cfg.MaxHeaderBytes < 0 {
		return nil, errors.New("egress: MaxConns and MaxHeaderBytes must not be negative")
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.MaxHeaderBytes == 0 {
		cfg.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if cfg.MaxHeaderBytes < 1024 {
		return nil, fmt.Errorf("egress: MaxHeaderBytes %d is too small (minimum 1024)", cfg.MaxHeaderBytes)
	}
	p := &Proxy{
		cfg:       cfg,
		resolver:  cfg.Resolver,
		sem:       make(chan struct{}, cfg.MaxConns),
		listeners: map[net.Listener]struct{}{},
		sessions:  map[*session]struct{}{},
	}
	if p.resolver == nil {
		p.resolver = net.DefaultResolver
	}
	var err error
	if p.allow, err = parsePatterns("allow entry", cfg.Allow, true); err != nil {
		return nil, err
	}
	if p.models, err = parsePatterns("model host", cfg.ModelHosts, false); err != nil {
		return nil, err
	}
	if p.blockPrefixes, err = normPrefixes("BlockPrefixes", cfg.BlockPrefixes); err != nil {
		return nil, err
	}
	if p.allowPrivate, err = normPrefixes("AllowPrivate", cfg.AllowPrivate); err != nil {
		return nil, err
	}
	names, phs := map[string]bool{}, map[string]bool{}
	for _, s := range cfg.Secrets {
		r, err := newSecretRule(s)
		if err != nil {
			return nil, err
		}
		if names[r.Name] || phs[r.lowerPH] {
			return nil, fmt.Errorf("egress: secret %s is listed twice", r.Name)
		}
		names[r.Name], phs[r.lowerPH] = true, true
		p.secrets = append(p.secrets, r)
	}
	vals := p.valuePatterns()
	p.valMatch = newMatcher(vals)
	reqPats := vals
	for _, r := range p.secrets {
		reqPats = append(reqPats, pattern{s: []byte(r.Placeholder), rule: r, kind: patPlaceholder})
	}
	p.reqMatch = newMatcher(reqPats)
	if len(p.secrets) > 0 || cfg.Inspect == InspectAll {
		if !cfg.CA.usable() {
			return nil, errors.New("egress: Config.CA is required to swap secrets or inspect traffic (create one with NewCA)")
		}
		for _, r := range p.secrets {
			for _, h := range r.hosts {
				if !cfg.CA.permitsPattern(h) {
					return nil, fmt.Errorf("egress: secret %s host %s is outside the CA's name constraints", r.Name, h)
				}
			}
		}
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p, nil
}

// permitsPattern reports whether every host pattern h matches is one the CA may impersonate.
func (c *CA) permitsPattern(h hostPattern) bool {
	if c.permit == nil {
		return true
	}
	if !h.wildcard {
		return c.permit.matchHost(h.host, h.addr)
	}
	for _, q := range c.permit {
		if q.wildcard && (h.host == q.host || strings.HasSuffix(h.host, "."+q.host)) {
			return true
		}
	}
	return false
}

// Serve accepts connections from l (the box's vsock UDS for PortEgress) until l is closed or Close is called.
func (p *Proxy) Serve(l net.Listener) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		l.Close()
		return errClosed
	}
	p.listeners[l] = struct{}{}
	p.wg.Add(1)
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.listeners, l)
		p.mu.Unlock()
		p.wg.Done()
	}()
	var backoff time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if p.isClosed() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if !retryableAccept(err) {
				return err
			}
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			select {
			case <-time.After(backoff):
			case <-p.ctx.Done():
				return nil
			}
			continue
		}
		backoff = 0
		select {
		case p.sem <- struct{}{}:
			p.start(c, false)
		default:
			p.start(c, true)
		}
	}
}

func retryableAccept(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM)
}

func (p *Proxy) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// Close stops accepting and closes every open connection.
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.wg.Wait()
		return nil
	}
	p.closed = true
	ls := make([]net.Listener, 0, len(p.listeners))
	for l := range p.listeners {
		ls = append(ls, l)
	}
	ss := make([]*session, 0, len(p.sessions))
	for s := range p.sessions {
		ss = append(ss, s)
	}
	p.mu.Unlock()
	p.cancel()
	for _, l := range ls {
		l.Close()
	}
	for _, s := range ss {
		s.closeAll()
	}
	p.wg.Wait()
	p.lim.close(p) // record what the limits were still holding
	return nil
}

// start runs one guest connection. busy means MaxConns was reached and the connection only gets a 503.
func (p *Proxy) start(c net.Conn, busy bool) {
	s := &session{p: p, raw: c, closers: []io.Closer{c}}
	s.watch = newIdleWatch(p.cfg.IdleTimeout, func() { s.idle.Store(true); s.closeAll() })
	s.client = &meteredConn{Conn: c, w: s.watch}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		s.watch.stop()
		c.Close()
		if !busy {
			<-p.sem
		}
		return
	}
	p.sessions[s] = struct{}{}
	p.wg.Add(1)
	p.mu.Unlock()
	go func() {
		defer p.wg.Done()
		defer func() {
			s.watch.stop()
			s.closeAll()
			p.mu.Lock()
			delete(p.sessions, s)
			p.mu.Unlock()
			if !busy {
				<-p.sem
			}
		}()
		defer func() {
			if r := recover(); r != nil {
				p.emit(Event{Kind: EventClosed, Reason: "internal error in the egress proxy (panic); connection closed"})
			}
		}()
		if busy {
			p.serveBusy(s)
			return
		}
		p.handle(s)
	}()
}

// serveBusy answers a connection over MaxConns.
func (p *Proxy) serveBusy(s *session) {
	p.busyMu.Lock()
	p.busyN++
	var n int
	if time.Since(p.busyLast) >= busyEventEvery {
		n, p.busyN, p.busyLast = p.busyN, 0, time.Now()
	}
	p.busyMu.Unlock()
	reason := fmt.Sprintf("the box already has %d open connections (MaxConns)", p.cfg.MaxConns)
	if n > 0 {
		p.emit(Event{Kind: EventDenied, Reason: fmt.Sprintf("%s; %d connection(s) refused", reason, n)})
	}
	s.raw.SetDeadline(time.Now().Add(2 * time.Second))
	p.writeRefusal(s.raw, http.StatusServiceUnavailable, target{}, reason,
		"Close idle connections or reuse keep-alive connections.")
	s.linger(nil)
}

// target is where a request wants to go.
type target struct {
	scheme string
	host   string     // canonical
	addr   netip.Addr // set for IP literals
	port   int
}

func (t target) url() string { return t.scheme + "://" + hostPort(t.host, t.port) }

func (t target) who() string {
	switch {
	case t.host == "":
		return "request"
	case t.port == 0:
		return t.host
	}
	return hostPort(t.host, t.port)
}

// handle reads the first request head and dispatches it.
func (p *Proxy) handle(s *session) {
	hl := &headLimiter{r: s.client}
	hl.limit(p.cfg.MaxHeaderBytes)
	br := bufio.NewReaderSize(hl, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		p.badHead(s, s.client, hl, err, target{})
		s.linger(br)
		return
	}
	hl.unlimit()
	switch {
	case req.Method == http.MethodConnect:
		p.serveConnect(s, req, br)
	case req.URL.Scheme != "" || req.URL.Host != "":
		p.servePlain(s, req, br)
	default:
		p.deny(s, s.client, target{}, "", "", refusal{status: 400,
			reason: "this is the box's HTTP proxy and the request is not in proxy form",
			todo:   "Point HTTP_PROXY and HTTPS_PROXY at the proxy so clients send CONNECT or absolute-form (http://host/path) requests."})
		s.linger(br)
	}
}

// badHead answers a request head that could not be read. A placeholder seen in the raw bytes is still a leak.
func (p *Proxy) badHead(s *session, w io.Writer, hl *headLimiter, err error, t target) {
	if hl.remain == 0 {
		p.deny(s, w, t, "", "", refusal{status: 431,
			reason: fmt.Sprintf("the request head is larger than %d bytes (MaxHeaderBytes)", p.cfg.MaxHeaderBytes),
			todo:   "Send fewer or smaller headers (large cookies are the usual cause)."})
		return
	}
	if len(hl.rec) == 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isTimeout(err) || errors.Is(err, net.ErrClosed)) {
		return // the client went away between requests
	}
	if f := p.find(string(hl.rec), true); f != nil {
		p.leak(s, w, t, "", "", &leakError{secret: f[0],
			reason: fmt.Sprintf("a placeholder for secret %s is in a malformed request", f[0].Name),
			todo:   "Send well-formed requests and put placeholders only in the bound header."})
		return
	}
	if f := p.findValues(string(hl.rec)); f != nil {
		p.leak(s, w, t, "", "", valueLeak(f[0], "a malformed request", ""))
		return
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isTimeout(err) || errors.Is(err, net.ErrClosed) {
		return
	}
	p.deny(s, w, t, "", "", refusal{status: 400, reason: "malformed HTTP request: " + printable(err.Error(), 200),
		todo: "Send an HTTP/1.1 request."})
}

// refusal is a reason Box answers the guest itself.
type refusal struct {
	status int
	reason string // shown to the guest and recorded
	detail string // recorded instead of reason when set (e.g. a private address the guest should not learn)
	todo   string
	rules  []string
}

// deny records egress.denied and answers the guest.
func (p *Proxy) deny(s *session, w io.Writer, t target, method, path string, r refusal) {
	rec := r.reason
	if r.detail != "" {
		rec = r.detail
	}
	p.emit(Event{Kind: EventDenied, Host: t.host, Port: t.port, Method: method, Path: path, Reason: rec, RuleIDs: r.rules})
	p.writeRefusal(w, r.status, t, r.reason, r.todo)
}

// leak records secret.leak and answers 403.
func (p *Proxy) leak(s *session, w io.Writer, t target, method, path string, l *leakError) {
	p.emit(Event{Kind: EventSecretLeak, Host: t.host, Port: t.port, Method: method, Path: path, Secret: l.secret.Name, Reason: l.reason})
	p.writeRefusal(w, http.StatusForbidden, t, l.reason, l.todo)
}

// writeRefusal writes "tkbox: <host>:<port> refused: <reason>. <what to do>" with the reason in X-Tkbox-Reason.
func (p *Proxy) writeRefusal(w io.Writer, status int, t target, reason, todo string) {
	if w == nil {
		return
	}
	reason = strings.TrimRight(reason, ". ")
	body := p.redact(fmt.Sprintf("tkbox: %s refused: %s. %s\n", printable(t.who(), 300), reason, todo))
	hdr := printable(p.redact(reason), 512)
	text := http.StatusText(status)
	if text == "" {
		text = "Error"
	}
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nX-Tkbox-Reason: %s\r\n"+
		"Cache-Control: no-store\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", status, text, hdr, len(body), body)
	io.WriteString(w, resp)
}

// emit stamps and redacts an event and hands it to the sink.
func (p *Proxy) emit(e Event) {
	e.Time = time.Now()
	e.Host = p.redact(e.Host)
	e.Path = p.redact(e.Path)
	e.Method = p.redact(e.Method)
	e.Reason = p.redact(e.Reason)
	switch e.Kind {
	case EventDenied, EventSecretLeak:
		p.lim.emit(p, e)
	default:
		p.cfg.Sink.Emit(e)
	}
}

// serveConnect handles CONNECT host:port.
func (p *Proxy) serveConnect(s *session, req *http.Request, br *bufio.Reader) {
	raw := req.RequestURI
	connectTarget := func() target {
		t := target{host: raw}
		if h, ps, err := net.SplitHostPort(raw); err == nil {
			t.host = h
			t.port, _ = parsePort(ps)
		}
		return t
	}
	if f := p.find(raw, true); f != nil {
		p.leak(s, s.client, connectTarget(), "", "", &leakError{secret: f[0],
			reason: fmt.Sprintf("a placeholder for secret %s is in the CONNECT host", f[0].Name),
			todo:   "Never put a secret in a host name: the lookup alone would send it to that domain's DNS servers."})
		s.linger(br)
		return
	}
	if f := p.findValueTarget(raw); f != nil {
		p.leak(s, s.client, connectTarget(), "", "", valueLeak(f[0], "the CONNECT host",
			"Never put a secret in a host name: the lookup alone would send it to that domain's DNS servers."))
		s.linger(br)
		return
	}
	host, lit, port, err := parseAuthority(raw, 0)
	if err != nil {
		p.deny(s, s.client, target{host: printable(raw, maxHostLen)}, "", "", refusal{status: 400,
			reason: "invalid CONNECT target: " + err.Error(), todo: "Send CONNECT host:port with an ASCII host name (IDNs as punycode)."})
		s.linger(br)
		return
	}
	// The decision comes before the first byte, so the record names only what is known then: a CONNECT to 443 is
	// HTTPS (the tunnel must carry TLS), and one to any other port is a TCP tunnel to that port, which an allow entry
	// naming the port may use for any protocol (SSH, SMTP, or TLS too).
	scheme := "tcp"
	if port == 443 {
		scheme = "https"
	}
	t := target{scheme: scheme, host: host, addr: lit, port: port}
	if req.ContentLength != 0 || len(req.TransferEncoding) > 0 {
		p.deny(s, s.client, t, "", "", refusal{status: 400, reason: "a CONNECT request has a body", todo: "Send CONNECT without a body."})
		s.linger(br)
		return
	}
	if port == 80 {
		// Inside a tunnel the guest would write the Host header and reach any site on that address. In absolute
		// form Box writes Host itself.
		p.deny(s, s.client, t, "", "", refusal{status: 403, reason: "port 80 tunnels are refused: send plain HTTP through the proxy",
			todo: "Set http_proxy (HTTP_PROXY) to the proxy so clients send absolute-form requests (GET http://" + hostPort(host, 80) +
				"/path); Box writes the Host header itself."})
		s.linger(br)
		return
	}
	inspect := p.cfg.Inspect == InspectAll || p.boundSecrets(host, lit)
	if inspect && !p.cfg.CA.Permits(host) {
		p.deny(s, s.client, t, "", "", refusal{status: 403,
			reason: "Box must inspect this host but the box CA may not impersonate it",
			todo:   "Add the host to the box's allow list so the CA covers it."})
		s.linger(br)
		return
	}
	addrs, ok := p.admit(s, s.client, br, t, "", "")
	if !ok {
		s.linger(br)
		return
	}
	up, err := p.dial(p.ctx, addrs, port)
	if err != nil {
		p.failed(s, s.client, t, refusal{status: 502, reason: "could not connect: " + err.Error(),
			todo: "The host did not accept the connection; try again later."})
		s.linger(br)
		return
	}
	s.track(up)
	upm := &meteredConn{Conn: up, w: s.watch}
	if _, err := io.WriteString(s.client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		p.emit(Event{Kind: EventClosed, Host: t.host, Port: t.port, Reason: s.endReason("the client went away")})
		return
	}
	// Only an allow entry that names the port lets something other than TLS through the tunnel.
	rawOK := p.allow.matchExplicitPort(t.host, t.addr, t.port)
	if inspect {
		p.serveMITM(s, t, br, upm, rawOK)
		return
	}
	p.serveTunnel(s, t, br, upm, rawOK)
}

// boundSecrets reports whether any secret is bound to host.
func (p *Proxy) boundSecrets(host string, addr netip.Addr) bool {
	for _, r := range p.secrets {
		if r.hosts.matchHost(host, addr) {
			return true
		}
	}
	return false
}

// failed reports an allowed connection that could not be made: egress.closed with the reason, and the answer.
func (p *Proxy) failed(s *session, w io.Writer, t target, r refusal) {
	p.emit(Event{Kind: EventClosed, Host: t.host, Port: t.port, Reason: r.reason})
	p.writeRefusal(w, r.status, t, r.reason, r.todo)
}

// admit runs the checks every new connection and every plain-HTTP request passes: allowlist, address safety and
// the Decider. On refusal it answers the guest and returns false.
func (p *Proxy) admit(s *session, w io.Writer, br *bufio.Reader, t target, method, path string) ([]netip.Addr, bool) {
	onList := p.allow.match(t.host, t.addr, t.port)
	var addrs []netip.Addr
	// A name off the allowlist is not resolved before the Decider allows it: the lookup itself would carry whatever
	// the guest encoded in the name to that domain's DNS servers.
	if onList || t.addr.IsValid() {
		a, err := p.resolve(p.ctx, t.host, t.addr)
		if err != nil {
			p.deny(s, w, t, method, path, resolveRefusal(err))
			return nil, false
		}
		addrs = a
	}
	v, r := p.decide(s, br, Request{
		BoxID: p.cfg.BoxID, Scheme: t.scheme, Host: t.host, Port: t.port, URL: t.url(),
		OnAllowlist: onList, Addrs: append([]netip.Addr(nil), addrs...),
	})
	if r != nil {
		p.deny(s, w, t, method, path, *r)
		return nil, false
	}
	if !v.Allow {
		reason := strings.TrimSpace(v.Reason)
		if reason == "" {
			reason = "the policy refused it"
		}
		p.deny(s, w, t, method, path, refusal{status: 403, reason: reason, rules: v.RuleIDs,
			todo: "If the job needs this host, add it to the box's allow list (tkbox.yaml or --allow) or ask the operator to approve it with `tkbox approve`."})
		return nil, false
	}
	if addrs == nil {
		a, err := p.resolve(p.ctx, t.host, t.addr)
		if err != nil {
			p.deny(s, w, t, method, path, resolveRefusal(err))
			return nil, false
		}
		addrs = a
	}
	p.emit(Event{Kind: EventAllowed, Host: t.host, Port: t.port, Method: method, Path: path, Reason: v.Reason, RuleIDs: v.RuleIDs})
	return addrs, true
}

func resolveRefusal(err error) refusal {
	var re *resolveError
	if errors.As(err, &re) {
		todo := "Check the host name."
		if re.status == 403 {
			todo = "Box connects only to public addresses; use a public host."
		}
		return refusal{status: re.status, reason: re.public, detail: re.detail, todo: todo}
	}
	return refusal{status: 502, reason: "could not resolve the host name", detail: err.Error(), todo: "Check the host name."}
}

var errClientGone = errors.New("the client disconnected while the connection waited for a decision")

// decide asks the Decider, bounded by DecideTimeout. An error, a timeout or the guest hanging up refuses.
func (p *Proxy) decide(s *session, br *bufio.Reader, req Request) (Verdict, *refusal) {
	ctx, cancel := context.WithTimeout(p.ctx, p.cfg.DecideTimeout)
	defer cancel()
	s.watch.pause()
	defer s.watch.resume()

	// Stop waiting (so the Decider can withdraw an approval prompt) if the guest hangs up.
	var gone atomic.Bool
	peekDone := make(chan struct{})
	go func() {
		defer close(peekDone)
		if _, err := br.Peek(1); err != nil && !isTimeout(err) {
			gone.Store(true)
			cancel()
		}
	}()
	defer func() {
		s.raw.SetReadDeadline(time.Unix(1, 0))
		<-peekDone
		s.raw.SetReadDeadline(time.Time{})
	}()

	type result struct {
		v   Verdict
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{err: errors.New("the decider panicked")}
			}
		}()
		v, err := p.cfg.Decider.Decide(ctx, req)
		ch <- result{v, err}
	}()
	select {
	case res := <-ch:
		if ctx.Err() == nil {
			if res.err != nil {
				return Verdict{}, &refusal{status: 403, reason: "Box could not get a decision for it",
					detail: "the decision failed: " + res.err.Error(),
					todo:   "Check that the Tracekit signer is running; Box refuses what it cannot record."}
			}
			return res.v, nil
		}
	case <-ctx.Done():
	}
	switch {
	case p.ctx.Err() != nil:
		return Verdict{}, &refusal{status: 503, reason: "the box's proxy is shutting down", todo: "The box is stopping."}
	case gone.Load():
		return Verdict{}, &refusal{status: 403, reason: errClientGone.Error(), todo: "Keep the connection open until it is decided."}
	}
	return Verdict{}, &refusal{status: 403, reason: fmt.Sprintf("no decision within %v", p.cfg.DecideTimeout),
		todo: "Ask the operator to approve it with `tkbox approve` while the request waits, or add the host to the box's allow list."}
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// session is one guest connection.
type session struct {
	p      *Proxy
	raw    net.Conn
	client *meteredConn
	watch  *idleWatch
	idle   atomic.Bool

	mu      sync.Mutex
	closers []io.Closer
	done    bool
}

// track closes c with the session.
func (s *session) track(c io.Closer) {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		c.Close()
		return
	}
	s.closers = append(s.closers, c)
	s.mu.Unlock()
}

func (s *session) closeAll() {
	s.mu.Lock()
	cs := s.closers
	s.closers, s.done = nil, true
	s.mu.Unlock()
	for _, c := range cs {
		c.Close()
	}
}

func (s *session) endReason(def string) string {
	switch {
	case s.idle.Load():
		return fmt.Sprintf("idle for %v (IdleTimeout)", s.p.cfg.IdleTimeout)
	case s.p.ctx.Err() != nil:
		return "the box's proxy closed"
	}
	return def
}

// linger half-closes the guest connection and drains what it already sent, so the guest reads our answer instead
// of a reset.
func (s *session) linger(br *bufio.Reader) {
	if !closeWrite(s.client) {
		return
	}
	s.raw.SetReadDeadline(time.Now().Add(lingerTimeout))
	var r io.Reader = s.client
	if br != nil {
		r = br
	}
	io.CopyN(io.Discard, r, 256<<10)
}

// splice copies both ways until both sides are done; a side that ends cleanly is half-closed on the other.
func (s *session) splice(cr io.Reader, cw net.Conn, ur io.Reader, uw net.Conn) (in, out int64) {
	inc := s.pipe(cw, ur)
	out = <-s.pipe(uw, cr)
	in = <-inc
	s.closeAll()
	return in, out
}

// pipe copies src to dst in the background and delivers the byte count when src ends; a clean end half-closes dst,
// anything else closes the session.
func (s *session) pipe(dst net.Conn, src io.Reader) <-chan int64 {
	done := make(chan int64, 1)
	go func() {
		n, err := io.CopyBuffer(writerOnly{dst}, readerOnly{src}, make([]byte, 32<<10))
		if err != nil || !closeWrite(dst) {
			s.closeAll()
		}
		done <- n
	}()
	return done
}

type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

func closeWrite(c any) bool {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite() == nil
	}
	return false
}

// meteredConn feeds the idle watch on every read and write.
type meteredConn struct {
	net.Conn
	w *idleWatch
}

func (c *meteredConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.w.touch()
	}
	return n, err
}

func (c *meteredConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.w.touch()
	}
	return n, err
}

func (c *meteredConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// bufConn reads through a reader that may hold bytes the client sent early (a pipelined or peeked ClientHello).
type bufConn struct {
	net.Conn
	r io.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// countWriter counts bytes written.
type countWriter struct {
	w io.Writer
	n atomic.Int64
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n.Add(int64(n))
	return n, err
}

// headLimiter bounds the bytes read while a request or response head is parsed and records them, so a parse error
// can still be checked for placeholders.
type headLimiter struct {
	r      io.Reader
	remain int64 // < 0: no limit
	rec    []byte
	norec  bool // upstream heads: limit only
}

var errHeadTooLarge = errors.New("head too large")

func (h *headLimiter) Read(b []byte) (int, error) {
	if h.remain == 0 {
		return 0, errHeadTooLarge
	}
	if h.remain > 0 && int64(len(b)) > h.remain {
		b = b[:h.remain]
	}
	n, err := h.r.Read(b)
	if h.remain > 0 {
		h.remain -= int64(n)
		if !h.norec {
			h.rec = append(h.rec, b[:n]...)
		}
	}
	return n, err
}

func (h *headLimiter) limit(n int) { h.remain, h.rec = int64(n), h.rec[:0] }
func (h *headLimiter) unlimit()    { h.remain, h.rec = -1, h.rec[:0] }

// idleWatch closes a session after IdleTimeout without traffic in either direction.
type idleWatch struct {
	d      time.Duration
	base   time.Time
	last   atomic.Int64 // since base, monotonic
	paused atomic.Int32
	onIdle func()

	mu      sync.Mutex
	t       *time.Timer
	stopped bool
}

func newIdleWatch(d time.Duration, onIdle func()) *idleWatch {
	w := &idleWatch{d: d, base: time.Now(), onIdle: onIdle}
	w.mu.Lock()
	w.t = time.AfterFunc(d, w.check)
	w.mu.Unlock()
	return w
}

func (w *idleWatch) touch() { w.last.Store(int64(time.Since(w.base))) }

func (w *idleWatch) pause() { w.paused.Add(1) }

func (w *idleWatch) resume() {
	w.touch()
	w.paused.Add(-1)
}

func (w *idleWatch) check() {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	idle := time.Since(w.base) - time.Duration(w.last.Load())
	if w.paused.Load() > 0 || idle < w.d {
		next := w.d - idle
		if w.paused.Load() > 0 || next <= 0 {
			next = w.d
		}
		w.t.Reset(next)
		w.mu.Unlock()
		return
	}
	w.stopped = true
	w.mu.Unlock()
	w.onIdle()
}

func (w *idleWatch) stop() {
	w.mu.Lock()
	w.stopped = true
	w.t.Stop()
	w.mu.Unlock()
}

// serverTLS is the guest-facing TLS config for one tunnel to t: a leaf for t.host only, HTTP/1.1 only, and the SNI
// must name the CONNECT host.
func (p *Proxy) serverTLS(t target, sniErr *error) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true, // a resumed session would skip the SNI check below
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if err := p.checkSNI(t, hello.ServerName); err != nil {
				*sniErr = err
				return nil, err
			}
			return p.cfg.CA.leaf(t.host)
		},
	}
}

// sniError is an SNI that does not name the CONNECT host.
type sniError struct {
	leak *leakError
	msg  string
}

func (e *sniError) Error() string { return e.msg }

func (p *Proxy) checkSNI(t target, sni string) error {
	if f := p.find(sni, true); f != nil {
		return &sniError{msg: "a placeholder is in the TLS server name", leak: &leakError{secret: f[0],
			reason: fmt.Sprintf("a placeholder for secret %s is in the TLS server name", f[0].Name)}}
	}
	if sni == "" {
		if t.addr.IsValid() {
			return nil // clients send no SNI for IP literals
		}
		return &sniError{msg: "the TLS ClientHello has no server name (SNI); Box needs it to match the CONNECT host"}
	}
	h, a, err := normalizeHost(sni)
	if err != nil || h != t.host || a.IsValid() != t.addr.IsValid() {
		return &sniError{msg: fmt.Sprintf("the TLS server name %q is not the CONNECT host %s", printable(sni, 255), t.host)}
	}
	return nil
}
