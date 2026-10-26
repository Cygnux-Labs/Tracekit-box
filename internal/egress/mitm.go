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
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// serveMITM terminates the guest's TLS with a leaf from the box CA, verifies the upstream, and forwards HTTP/1.1
// requests one by one, swapping placeholders for values where bound and refusing every other placeholder.
// The guest's ClientHello passes the same checks as on any tunnel first. rawOK: the allow entry names the port.
func (p *Proxy) serveMITM(s *session, t target, br *bufio.Reader, up *meteredConn, rawOK bool) {
	// Only TLS can be inspected. With nothing to swap outside TLS, anything else may pass as an opaque tunnel where
	// the allow entry names the port; Inspect "all" promised leak checks, so there it may not.
	nonTLS := ""
	switch {
	case p.cfg.Inspect == InspectAll:
		nonTLS = "inspect all: the tunnel does not carry TLS, so Box cannot check it for secrets"
	case !rawOK:
		nonTLS = msgNotTLS
	}
	hello, isTLS, ok := p.checkTunnel(s, t, br, tlsPeekTimeout, nonTLS)
	if !ok {
		return
	}
	if !isTLS {
		in, out := s.splice(br, s.client, up, up)
		p.emit(Event{Kind: EventClosed, Host: t.host, Port: t.port, BytesIn: in, BytesOut: out, Reason: s.endReason("")})
		return
	}
	// Box terminates this TLS itself: a HelloRetryRequest is its own, and crypto/tls refuses a second ClientHello
	// that names another server.
	br0 := io.MultiReader(&byteReader{b: hello}, br)

	upTLS := tls.Client(up, &tls.Config{
		ServerName: t.host,
		RootCAs:    p.cfg.UpstreamRoots,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	s.track(upTLS)
	hctx, cancel := context.WithTimeout(p.ctx, p.cfg.DialTimeout)
	upErr := upTLS.HandshakeContext(hctx)
	cancel()
	if upErr == nil {
		if np := upTLS.ConnectionState().NegotiatedProtocol; np != "" && np != "http/1.1" {
			upErr = fmt.Errorf("the host chose protocol %q", np)
		}
	}

	var sniErr error
	cli := tls.Server(&bufConn{Conn: s.client, r: br0}, p.serverTLS(t, &sniErr))
	s.track(cli)
	hctx, cancel = context.WithTimeout(p.ctx, p.cfg.DialTimeout)
	err := cli.HandshakeContext(hctx)
	cancel()
	if err == nil {
		// Belt and braces: the SNI the session actually negotiated.
		if e := p.checkSNI(t, cli.ConnectionState().ServerName); e != nil {
			sniErr, err = e, e
		}
	}
	if err != nil {
		var se *sniError
		switch {
		case errors.As(sniErr, &se) && se.leak != nil:
			p.emit(Event{Kind: EventSecretLeak, Host: t.host, Port: t.port, Secret: se.leak.secret.Name, Reason: se.leak.reason})
		case errors.As(sniErr, &se):
			p.emit(Event{Kind: EventDenied, Host: t.host, Port: t.port, Reason: se.msg})
		default:
			p.emit(Event{Kind: EventClosed, Host: t.host, Port: t.port,
				Reason: s.endReason("TLS handshake with the client failed: " + printable(err.Error(), 200))})
		}
		return
	}

	cliOut := &countWriter{w: cli}
	hl := &headLimiter{r: cli}
	cr := bufio.NewReaderSize(hl, 4096)
	if upErr != nil {
		// Answer inside the tunnel, where the guest's client shows the body (it rarely shows a CONNECT error's).
		hl.limit(p.cfg.MaxHeaderBytes)
		http.ReadRequest(cr)
		p.failed(s, cliOut, t, refusal{status: 502, reason: "TLS to the host failed: " + printable(upErr.Error(), 300),
			todo: "Box verifies the host's certificate against the host's system roots; check the host name."})
		return
	}
	upOut := &countWriter{w: upTLS}
	uhl := &headLimiter{r: upTLS, norec: true}
	ur := bufio.NewReaderSize(uhl, 32<<10)
	x := &exchange{p: p, s: s, t: t, cliOut: cliOut, upOut: upOut, cr: cr, ur: ur, uhl: uhl, upRaw: up, cli: cli, up: upTLS}
	for {
		hl.limit(p.cfg.MaxHeaderBytes)
		req, err := http.ReadRequest(cr)
		if err != nil {
			p.badHead(s, cli, hl, err, t)
			break
		}
		hl.unlimit()
		if !x.forward(req, true) {
			break
		}
	}
	p.emit(Event{Kind: EventClosed, Host: t.host, Port: t.port,
		BytesIn: cliOut.n.Load() + x.spliceIn, BytesOut: upOut.n.Load() + x.spliceOut, Reason: s.endReason(x.endReason)})
}

// exchange forwards requests from the guest to one upstream connection.
type exchange struct {
	p      *Proxy
	s      *session
	t      target
	cliOut *countWriter // guest-bound bytes
	upOut  *countWriter // upstream-bound bytes
	cr     *bufio.Reader
	ur     *bufio.Reader
	uhl    *headLimiter
	upRaw  net.Conn // closed to cut a request off mid-body
	cli    net.Conn // for an upgrade splice (nil for plain HTTP)
	up     net.Conn

	spliceIn, spliceOut int64
	endReason           string
	status              int // of the last final response
}

// forward sends one request and its response. tls is false for plain HTTP, where secrets are never swapped and
// the connection always closes afterwards. It returns whether the connection may carry another request.
func (x *exchange) forward(req *http.Request, overTLS bool) bool {
	p, t := x.p, x.t
	path := req.URL.Path
	method := req.Method

	// Placeholders: never in the method, the URL or the Host; in headers only where bound (never over plain HTTP).
	if f := p.find(method, true); f != nil {
		return x.leak(method, path, &leakError{secret: f[0], reason: fmt.Sprintf("a placeholder for secret %s is in the request method", f[0].Name),
			todo: "Use a normal HTTP method."})
	}
	if f := p.findTarget(req.RequestURI); f != nil {
		return x.leak(method, path, &leakError{secret: f[0], reason: fmt.Sprintf("a placeholder for secret %s is in the URL; Box swaps secrets only into request headers", f[0].Name),
			todo: "Send the secret in its bound header instead of the URL."})
	}
	if f := p.find(req.Host, true); f != nil {
		return x.leak(method, path, &leakError{secret: f[0], reason: fmt.Sprintf("a placeholder for secret %s is in the Host header", f[0].Name),
			todo: "Never put a secret in a host name."})
	}
	// Real values: never in the method, the URL or the Host either.
	if f := p.findValues(method); f != nil {
		return x.leak(method, path, valueLeak(f[0], "the request method", ""))
	}
	if f := p.findValueTarget(req.RequestURI); f != nil {
		return x.leak(method, path, valueLeak(f[0], "the URL", ""))
	}
	if f := p.findValueTarget(req.Host); f != nil {
		return x.leak(method, path, valueLeak(f[0], "the Host header", ""))
	}
	// Where the request goes must be the tunnel's host.
	if overTLS {
		if r := x.checkInner(req); r != nil {
			p.deny(x.s, x.cliOut, t, method, path, *r)
			x.endReason = r.reason
			return false
		}
	}
	upType := ""
	if overTLS {
		upType = upgradeType(req.Header)
		// The Upgrade header is the one hop-by-hop header Box sends on, so the header checks below never see it.
		if f := p.find(upType, true); f != nil {
			return x.leak(method, path, &leakError{secret: f[0], reason: fmt.Sprintf("a placeholder for secret %s is in the Upgrade header", f[0].Name),
				todo: "Send the secret in its bound header."})
		}
		if f := p.findValues(upType); f != nil {
			return x.leak(method, path, valueLeak(f[0], "the Upgrade header", ""))
		}
	}
	teTrailers := headerHasToken(req.Header, "Te", "trailers")
	stripHopByHop(req.Header)
	// Before the swap puts values in: a value the guest sent itself may only go where Box would have put it.
	if l := p.checkValues(req.Header, t.host, overTLS); l != nil {
		return x.leak(method, path, l)
	}
	var used []*secretRule
	bound := overTLS && p.boundSecrets(t.host, t.addr)
	if overTLS {
		var l *leakError
		if used, l = p.swapHeaders(req.Header, t.host, true); l != nil {
			return x.leak(method, path, l)
		}
	}
	if bound && upType != "" {
		// After a switch the host's bytes are a protocol Box does not read (WebSocket frames, h2c), where an
		// echoed value would reach the guest unredacted; so the value is not sent into one at all.
		r := refusal{status: http.StatusForbidden,
			reason: "Box does not relay protocol upgrades (such as WebSocket) to a host with a bound secret: it could not keep the secret's value out of the upgraded stream",
			todo:   "Use the host's plain HTTPS API, or send this host's credential without a Box secret binding."}
		p.deny(x.s, x.cliOut, t, method, path, r)
		x.endReason = r.reason
		return false
	}
	if bound {
		// A host that may echo a value must answer in plain bytes, where Box can redact it, and whole: a range
		// could hand back an echoed value in pieces too short to recognise.
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Del("Range")
		req.Header.Del("If-Range")
		req.Header.Del("Request-Range") // the legacy alias some servers (Apache httpd) still honour
	}
	if upType != "" {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", upType)
	}
	if teTrailers {
		req.Header.Set("Te", "trailers")
	}
	if !overTLS {
		req.Header.Set("Connection", "close")
	}

	// The body streams through a scanner that holds back enough to stop a placeholder or a value before it leaves.
	var bodyLeak atomic.Pointer[pattern]
	var body io.Reader
	if req.Body != nil && req.Body != http.NoBody {
		body = req.Body
		if !p.reqMatch.empty() {
			body = p.newScanReader(req.Body, func(m *pattern) {
				bodyLeak.Store(m)
				x.upRaw.Close()
			})
		}
	}
	target := req.RequestURI
	if req.URL.Scheme != "" || req.URL.Host != "" {
		target = req.URL.RequestURI()
	}
	hostHdr := t.host
	if t.addr.IsValid() && t.addr.Is6() {
		hostHdr = "[" + t.host + "]"
	}
	if (overTLS && t.port != 443) || (!overTLS && t.port != 80) {
		hostHdr = hostPort(t.host, t.port)
	}
	out := outRequest{method: method, target: target, host: hostHdr, header: req.Header, body: body, contentLength: req.ContentLength}
	if body == nil {
		out.contentLength = 0
	}
	for _, r := range used {
		p.emit(Event{Kind: EventSecretUse, Host: t.host, Port: t.port, Method: method, Path: path, Secret: r.Name})
	}

	in0, out0 := x.cliOut.n.Load(), x.upOut.n.Load()
	wdone := make(chan error, 1)
	go func() { wdone <- out.write(x.upOut) }()
	// cutOff ends the exchange early: stop the upstream, answer the guest if nothing was sent yet, and only then
	// wait for the writer (which may be blocked reading the guest's body).
	cutOff := func(answer func()) bool {
		x.upRaw.Close()
		if answer != nil {
			answer()
		}
		x.s.closeAll()
		<-wdone
		if body != nil {
			req.Body.Close()
		}
		return false
	}

	var resp *http.Response
	var err error
	for i := 0; ; i++ {
		x.uhl.limit(maxResponseHeadBytes)
		resp, err = http.ReadResponse(x.ur, &http.Request{Method: method})
		tooBig := x.uhl.remain == 0
		x.uhl.unlimit()
		if err != nil {
			// Never quote the parser's error: it can carry upstream bytes, and an upstream may echo a value.
			switch {
			case tooBig:
				err = fmt.Errorf("its response head is larger than %d bytes", maxResponseHeadBytes)
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
				err = errors.New("it closed the connection")
			case isTimeout(err), errors.Is(err, net.ErrClosed):
				err = errors.New("the connection was closed")
			default:
				err = errors.New("its response is not valid HTTP/1.1")
			}
			break
		}
		if overTLS {
			p.redactValues(resp.Header)
			p.redactValues(resp.Trailer) // the names announced in Trailer, which go to the guest in its Trailer header
		}
		if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
			if i >= maxInterim {
				err = fmt.Errorf("more than %d interim responses", maxInterim)
				break
			}
			if overTLS || req.ProtoAtLeast(1, 1) {
				if _, werr := writeResponse(x.cliOut, resp, method, true, false, "", nil); werr != nil {
					return cutOff(nil)
				}
			}
			continue
		}
		break
	}
	if err != nil {
		if m := bodyLeak.Load(); m != nil {
			return cutOff(func() { x.leak(method, path, bodyLeakError(m, overTLS)) })
		}
		x.endReason = "the host sent no valid response: " + err.Error()
		return cutOff(func() {
			p.writeRefusal(x.cliOut, http.StatusBadGateway, t, x.endReason, "The host closed the connection or answered with something that is not HTTP/1.1.")
		})
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		if upType == "" || !strings.EqualFold(upgradeType(resp.Header), upType) {
			x.endReason = "the host switched protocols without being asked"
			return cutOff(func() {
				p.writeRefusal(x.cliOut, http.StatusBadGateway, t, x.endReason, "Ask for the upgrade with Connection: Upgrade.")
			})
		}
		if _, err := writeResponse(x.cliOut, resp, method, true, false, upType, nil); err != nil {
			return cutOff(nil)
		}
		if err := <-wdone; err != nil {
			x.s.closeAll()
			return false
		}
		// After the switch Box reads neither direction: it swaps nothing into the guest's bytes, and a host's
		// bytes are not redacted. Only a host with no bound secret gets here (forward refuses upgrades to bound
		// hosts): no value was sent to it, so its upgraded stream passes as its encoded bodies do.
		x.spliceIn, x.spliceOut = x.s.splice(x.cr, x.cli, x.ur, x.up)
		return false
	}

	if overTLS {
		if r := p.guardBody(resp, method, bound); r != nil {
			x.endReason = r.reason
			return cutOff(func() { p.writeRefusal(x.cliOut, r.status, t, r.reason, r.todo) })
		}
	}
	closeAfter := !overTLS || req.Close || resp.Close
	_, werr := writeResponse(x.cliOut, resp, method, req.ProtoAtLeast(1, 1), closeAfter, "", p.redactValues)
	if werr != nil {
		return cutOff(nil)
	}
	rerr := <-wdone
	if m := bodyLeak.Load(); m != nil {
		// The host answered before the guest finished the body; the rest never left.
		l := bodyLeakError(m, overTLS)
		p.emit(Event{Kind: EventSecretLeak, Host: t.host, Port: t.port, Method: method, Path: path, Secret: m.rule.Name, Reason: l.reason})
		x.endReason = l.reason
		x.s.closeAll()
		return false
	}
	x.status = resp.StatusCode
	bytesIn, bytesOut := x.cliOut.n.Load()-in0, x.upOut.n.Load()-out0
	if p.models.matchHost(t.host, t.addr) {
		p.emit(Event{Kind: EventModelCall, Host: t.host, Port: t.port, Method: method, Path: path, Status: resp.StatusCode,
			BytesIn: bytesIn, BytesOut: bytesOut})
	}
	return rerr == nil && !closeAfter
}

// guardBody makes sure no secret value in a response body on an inspected connection reaches the guest: a plain body
// streams through the redactor; a bound host's encoded body (which it sent although Box asked for identity) is
// decoded first when it is gzip or deflate, and refused otherwise.
func (p *Proxy) guardBody(resp *http.Response, method string, bound bool) *refusal {
	code := resp.StatusCode
	if bound && code == http.StatusPartialContent {
		// Box sent no Range: a piece of a body can hold a piece of a value, too short to recognise.
		return &refusal{status: 502, reason: "the host answered with a partial response (206), which Box can't check whole for secret values",
			todo: "Box removes Range from requests to hosts with a bound secret so it sees whole responses; this host sent a range anyway."}
	}
	if p.valMatch.empty() || method == http.MethodHead || code == http.StatusNoContent || code == http.StatusNotModified || code < 200 {
		return nil
	}
	codings := contentCodings(resp.Header)
	if len(codings) == 0 {
		resp.Body = io.NopCloser(newRedactReader(p.valMatch, resp.Body))
		return nil
	}
	if !bound {
		return nil // no value is ever sent to this host; its encoded bodies pass as they are
	}
	const todo = "Box asks hosts with a bound secret for unencoded responses (Accept-Encoding: identity) so it can keep secret values out of them; this host ignored that."
	dec, err := decodeBody(resp.Body, codings)
	if err != nil {
		return &refusal{status: 502, reason: "the host answered with " + err.Error() + ", which Box can't check for secret values", todo: todo}
	}
	resp.Body = io.NopCloser(newRedactReader(p.valMatch, dec))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	return nil
}

func bodyLeakError(m *pattern, overTLS bool) *leakError {
	r := m.rule
	if m.kind == patValue {
		if !overTLS {
			return valueLeak(r, "a plain-HTTP request body", "Box never sends secrets over plain HTTP, and never in bodies.")
		}
		return valueLeak(r, "the request body", "Box sends secrets only in their header; send the placeholder there instead.")
	}
	if !overTLS {
		return &leakError{secret: r, reason: fmt.Sprintf("a placeholder for secret %s is in a plain-HTTP request body", r.Name),
			todo: "Box never sends secrets over plain HTTP; use https://."}
	}
	return &leakError{secret: r, reason: fmt.Sprintf("a placeholder for secret %s is in the request body; Box swaps secrets only into request headers", r.Name),
		todo: "Send the secret in its bound header."}
}

func (x *exchange) leak(method, path string, l *leakError) bool {
	x.p.leak(x.s, x.cliOut, x.t, method, path, l)
	x.endReason = l.reason
	return false
}

// checkInner validates a request inside a tunnel: origin form (or absolute form naming the tunnel's host) and a Host
// header that names the CONNECT host.
func (x *exchange) checkInner(req *http.Request) *refusal {
	t := x.t
	if req.Method == http.MethodConnect {
		return &refusal{status: 400, reason: "CONNECT inside a tunnel", todo: "Open a new connection to the proxy for each CONNECT."}
	}
	if req.URL.Scheme != "" && req.URL.Scheme != "https" {
		return &refusal{status: 400, reason: "an absolute URL with scheme " + req.URL.Scheme + " inside a TLS tunnel", todo: "Send origin-form requests."}
	}
	if req.URL.Opaque != "" {
		// "https:http://evil.example/x" has no URL host to check, and would go upstream as "http://evil.example/x".
		return &refusal{status: 400, reason: "an opaque request target inside a TLS tunnel", todo: "Send origin-form requests."}
	}
	if req.Host == "" {
		return &refusal{status: 400, reason: "the request has no Host header", todo: "Send Host: " + t.host + "."}
	}
	h, _, port, err := parseAuthority(req.Host, t.port)
	if err != nil || h != t.host || port != t.port {
		return &refusal{status: 403, reason: fmt.Sprintf("the Host header %q does not match the tunnel's host %s", printable(req.Host, 260), t.who()),
			todo: "Open a separate CONNECT for each host."}
	}
	if req.URL.Host != "" && req.URL.Host != req.Host {
		h, _, port, err := parseAuthority(req.URL.Host, t.port)
		if err != nil || h != t.host || port != t.port {
			return &refusal{status: 403, reason: "the request URL names another host than the tunnel", todo: "Open a separate CONNECT for each host."}
		}
	}
	return nil
}

// servePlain handles one absolute-form http:// request; the connection closes after it.
func (p *Proxy) servePlain(s *session, req *http.Request, br *bufio.Reader) {
	u := req.URL
	path := u.Path
	defer s.linger(br)
	// Leaks first, wherever the request was going: nothing in plain HTTP may carry a placeholder.
	t0 := target{scheme: "http", host: printable(u.Host, maxHostLen)}
	defPort := 80
	if u.Scheme == "https" {
		defPort = 443
	}
	if h, lit, port, err := parseAuthority(u.Host, defPort); err == nil {
		t0.host, t0.addr, t0.port = h, lit, port
	}
	if f := p.find(req.Method, true); f != nil {
		p.leak(s, s.client, t0, "", path, &leakError{secret: f[0], reason: fmt.Sprintf("a placeholder for secret %s is in the request method", f[0].Name), todo: "Use a normal HTTP method."})
		return
	}
	if f := p.findTarget(req.RequestURI); f != nil {
		p.leak(s, s.client, t0, req.Method, path, &leakError{secret: f[0],
			reason: fmt.Sprintf("a placeholder for secret %s is in a plain-HTTP URL", f[0].Name),
			todo:   "Box never sends secrets over plain HTTP; use https:// and the secret's bound header."})
		return
	}
	if _, l := p.swapHeaders(req.Header, t0.host, false); l != nil {
		p.leak(s, s.client, t0, req.Method, path, l)
		return
	}
	// Nor a real value (before the Decider sees the host).
	if f := p.findValues(req.Method); f != nil {
		p.leak(s, s.client, t0, "", path, valueLeak(f[0], "the request method", ""))
		return
	}
	if f := p.findValueTarget(req.RequestURI); f != nil {
		p.leak(s, s.client, t0, req.Method, path, valueLeak(f[0], "a plain-HTTP URL", "Box never sends secrets over plain HTTP, and never in URLs."))
		return
	}
	if l := p.checkValues(req.Header, t0.host, false); l != nil {
		p.leak(s, s.client, t0, req.Method, path, l)
		return
	}
	switch {
	case u.Scheme == "https":
		p.deny(s, s.client, t0, req.Method, path, refusal{status: 400, reason: "an https:// URL sent as a plain proxy request",
			todo: "Send HTTPS through CONNECT: set HTTPS_PROXY to the proxy."})
		return
	case u.Scheme != "http":
		p.deny(s, s.client, t0, req.Method, path, refusal{status: 400, reason: fmt.Sprintf("scheme %q is not supported", printable(u.Scheme, 20)),
			todo: "Use http:// (or https:// through CONNECT)."})
		return
	case u.User != nil:
		p.deny(s, s.client, t0, req.Method, path, refusal{status: 400, reason: "credentials in the URL",
			todo: "Send credentials in a header over HTTPS."})
		return
	}
	host, lit, port, err := parseAuthority(u.Host, 80)
	if err != nil {
		p.deny(s, s.client, target{host: printable(u.Host, maxHostLen)}, req.Method, path, refusal{status: 400,
			reason: "invalid host: " + err.Error(), todo: "Use an ASCII host name (IDNs as punycode)."})
		return
	}
	t := target{scheme: "http", host: host, addr: lit, port: port}
	if r := p.offAllowlistInspectAll(t, false); r != nil {
		p.deny(s, s.client, t, req.Method, path, *r)
		return
	}
	addrs, ok := p.admit(s, s.client, br, t, req.Method, path)
	if !ok {
		return
	}
	up, err := p.dial(p.ctx, addrs, port)
	if err != nil {
		p.failed(s, s.client, t, refusal{status: 502, reason: "could not connect: " + err.Error(),
			todo: "The host did not accept the connection; try again later."})
		return
	}
	s.track(up)
	upm := &meteredConn{Conn: up, w: s.watch}
	uhl := &headLimiter{r: upm, norec: true}
	x := &exchange{p: p, s: s, t: t, cliOut: &countWriter{w: s.client}, upOut: &countWriter{w: upm},
		cr: br, ur: bufio.NewReaderSize(uhl, 32<<10), uhl: uhl, upRaw: up, up: upm}
	x.forward(req, false)
	p.emit(Event{Kind: EventClosed, Host: t.host, Port: t.port, Method: req.Method, Path: path, Status: x.status,
		BytesIn: x.cliOut.n.Load(), BytesOut: x.upOut.n.Load(), Reason: s.endReason(x.endReason)})
}

// outRequest is a request as Box sends it upstream.
type outRequest struct {
	method, target, host string
	header               http.Header
	body                 io.Reader // nil: none
	contentLength        int64     // -1: unknown, sent chunked
}

// write sends the head at once and the body as it arrives (flushing every read, so streamed uploads stream).
// Trailers are dropped.
func (o outRequest) write(w io.Writer) error {
	bw := bufio.NewWriterSize(w, 16<<10)
	h := o.header
	h.Del("Content-Length")
	h.Del("Transfer-Encoding")
	h.Del("Host")
	chunked := false
	switch {
	case o.body == nil:
		if o.method == http.MethodPost || o.method == http.MethodPut || o.method == http.MethodPatch {
			h.Set("Content-Length", "0")
		}
	case o.contentLength >= 0:
		h.Set("Content-Length", strconv.FormatInt(o.contentLength, 10))
	default:
		h.Set("Transfer-Encoding", "chunked")
		chunked = true
	}
	fmt.Fprintf(bw, "%s %s HTTP/1.1\r\nHost: %s\r\n", o.method, o.target, o.host)
	if err := writeHeader(bw, h); err != nil {
		return err
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if o.body == nil {
		return nil
	}
	n, err := copyBody(bw, o.body, chunked, nil)
	if err != nil {
		return err
	}
	if !chunked && n != o.contentLength {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// writeResponse writes resp to the guest with fresh framing and flushes every body read, so streamed (SSE) model
// responses arrive as they are produced. chunkOK is false for HTTP/1.0 clients.
func writeResponse(w io.Writer, resp *http.Response, method string, chunkOK, closeConn bool, upType string, fixTrailer func(http.Header)) (int64, error) {
	bw := bufio.NewWriterSize(w, 16<<10)
	code := resp.StatusCode
	// The canonical reason phrase, never the host's: a host that echoes a value could put it there.
	text := http.StatusText(code)
	if text == "" {
		text = "Status"
	}
	h := resp.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	origCL := h.Get("Content-Length")
	var trailerKeys []string
	for k := range resp.Trailer {
		if !isHopByHop(textproto.CanonicalMIMEHeaderKey(k)) {
			trailerKeys = append(trailerKeys, k)
		}
	}
	sort.Strings(trailerKeys)
	stripHopByHop(h)
	h.Del("Content-Length")
	interim := code >= 100 && code < 200
	bodyless := interim || method == http.MethodHead || code == http.StatusNoContent || code == http.StatusNotModified
	chunked := false
	switch {
	case code == http.StatusSwitchingProtocols:
		h.Set("Connection", "Upgrade")
		h.Set("Upgrade", upType)
	case interim:
	case bodyless:
		if origCL != "" && code != http.StatusNoContent {
			h.Set("Content-Length", origCL)
		}
	case resp.ContentLength >= 0:
		h.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	case chunkOK:
		h.Set("Transfer-Encoding", "chunked")
		if len(trailerKeys) > 0 {
			h.Set("Trailer", strings.Join(trailerKeys, ", "))
		}
		chunked = true
	default:
		closeConn = true // an HTTP/1.0 client reads to EOF
	}
	if closeConn && !interim {
		h.Set("Connection", "close")
	}
	fmt.Fprintf(bw, "HTTP/1.1 %03d %s\r\n", code, text)
	if err := writeHeader(bw, h); err != nil {
		return 0, err
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return 0, err
	}
	if err := bw.Flush(); err != nil {
		return 0, err
	}
	if bodyless {
		return 0, nil
	}
	return copyBody(bw, resp.Body, chunked, func() http.Header {
		tr := resp.Trailer.Clone()
		if fixTrailer != nil {
			fixTrailer(tr)
		}
		return tr
	})
}

// copyBody copies r to bw, flushing after every read; chunked frames it and ends with trailers.
func copyBody(bw *bufio.Writer, r io.Reader, chunked bool, trailer func() http.Header) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if chunked {
				fmt.Fprintf(bw, "%x\r\n", n)
			}
			bw.Write(buf[:n])
			if chunked {
				bw.WriteString("\r\n")
			}
			if ferr := bw.Flush(); ferr != nil {
				return total, ferr
			}
			total += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return total, err
		}
	}
	if chunked {
		bw.WriteString("0\r\n")
		if trailer != nil {
			if tr := trailer(); len(tr) > 0 {
				tr = tr.Clone()
				stripHopByHop(tr)
				if err := writeHeader(bw, tr); err != nil {
					return total, err
				}
			}
		}
		bw.WriteString("\r\n")
		return total, bw.Flush()
	}
	return total, bw.Flush()
}

// writeHeader writes header lines in sorted order; net/http drops invalid names and turns newlines into spaces.
func writeHeader(w io.Writer, h http.Header) error { return h.Write(w) }

// stripHopByHop removes hop-by-hop headers, including any the Connection header names.
func stripHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if f = textproto.TrimString(f); f != "" {
				h.Del(f)
			}
		}
	}
	for _, k := range hopByHop {
		h.Del(k)
	}
}

// upgradeType returns the protocol a request or response asks to switch to, or "".
func upgradeType(h http.Header) string {
	if !headerHasToken(h, "Connection", "upgrade") {
		return ""
	}
	return printable(textproto.TrimString(h.Get("Upgrade")), 100)
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(textproto.TrimString(f), token) {
				return true
			}
		}
	}
	return false
}
