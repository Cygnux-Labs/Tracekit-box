package egress

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"time"
)

// What a tunnel may carry. The allowlist checks the CONNECT name, but bytes inside a tunnel pick the virtual host
// themselves (the TLS server name, or the Host header of plain HTTP), so Box reads the first flight before anything
// reaches the host: a ClientHello whose server name is the CONNECT host, without ECH, which would hide the real
// one. Only an allow entry that names the port lets other protocols through.

const extensionECH = 0xfe0d // encrypted_client_hello

// TLS alert descriptions Box answers a refused ClientHello with.
const (
	alertAccessDenied     = 49
	alertDecodeError      = 50
	alertUnrecognizedName = 112
)

const msgNotTLS = "the tunnel does not carry TLS: only an allow entry that names the port (host:port) lets other protocols through"

// helloInfo is what a ClientHello says.
type helloInfo struct {
	seen bool
	sni  string
	ech  bool
}

var (
	errHelloSeen   = errors.New("ClientHello read")
	errHelloTooBig = errors.New("ClientHello too large")
)

// helloConn feeds crypto/tls the guest's bytes, records them for replay and swallows whatever tls writes back.
type helloConn struct {
	r   io.Reader
	rec []byte
}

func (c *helloConn) Read(b []byte) (int, error) {
	room := maxHelloBytes - len(c.rec)
	if room <= 0 {
		return 0, errHelloTooBig
	}
	if len(b) > room {
		b = b[:room]
	}
	n, err := c.r.Read(b)
	c.rec = append(c.rec, b[:n]...)
	return n, err
}

func (c *helloConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *helloConn) Close() error                     { return nil }
func (c *helloConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *helloConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *helloConn) SetDeadline(time.Time) error      { return nil }
func (c *helloConn) SetReadDeadline(time.Time) error  { return nil }
func (c *helloConn) SetWriteDeadline(time.Time) error { return nil }

// readClientHello reads one ClientHello from r with crypto/tls's own parser (records reassembled, extensions checked
// as strictly as a Go server does: one server name, no duplicates) and returns what it says and every byte read, to
// replay to the host unchanged.
func readClientHello(r io.Reader) (helloInfo, []byte, error) {
	var info helloInfo
	hc := &helloConn{r: r}
	note := func(chi *tls.ClientHelloInfo, ech bool) {
		info.seen, info.sni = true, chi.ServerName
		info.ech = ech || slices.Contains(chi.Extensions, extensionECH)
	}
	err := tls.Server(hc, &tls.Config{
		// Called first whenever the ClientHello has an ECH extension, before it is parsed.
		GetEncryptedClientHelloKeys: func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			note(chi, true)
			return nil, errHelloSeen
		},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			note(chi, false)
			return nil, errHelloSeen
		},
	}).Handshake()
	if info.seen {
		return info, hc.rec, nil
	}
	if err == nil {
		err = errors.New("no ClientHello")
	}
	return info, hc.rec, err
}

// checkTunnel reads what the guest opens a tunnel with and enforces what the tunnel may carry. waitFirst bounds the
// wait for the guest's first byte (0: only the idle timeout does); the rest of a ClientHello must arrive within
// tlsPeekTimeout. nonTLS is the refusal for a stream that does not start with TLS, "" to let it through. It returns a
// reader that replays every byte read and then the rest of the stream, and whether the stream is TLS. On refusal it
// records why, tells the guest as well as the protocol allows, and returns ok=false.
func (p *Proxy) checkTunnel(s *session, t target, br *bufio.Reader, waitFirst time.Duration, nonTLS string) (cr io.Reader, isTLS, ok bool) {
	if waitFirst > 0 {
		s.raw.SetReadDeadline(time.Now().Add(waitFirst))
	}
	b, err := br.Peek(1)
	s.raw.SetReadDeadline(time.Time{})
	if err != nil {
		if !isTimeout(err) || s.idle.Load() || p.ctx.Err() != nil {
			p.emit(Event{Kind: EventClosed, Host: t.host, Port: t.port, Reason: s.endReason("the client went away")})
			return nil, false, false
		}
		b = nil // nothing yet: a protocol whose server speaks first (SMTP), or a silent client
	}
	if len(b) == 0 || b[0] != 0x16 {
		if nonTLS != "" {
			if len(b) == 0 {
				nonTLS = "no TLS ClientHello within " + tlsPeekTimeout.String() + "; " + nonTLS
			}
			// Answer in HTTP: a guest that sent plain HTTP into the tunnel shows it.
			p.deny(s, s.client, t, "", "", refusal{status: 403, reason: nonTLS,
				todo: "Send HTTPS through the tunnel, plain HTTP through the proxy in absolute form (http_proxy), or ask the operator to allow host:port."})
			s.linger(br)
			return nil, false, false
		}
		return br, false, true
	}

	s.raw.SetReadDeadline(time.Now().Add(tlsPeekTimeout))
	hello, rec, err := readClientHello(br)
	s.raw.SetReadDeadline(time.Time{})
	cr = io.MultiReader(&byteReader{b: rec}, br)
	if err != nil {
		gone := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
		switch {
		case s.idle.Load() || p.ctx.Err() != nil || (gone && !isTimeout(err)):
			p.emit(Event{Kind: EventClosed, Host: t.host, Port: t.port, Reason: s.endReason("the client went away")})
		case isTimeout(err):
			p.denyHello(s, t, br, alertDecodeError, "the TLS ClientHello did not arrive whole within "+tlsPeekTimeout.String())
		default:
			p.denyHello(s, t, br, alertDecodeError, "the tunnel starts with a TLS record but not a ClientHello Box can read")
		}
		return nil, true, false
	}
	sniErr := p.checkSNI(t, hello.sni)
	var se *sniError
	switch {
	case errors.As(sniErr, &se) && se.leak != nil:
		p.emit(Event{Kind: EventSecretLeak, Host: t.host, Port: t.port, Secret: se.leak.secret.Name, Reason: se.leak.reason})
		tlsAlert(s.client, alertAccessDenied)
		s.linger(br)
		return nil, true, false
	case hello.ech:
		p.denyHello(s, t, br, alertAccessDenied,
			"encrypted ClientHello (ECH) can't be checked: Box must see the server name the host will serve; turn ECH off in the client")
		return nil, true, false
	case errors.As(sniErr, &se):
		p.denyHello(s, t, br, alertUnrecognizedName, se.msg)
		return nil, true, false
	}
	return cr, true, true
}

// denyHello records a refused ClientHello and answers it with a TLS alert, so the guest's TLS library names the
// refusal instead of seeing a reset.
func (p *Proxy) denyHello(s *session, t target, br *bufio.Reader, alert byte, reason string) {
	p.emit(Event{Kind: EventDenied, Host: t.host, Port: t.port, Reason: reason})
	tlsAlert(s.client, alert)
	s.linger(br)
}

// tlsAlert writes a fatal TLS alert record.
func tlsAlert(w io.Writer, desc byte) {
	w.Write([]byte{21, 3, 3, 0, 2, 2, desc})
}

// byteReader reads b once (bytes.Reader without its WriterTo, which io.Copy would otherwise prefer).
type byteReader struct{ b []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// serveTunnel relays a tunnel Box does not inspect, once its first bytes pass checkTunnel.
func (p *Proxy) serveTunnel(s *session, t target, br *bufio.Reader, up *meteredConn, rawOK bool) {
	var in <-chan int64
	wait, nonTLS := tlsPeekTimeout, msgNotTLS
	if rawOK {
		// The host may speak first (SSH and SMTP servers send banners): pass its bytes while Box waits for the
		// guest's first byte, which then has no deadline but the idle timeout. Nothing the guest sends leaves
		// before the check.
		in = s.pipe(s.client, up)
		wait, nonTLS = 0, ""
	}
	cr, _, ok := p.checkTunnel(s, t, br, wait, nonTLS)
	if !ok {
		s.closeAll()
		if in != nil {
			<-in
		}
		return
	}
	if in == nil {
		in = s.pipe(s.client, up)
	}
	out := <-s.pipe(up, cr)
	nIn := <-in
	s.closeAll()
	p.emit(Event{Kind: EventClosed, Host: t.host, Port: t.port, BytesIn: nIn, BytesOut: out, Reason: s.endReason("")})
}
