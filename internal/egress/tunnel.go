package egress

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"time"
)

// What a tunnel may carry. The allowlist checks the CONNECT name, but bytes inside a tunnel pick the virtual host
// themselves (the TLS server name, or the Host header of plain HTTP), so Box reads the first flight before anything
// reaches the host: a ClientHello whose server name is the CONNECT host, named once, without ECH, which would hide
// the real one. A TLS 1.3 HelloRetryRequest makes the guest send a second ClientHello, which passes the same checks.
// Only an allow entry that names the port lets other protocols through.

const extensionECH = 0xfe0d // encrypted_client_hello

// TLS alert descriptions Box answers a refused ClientHello with.
const (
	alertUnexpectedMessage = 10
	alertIllegalParameter  = 47
	alertAccessDenied      = 49
	alertDecodeError       = 50
	alertUnrecognizedName  = 112
)

// TLS record framing.
const (
	recordCCS       = 20
	recordAlert     = 21
	recordHandshake = 22
	recordData      = 23
	maxRecordLen    = 16384 + 2048 // the largest record payload crypto/tls accepts
)

const msgNotTLS = "the tunnel does not carry TLS: only an allow entry that names the port (host:port) lets other protocols through"

// helloInfo is what a ClientHello says.
type helloInfo struct {
	seen  bool
	sni   string
	ech   bool
	names []string // every entry of the server_name extension, as sent
	// nameList is why the server_name extension is refused, "" when it holds exactly one host_name entry (or none).
	nameList string
}

var (
	errHelloSeen   = errors.New("ClientHello read")
	errHelloTooBig = errors.New("ClientHello too large")
	errNotHello    = errors.New("not a ClientHello")
)

// helloConn feeds crypto/tls a ClientHello's records and swallows whatever tls writes back.
type helloConn struct{ r io.Reader }

func (c *helloConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c *helloConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *helloConn) Close() error                     { return nil }
func (c *helloConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *helloConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *helloConn) SetDeadline(time.Time) error      { return nil }
func (c *helloConn) SetReadDeadline(time.Time) error  { return nil }
func (c *helloConn) SetWriteDeadline(time.Time) error { return nil }

// readHelloRecords reads exactly the handshake records that carry one ClientHello and returns them as sent and the
// reassembled message. It never reads past the record that completes the message, so whatever the guest sent after
// it (a second ClientHello, early data) stays in br for the next check.
func readHelloRecords(br *bufio.Reader) (rec, msg []byte, err error) {
	need := -1
	for {
		hdr, err := br.Peek(5)
		if err != nil {
			if err == io.EOF && len(rec) > 0 {
				err = io.ErrUnexpectedEOF
			}
			return rec, nil, err
		}
		n := int(binary.BigEndian.Uint16(hdr[3:5]))
		if hdr[0] != recordHandshake || n == 0 || n > maxRecordLen {
			return rec, nil, errNotHello
		}
		if len(rec)+5+n > maxHelloBytes {
			return rec, nil, errHelloTooBig
		}
		r := make([]byte, 5+n)
		if _, err := io.ReadFull(br, r); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return rec, nil, err
		}
		rec, msg = append(rec, r...), append(msg, r[5:]...)
		if need < 0 && len(msg) >= 4 {
			if msg[0] != 1 { // client_hello
				return rec, nil, errNotHello
			}
			if need = 4 + (int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])); need > maxHelloBytes {
				return rec, nil, errHelloTooBig
			}
		}
		if need >= 0 && len(msg) >= need {
			if len(msg) > need {
				return rec, nil, errNotHello // something follows the ClientHello in its record
			}
			return rec, msg, nil
		}
	}
}

// readClientHello reads one ClientHello from br with crypto/tls's own parser (records reassembled, extensions checked
// as strictly as a Go server does: one host name, no duplicates) plus Box's own read of the server_name list, and
// returns what it says and its records, to replay to the host unchanged.
func readClientHello(br *bufio.Reader) (helloInfo, []byte, error) {
	var info helloInfo
	rec, msg, err := readHelloRecords(br)
	if err != nil {
		return info, rec, err
	}
	note := func(chi *tls.ClientHelloInfo, ech bool) {
		info.seen, info.sni = true, chi.ServerName
		info.ech = ech || slices.Contains(chi.Extensions, extensionECH)
	}
	err = tls.Server(&helloConn{r: &byteReader{b: rec}}, &tls.Config{
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
	if !info.seen {
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = errNotHello
		}
		return info, rec, err
	}
	var ok bool
	if info.names, info.nameList, ok = serverNames(msg); !ok {
		return info, rec, errNotHello
	}
	return info, rec, nil
}

// serverNames reads the server_name extension of a ClientHello message itself. crypto/tls skips entries whose type
// is not host_name and takes the host_name entry wherever it sits, while a router that reads the first entry would
// pick another name; so Box accepts only a list of exactly one host_name entry, and returns why it refuses any other.
// ok is false when the message does not parse.
func serverNames(msg []byte) (names []string, refuse string, ok bool) {
	r := &tlsReader{b: msg, ok: true}
	r.take(4)      // msg_type, length
	r.take(2 + 32) // legacy_version, random
	r.vec8()       // legacy_session_id
	r.vec16()      // cipher_suites
	r.vec8()       // legacy_compression_methods
	if !r.ok || len(r.b) == 0 {
		return nil, "", r.ok // no extensions
	}
	exts := &tlsReader{b: r.vec16()}
	exts.ok = r.ok && len(r.b) == 0
	for exts.ok && len(exts.b) > 0 {
		typ, data := exts.u16(), exts.vec16()
		if typ != 0 || !exts.ok { // server_name
			continue
		}
		d := &tlsReader{b: data, ok: true}
		list := &tlsReader{b: d.vec16()}
		list.ok = d.ok && len(d.b) == 0
		for list.ok && len(list.b) > 0 {
			nameType, name := list.u8(), list.vec16()
			if list.ok {
				names = append(names, string(name))
				if nameType != 0 && refuse == "" {
					refuse = fmt.Sprintf("the TLS server_name extension has an entry of type %d, not a host name; servers and routers read such lists differently", nameType)
				}
			}
		}
		if !list.ok {
			return nil, "", false
		}
	}
	if len(names) > 1 && refuse == "" {
		refuse = fmt.Sprintf("the TLS server_name extension lists %d names; servers and routers read such lists differently", len(names))
	}
	return names, refuse, exts.ok
}

// tlsReader reads TLS vectors; a short read clears ok, after which every read returns nothing.
type tlsReader struct {
	b  []byte
	ok bool
}

func (r *tlsReader) take(n int) []byte {
	if !r.ok || n > len(r.b) {
		r.ok = false
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *tlsReader) u8() int {
	if v := r.take(1); len(v) == 1 {
		return int(v[0])
	}
	return 0
}

func (r *tlsReader) u16() int {
	if v := r.take(2); len(v) == 2 {
		return int(v[0])<<8 | int(v[1])
	}
	return 0
}

func (r *tlsReader) vec8() []byte  { return r.take(r.u8()) }
func (r *tlsReader) vec16() []byte { return r.take(r.u16()) }

// checkTunnel reads what the guest opens a tunnel with and enforces what the tunnel may carry. waitFirst bounds the
// wait for the guest's first byte (0: only the idle timeout does); the rest of a ClientHello must arrive within
// tlsPeekTimeout. nonTLS is the refusal for a stream that does not start with TLS, "" to let it through. It returns
// the records of the ClientHello it checked (nil when the stream is not TLS), to send on unchanged before the rest
// of br, and whether the stream is TLS. On refusal it records why, tells the guest as well as the protocol allows,
// and returns ok=false.
func (p *Proxy) checkTunnel(s *session, t target, br *bufio.Reader, waitFirst time.Duration, nonTLS string) (hello []byte, isTLS, ok bool) {
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
	if len(b) == 0 || b[0] != recordHandshake {
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
		return nil, false, true
	}

	s.raw.SetReadDeadline(time.Now().Add(tlsPeekTimeout))
	info, rec, err := readClientHello(br)
	s.raw.SetReadDeadline(time.Time{})
	if err != nil {
		p.helloFailed(s, t, br, err, false)
		return nil, true, false
	}
	if !p.admitHello(s, t, br, info) {
		return nil, true, false
	}
	return rec, true, true
}

// helloFailed records a ClientHello Box could not read whole (retry: the one after a HelloRetryRequest).
func (p *Proxy) helloFailed(s *session, t target, br *bufio.Reader, err error, retry bool) {
	gone := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
	which, unreadable := "ClientHello", "the tunnel starts with a TLS record but not a ClientHello Box can read"
	if retry {
		which, unreadable = "ClientHello after the host's HelloRetryRequest", "after the host's HelloRetryRequest the guest sent no ClientHello Box can read"
	}
	switch {
	case s.idle.Load() || p.ctx.Err() != nil || (gone && !isTimeout(err)):
		p.emit(Event{Kind: EventClosed, Host: t.host, Port: t.port, Reason: s.endReason("the client went away")})
	case isTimeout(err):
		p.denyHello(s, t, br, alertDecodeError, "the TLS "+which+" did not arrive whole within "+tlsPeekTimeout.String())
	default:
		p.denyHello(s, t, br, alertDecodeError, unreadable)
	}
}

// admitHello enforces what a ClientHello may say: its server name is the CONNECT host (an IP-literal CONNECT may send
// none), as the only entry of its list, and it has no ECH. On refusal it records why and answers with a TLS alert.
func (p *Proxy) admitHello(s *session, t target, br *bufio.Reader, hello helloInfo) bool {
	sniErr := p.checkSNI(t, hello.sni)
	for _, n := range hello.names {
		if e, ok := p.checkSNI(t, n).(*sniError); ok && e.leak != nil {
			sniErr = e
		}
	}
	var se *sniError
	switch {
	case errors.As(sniErr, &se) && se.leak != nil:
		p.emit(Event{Kind: EventSecretLeak, Host: t.host, Port: t.port, Secret: se.leak.secret.Name, Reason: se.leak.reason})
		tlsAlert(s.client, alertAccessDenied)
		s.linger(br)
		return false
	case hello.ech:
		p.denyHello(s, t, br, alertAccessDenied,
			"encrypted ClientHello (ECH) can't be checked: Box must see the server name the host will serve; turn ECH off in the client")
		return false
	case hello.nameList != "":
		p.denyHello(s, t, br, alertIllegalParameter, hello.nameList)
		return false
	case errors.As(sniErr, &se):
		p.denyHello(s, t, br, alertUnrecognizedName, se.msg)
		return false
	}
	return true
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

// helloRetryRandom is the ServerHello random of a TLS 1.3 HelloRetryRequest (RFC 8446, section 4.1.3).
var helloRetryRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// What the host answered a ClientHello with.
const (
	answerHello   = iota // a ServerHello, an alert, or anything else after which no second ClientHello is taken
	answerRetry          // a HelloRetryRequest: the guest sends a second ClientHello
	answerUnknown        // more bytes than Box follows before the answer is known
)

const maxAnswerWatch = 256 << 10

// answerWatch passes the host's bytes to the guest unchanged and reports on dec what the host answered each
// ClientHello with, until it answers with anything but a HelloRetryRequest. dec is closed once the host's side of the
// tunnel has ended (closeDec, after the last Read).
type answerWatch struct {
	r       io.Reader
	dec     chan int
	done    bool
	seen    int    // bytes watched
	in      []byte // record bytes not parsed yet
	hs      []byte // handshake bytes not parsed yet
	told    bool   // the handshake message at the start of hs was reported
	retries int
}

func newAnswerWatch(r io.Reader) *answerWatch { return &answerWatch{r: r, dec: make(chan int, 4)} }

func (w *answerWatch) Read(b []byte) (int, error) {
	n, err := w.r.Read(b)
	if !w.done && n > 0 {
		w.feed(b[:n])
	}
	return n, err
}

func (w *answerWatch) closeDec() { close(w.dec) }

func (w *answerWatch) tell(d int) {
	w.dec <- d
	w.done, w.in, w.hs = true, nil, nil
}

func (w *answerWatch) feed(b []byte) {
	if w.seen += len(b); w.seen > maxAnswerWatch {
		w.tell(answerUnknown)
		return
	}
	w.in = append(w.in, b...)
	for !w.done && len(w.in) >= 5 {
		typ, n := w.in[0], int(binary.BigEndian.Uint16(w.in[3:5]))
		if typ != recordHandshake && typ != recordCCS {
			w.tell(answerHello) // an alert, application data, or not TLS at all
			return
		}
		if len(w.in) < 5+n {
			return
		}
		frag := w.in[5 : 5+n]
		w.in = w.in[5+n:]
		if typ == recordHandshake {
			w.hs = append(w.hs, frag...)
			w.messages()
		}
	}
}

// messages reports each handshake message in w.hs as soon as its random is in.
func (w *answerWatch) messages() {
	for !w.done && len(w.hs) >= 4 {
		if w.hs[0] != 2 { // server_hello
			w.tell(answerHello)
			return
		}
		if !w.told {
			if len(w.hs) < 4+2+32 {
				return
			}
			if !bytes.Equal(w.hs[6:38], helloRetryRandom) {
				w.tell(answerHello)
				return
			}
			w.told, w.retries = true, w.retries+1
			if w.retries > 1 {
				w.tell(answerRetry) // the guest side refuses a second one
				return
			}
			w.dec <- answerRetry
		}
		mlen := 4 + (int(w.hs[1])<<16 | int(w.hs[2])<<8 | int(w.hs[3]))
		if len(w.hs) < mlen {
			return
		}
		w.hs, w.told = w.hs[mlen:], false
	}
}

// relayError is a write to the host that failed.
type relayError struct{ error }

// followHello sends the guest's checked ClientHello and holds the rest of what the guest sends until the host has
// answered it. A TLS 1.3 HelloRetryRequest makes the guest send a second ClientHello, which is read and checked like
// the first before it leaves (records before it that are not handshake records, a change_cipher_spec or early data
// the host skips, pass as they are). RFC 8446 allows one HelloRetryRequest; a second ends the tunnel. It returns the
// bytes sent to the host; end, when set, is why the tunnel must close now (the relay then ends at once and records
// it); ok is false when it refused, already recorded.
func (p *Proxy) followHello(s *session, t target, br *bufio.Reader, up io.Writer, hello []byte, w *answerWatch) (sent int64, end string, ok bool) {
	for retry := false; ; retry = true {
		n, err := up.Write(hello)
		sent += int64(n)
		if err != nil {
			s.closeAll()
			return sent, "the host closed the connection", true
		}
		d, open := <-w.dec
		switch {
		case !open:
			s.closeAll()
			return sent, "the host closed the connection before it answered the TLS ClientHello", true
		case d == answerHello:
			return sent, "", true
		case d == answerUnknown:
			s.closeAll()
			return sent, "the host's answer to the TLS ClientHello is not one Box can follow", true
		case retry:
			p.denyHello(s, t, br, alertUnexpectedMessage, "the host sent a second TLS HelloRetryRequest, which TLS does not allow")
			return sent, "", false
		}
		s.raw.SetReadDeadline(time.Now().Add(tlsPeekTimeout))
		info, rec, err := nextHello(br, up, &sent)
		s.raw.SetReadDeadline(time.Time{})
		var re relayError
		switch {
		case errors.As(err, &re):
			s.closeAll()
			return sent, "the host closed the connection", true
		case err != nil:
			p.helloFailed(s, t, br, err, true)
			return sent, "", false
		case !p.admitHello(s, t, br, info):
			return sent, "", false
		}
		hello = rec
	}
}

// nextHello reads the guest's ClientHello after a HelloRetryRequest. Records before it that are not handshake records
// (change_cipher_spec, early data the host skips, an alert) go to the host as they are.
func nextHello(br *bufio.Reader, up io.Writer, sent *int64) (helloInfo, []byte, error) {
	for {
		hdr, err := br.Peek(5)
		if err != nil {
			return helloInfo{}, nil, err
		}
		typ, n := hdr[0], int(binary.BigEndian.Uint16(hdr[3:5]))
		if typ == recordHandshake {
			return readClientHello(br)
		}
		if typ != recordCCS && typ != recordAlert && typ != recordData || n > maxRecordLen {
			return helloInfo{}, nil, errNotHello
		}
		rec := make([]byte, 5+n)
		if _, err := io.ReadFull(br, rec); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return helloInfo{}, nil, err
		}
		m, err := up.Write(rec)
		*sent += int64(m)
		if err != nil {
			return helloInfo{}, nil, relayError{err}
		}
	}
}

// serveTunnel relays a tunnel Box does not inspect, once its first bytes pass checkTunnel.
func (p *Proxy) serveTunnel(s *session, t target, br *bufio.Reader, up *meteredConn, rawOK bool) {
	// The host's answer to each ClientHello is watched on its way to the guest (see followHello).
	w := newAnswerWatch(up)
	var in chan int64
	startIn := func() {
		in = make(chan int64, 1)
		piped := s.pipe(s.client, w)
		go func() {
			n := <-piped
			w.closeDec()
			in <- n
		}()
	}
	wait, nonTLS := tlsPeekTimeout, msgNotTLS
	if rawOK {
		// The host may speak first (SSH and SMTP servers send banners): pass its bytes while Box waits for the
		// guest's first byte, which then has no deadline but the idle timeout. Nothing the guest sends leaves
		// before the check.
		startIn()
		wait, nonTLS = 0, ""
	}
	hello, isTLS, ok := p.checkTunnel(s, t, br, wait, nonTLS)
	if !ok {
		s.closeAll()
		if in != nil {
			<-in
		}
		return
	}
	if in == nil {
		startIn()
	}
	var sent int64
	end := ""
	if isTLS {
		if sent, end, ok = p.followHello(s, t, br, up, hello, w); !ok {
			s.closeAll()
			<-in
			return
		}
	}
	out := <-s.pipe(up, br)
	nIn := <-in
	s.closeAll()
	p.emit(Event{Kind: EventClosed, Host: t.host, Port: t.port, BytesIn: nIn, BytesOut: sent + out, Reason: s.endReason(end)})
}
