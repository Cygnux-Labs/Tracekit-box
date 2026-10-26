package egress

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// captureConn records what a TLS client writes and fails its first read, so the handshake stops after the hello.
type captureConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *captureConn) Write(b []byte) (int, error)      { return c.buf.Write(b) }
func (c *captureConn) Read([]byte) (int, error)         { return 0, errors.New("done") }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }

func goHello(sni string, maxVer uint16) []byte {
	c := &captureConn{}
	tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MaxVersion: maxVer, NextProtos: []string{"h2", "http/1.1"}}).Handshake()
	return c.buf.Bytes()
}

// helloNames is an independent read of the records Box forwards: every entry of every server_name extension (any name
// type), whether an ECH extension is present, and whether the records hold exactly one ClientHello and nothing else.
func helloNames(rec []byte) (names []string, ech, ok bool) {
	var msg []byte
	for len(rec) > 0 {
		if len(rec) < 5 || rec[0] != 22 {
			return nil, false, false
		}
		n := int(binary.BigEndian.Uint16(rec[3:5]))
		if len(rec) < 5+n {
			return nil, false, false
		}
		msg = append(msg, rec[5:5+n]...)
		rec = rec[5+n:]
	}
	if len(msg) < 4 || msg[0] != 1 {
		return nil, false, false
	}
	l := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if len(msg) != 4+l {
		return nil, false, false
	}
	b := msg[4:]
	skip := func(n int) bool {
		if n > len(b) {
			return false
		}
		b = b[n:]
		return true
	}
	vec := func(lenBytes int) ([]byte, bool) {
		if len(b) < lenBytes {
			return nil, false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(b[i])
		}
		b = b[lenBytes:]
		if n > len(b) {
			return nil, false
		}
		v := b[:n]
		b = b[n:]
		return v, true
	}
	if !skip(2 + 32) {
		return nil, false, false
	}
	for _, lb := range []int{1, 2, 1} {
		if _, ok := vec(lb); !ok {
			return nil, false, false
		}
	}
	if len(b) == 0 {
		return nil, false, true
	}
	exts, ok := vec(2)
	if !ok || len(b) != 0 {
		return nil, false, false
	}
	for len(exts) >= 4 {
		typ := int(binary.BigEndian.Uint16(exts))
		n := int(binary.BigEndian.Uint16(exts[2:]))
		if 4+n > len(exts) {
			return nil, false, false
		}
		data := exts[4 : 4+n]
		exts = exts[4+n:]
		if typ == extensionECH {
			ech = true
		}
		if typ != 0 || len(data) < 2 {
			continue
		}
		list := data[2:]
		for len(list) >= 3 {
			nl := int(binary.BigEndian.Uint16(list[1:3]))
			if 3+nl > len(list) {
				break
			}
			names = append(names, string(list[3:3+nl]))
			list = list[3+nl:]
		}
	}
	return names, ech, true
}

// FuzzClientHello: a ClientHello Box admits for a CONNECT host names that host, and only it, in every reading of the
// bytes it forwards: crypto/tls's, Box's own, and one that takes every server_name entry of any type; the forwarded
// records hold exactly one ClientHello; nothing past it is consumed.
func FuzzClientHello(f *testing.F) {
	for _, sni := range []string{"api.github.com", "API.GitHub.com", "evil.example", "1.2.3.4", ""} {
		f.Add(goHello(sni, tls.VersionTLS13), []byte(nil), uint8(0))
		f.Add(goHello(sni, tls.VersionTLS12), []byte{7, 3, 200}, uint8(1))
	}
	targets := []target{
		{scheme: "https", host: "api.github.com", port: 443},
		{scheme: "https", host: "1.2.3.4", addr: netip.MustParseAddr("1.2.3.4"), port: 443},
		{scheme: "https", host: "evil.example", port: 8443},
	}
	p := &Proxy{}
	f.Fuzz(func(t *testing.T, data, tail []byte, sel uint8) {
		in := append(append([]byte(nil), data...), tail...)
		br := bufio.NewReader(&chunkReader{data: in, sizes: tail})
		info, rec, err := readClientHello(br)
		if err != nil {
			return
		}
		if !bytes.HasPrefix(in, rec) {
			t.Fatal("forwarded records are not the bytes read")
		}
		rest := make([]byte, len(in)-len(rec))
		n, _ := br.Read(rest)
		_ = n
		names, ech, ok := helloNames(rec)
		if !ok {
			t.Fatalf("Box accepted records that are not exactly one ClientHello: %x", rec)
		}
		tt := targets[int(sel)%len(targets)]
		admitted := p.checkSNI(tt, info.sni) == nil && info.nameList == "" && !info.ech
		for _, nm := range info.names {
			if e, isSNI := p.checkSNI(tt, nm).(*sniError); isSNI && e.leak != nil {
				admitted = false
			}
		}
		if !admitted {
			return
		}
		if ech {
			t.Fatalf("admitted a ClientHello with an ECH extension for %s", tt.host)
		}
		if len(names) > 1 {
			t.Fatalf("admitted a server_name list of %d entries %q for %s", len(names), names, tt.host)
		}
		for _, nm := range names {
			h, a, err := normalizeHost(nm)
			if err != nil || h != tt.host || a.IsValid() != tt.addr.IsValid() {
				t.Fatalf("admitted SNI %q for CONNECT host %s (Go reads %q)", nm, tt.host, info.sni)
			}
		}
		if len(names) == 0 && !tt.addr.IsValid() {
			t.Fatalf("admitted a ClientHello without SNI for name %s", tt.host)
		}
	})
}
