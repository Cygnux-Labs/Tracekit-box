package egress

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// The oracle: IANA's IPv4 and IPv6 special-purpose registries (entries that are not globally reachable), plus
// multicast, the deprecated site-local range and broadcast, written out independently of builtinBlocked.
var (
	oracleV4 = mustPrefixes("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")
	oracleV6 = mustPrefixes("::/128", "::1/128", "::/96", "::ffff:0:0:0/96", "64:ff9b:1::/48", "100::/64",
		"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8")
	oracleMeta = []netip.Addr{netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("fd00:ec2::254"),
		netip.MustParseAddr("169.254.170.2"), netip.MustParseAddr("169.254.170.23"), netip.MustParseAddr("fd00:ec2::23"),
		netip.MustParseAddr("100.100.100.200"), netip.MustParseAddr("168.63.129.16")}
	wellKnownNAT64 = netip.MustParsePrefix("64:ff9b::/96")
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// oracleViews: the address itself (no zone), and the IPv4 address it carries when it is IPv4-mapped or NAT64.
func oracleViews(a netip.Addr) []netip.Addr {
	a = a.WithZone("")
	out := []netip.Addr{a}
	b := a.As16()
	v4 := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	if a.Is4In6() || (a.Is6() && wellKnownNAT64.Contains(a)) {
		out = append(out, v4)
	}
	return out
}

func inAny(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// oracleBlocked reports whether the oracle refuses a.
func oracleBlocked(a netip.Addr) bool {
	for _, v := range oracleViews(a) {
		if v.Is4() && inAny(oracleV4, v) || v.Is6() && inAny(oracleV6, v) || v == netip.MustParseAddr("255.255.255.255") {
			return true
		}
	}
	return false
}

func oracleMetadata(a netip.Addr) bool {
	for _, v := range oracleViews(a) {
		for _, m := range oracleMeta {
			if v == m {
				return true
			}
		}
	}
	return false
}

// v4Forms writes IPv4 address x the ways resolvers, URL parsers and inet_aton accept.
func v4Forms(x uint32, sel uint8) []string {
	a, b, c, d := x>>24, x>>16&0xff, x>>8&0xff, x&0xff
	forms := []string{
		fmt.Sprintf("%d.%d.%d.%d", a, b, c, d),
		fmt.Sprintf("%d.%d.%d.%d.", a, b, c, d),
		fmt.Sprintf("%d", x),
		fmt.Sprintf("0x%x", x),
		fmt.Sprintf("0X%X", x),
		fmt.Sprintf("0%o", x),
		fmt.Sprintf("%d.%d", a, x&0xffffff),
		fmt.Sprintf("%d.%d.%d", a, b, x&0xffff),
		fmt.Sprintf("0%o.0%o.0%o.0%o", a, b, c, d),
		fmt.Sprintf("0x%x.0x%x.0x%x.0x%x", a, b, c, d),
		fmt.Sprintf("0x%02x.%d.0%o.%d", a, b, c, d),
		fmt.Sprintf("%03d.%03d.%03d.%03d", a, b, c, d),
		fmt.Sprintf("%d.%d.%d.%d..", a, b, c, d),
		fmt.Sprintf("::ffff:%d.%d.%d.%d", a, b, c, d),
		fmt.Sprintf("::FFFF:%x:%x", x>>16, x&0xffff),
		fmt.Sprintf("0:0:0:0:0:ffff:%d.%d.%d.%d", a, b, c, d),
		fmt.Sprintf("0000:0000:0000:0000:0000:ffff:%04x:%04x", x>>16, x&0xffff),
		fmt.Sprintf("::%d.%d.%d.%d", a, b, c, d),
		fmt.Sprintf("::%x:%x", x>>16, x&0xffff),
		fmt.Sprintf("64:ff9b::%d.%d.%d.%d", a, b, c, d),
		fmt.Sprintf("64:FF9B:0:0:0:0:%x:%x", x>>16, x&0xffff),
		fmt.Sprintf("::ffff:0:%d.%d.%d.%d", a, b, c, d),
		fmt.Sprintf("2002:%x:%x::1", x>>16, x&0xffff),
		fmt.Sprintf("64:ff9b:1::%d.%d.%d.%d", a, b, c, d),
		fmt.Sprintf("::ffff:%d.%d.%d.%d%%eth0", a, b, c, d),
		fmt.Sprintf("::ffff:%d.%d.%d.%d%%25eth0", a, b, c, d),
		fmt.Sprintf("::ffff:0%o.%d.%d.%d", a, b, c, d),
	}
	if sel&1 != 0 {
		forms = append(forms, fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)+strings.Repeat(".", int(sel>>5)))
	}
	return forms
}

// v6Forms writes IPv6 address a in canonical, expanded, upper-case, zoned and dotted-tail forms.
func v6Forms(a netip.Addr) []string {
	b := a.As16()
	var groups []string
	for i := 0; i < 16; i += 2 {
		groups = append(groups, fmt.Sprintf("%04x", binary.BigEndian.Uint16(b[i:])))
	}
	return []string{
		a.String(),
		strings.ToUpper(a.String()),
		strings.Join(groups, ":"),
		strings.Join(groups[:6], ":") + fmt.Sprintf(":%d.%d.%d.%d", b[12], b[13], b[14], b[15]),
		a.String() + "%eth0",
		a.String() + "%25lo",
		a.StringExpanded(),
	}
}

// wraps puts a host form where the proxy reads one: CONNECT targets and absolute-form URLs.
func wraps(h string) []string {
	return []string{h, h + ":443", h + ":80", "[" + h + "]", "[" + h + "]:443", "[" + h + "]:8443"}
}

// inetAton is glibc's inet_aton: 1 to 4 parts, each decimal, 0-octal or 0x-hex, the last filling the remaining bytes.
func inetAton(s string) (uint32, bool) {
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return 0, false
	}
	var vals []uint64
	for _, p := range parts {
		if p == "" {
			return 0, false
		}
		base := 10
		q := p
		switch {
		case strings.HasPrefix(q, "0x") || strings.HasPrefix(q, "0X"):
			base, q = 16, q[2:]
			if q == "" {
				q = "0"
			}
		case len(q) > 1 && q[0] == '0':
			base, q = 8, q[1:]
		}
		v, err := strconv.ParseUint(q, base, 64)
		if err != nil {
			return 0, false
		}
		vals = append(vals, v)
	}
	var x uint64
	for i, v := range vals[:len(vals)-1] {
		if v > 0xff {
			return 0, false
		}
		x |= v << (24 - 8*i)
	}
	last := vals[len(vals)-1]
	if max := uint64(1)<<(8*(5-len(vals))) - 1; last > max {
		return 0, false
	}
	return uint32(x | last), true
}

// checkForm runs one textual form through every place the proxy parses a guest's host and checks the result.
func checkForm(t *testing.T, p *Proxy, form string, intended netip.Addr) {
	t.Helper()
	blocked := oracleBlocked(intended)
	meta := oracleMetadata(intended)
	check := func(where, host string, lit netip.Addr) {
		t.Helper()
		if !lit.IsValid() {
			// A name: it is resolved, and every answer checked. But a name a libc resolver reads as IPv4 must not get
			// through as a name.
			n := strings.TrimSuffix(host, ".")
			if v, ok := inetAton(n); ok {
				t.Fatalf("%s: %q is accepted as the name %q, which inet_aton reads as %v", where, form, host, netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}))
			}
			return
		}
		bad, _ := p.refused(lit)
		if oracleBlocked(lit) && !bad && len(p.allowPrivate) == 0 {
			t.Fatalf("%s: %q parses to %v, which the oracle blocks, and refused() lets it through", where, form, lit)
		}
		if oracleMetadata(lit) && !bad {
			t.Fatalf("%s: %q parses to metadata address %v and is not refused (allowPrivate %v)", where, form, lit, p.allowPrivate)
		}
		// A block prefix holds for every view of the address, and an IPv6 one that spans the IPv4-mapped range
		// holds for the IPv4 addresses it covers there.
		views := oracleViews(lit)
		for _, v := range views {
			if v.Is4() {
				views = append(views, netip.AddrFrom16(v.As16()))
			}
		}
		for _, bp := range p.blockPrefixes {
			for _, v := range views {
				if bp.Contains(v) && !bad {
					t.Fatalf("%s: %q parses to %v inside BlockPrefixes %v and is not refused", where, form, lit, bp)
				}
			}
		}
		// The address dialed is the one checked, so the literal must not be a different address than the text
		// names when that one is blocked.
		if lit.Unmap().WithZone("") != intended.Unmap().WithZone("") && (blocked || meta) && !bad {
			if !oracleBlocked(lit) {
				t.Fatalf("%s: %q names blocked %v but parses to %v, which is not refused", where, form, intended, lit)
			}
		}
	}
	for _, w := range wraps(form) {
		// CONNECT
		if host, lit, _, err := parseAuthority(w, 0); err == nil {
			check("CONNECT "+w, host, lit)
		}
		// absolute form, as net/http hands u.Host to servePlain
		raw := "GET http://" + w + "/x HTTP/1.1\r\nHost: h\r\n\r\n"
		if req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw))); err == nil {
			if host, lit, _, err := parseAuthority(req.URL.Host, 80); err == nil {
				check("GET http://"+w, host, lit)
			}
		}
	}
	// SNI and a resolver answer
	if host, lit, err := normalizeHost(form); err == nil {
		check("SNI "+form, host, lit)
	}
}

// FuzzAddrForms: any textual form of an address in a blocked range is refused wherever the proxy parses a host, the
// metadata addresses are refused even when AllowPrivate covers them, and BlockPrefixes holds in every form.
func FuzzAddrForms(f *testing.F) {
	for _, s := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "0.0.0.0", "100.64.0.1", "192.0.0.8",
		"::1", "::ffff:127.0.0.1", "fe80::1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::1", "2001:0:4136:e378::1",
		"fd00:ec2::254", "168.63.129.16", "100.100.100.200", "8.8.8.8", "2606:4700::1111", "5f00::1"} {
		a := netip.MustParseAddr(s)
		b := a.As16()
		f.Add(b[:], a.Is4(), uint8(0), uint8(0))
	}
	// I1: BlockPrefixes ::/23 (pol 2, 23 bits) spans the IPv4-mapped range, so it blocks ::ffff:8.8.8.8 and 8.8.8.8
	mapped := netip.MustParseAddr("::ffff:8.8.8.8").As16()
	f.Add(mapped[:], false, uint8(23), uint8(2))
	f.Fuzz(func(t *testing.T, raw []byte, v4 bool, sel, pol uint8) {
		var b16 [16]byte
		copy(b16[:], raw)
		var a netip.Addr
		if v4 {
			a = netip.AddrFrom4([4]byte{b16[12], b16[13], b16[14], b16[15]})
			if len(raw) == 4 {
				a = netip.AddrFrom4([4]byte(raw))
			}
		} else {
			a = netip.AddrFrom16(b16)
		}
		p := &Proxy{}
		switch pol % 4 {
		case 1: // the operator allows every private range
			p.allowPrivate, _ = normPrefixes("", mustPrefixes("0.0.0.0/0", "::/0"))
		case 2: // the operator blocks a prefix of the address (as the daemon blocks the host's own addresses)
			pr, _ := a.Prefix(int(sel) % (a.BitLen() + 1))
			p.blockPrefixes, _ = normPrefixes("", []netip.Prefix{pr})
		case 3:
			p.allowPrivate, _ = normPrefixes("", mustPrefixes("10.0.0.0/8", "169.254.0.0/16", "fc00::/7"))
		}
		// Blocked itself on the canonical address and its mapped form.
		if oracleBlocked(a) {
			if bad, _ := Blocked(a); !bad {
				t.Fatalf("Blocked(%v) = false; the oracle blocks it", a)
			}
			if a.Is4() {
				if bad, _ := Blocked(netip.AddrFrom16(a.As16())); !bad {
					t.Fatalf("Blocked(%v) = false for the IPv4-mapped form", netip.AddrFrom16(a.As16()))
				}
			}
		}
		// The resolver path: any address a resolver returns, with or without a zone, in mapped form.
		for _, r := range []netip.Addr{a, a.WithZone("eth0"), netip.AddrFrom16(a.As16())} {
			if !r.IsValid() {
				continue
			}
			p2 := &Proxy{allowPrivate: p.allowPrivate, blockPrefixes: p.blockPrefixes, resolver: fixedResolver{r}}
			p2.cfg.DialTimeout = DefaultDialTimeout
			got, err := p2.resolve(context.Background(), "name.example", netip.Addr{})
			if err == nil {
				for _, g := range got {
					if bad, _ := p2.refused(g); bad {
						t.Fatalf("resolve returned %v, which refused() refuses", g)
					}
					if oracleBlocked(g) && len(p.allowPrivate) == 0 {
						t.Fatalf("resolve(%v) returned %v, which the oracle blocks", r, g)
					}
					if oracleMetadata(g) {
						t.Fatalf("resolve(%v) returned metadata address %v", r, g)
					}
				}
			}
		}
		if a.Is4() {
			for _, form := range v4Forms(binary.BigEndian.Uint32(a.AsSlice()), sel) {
				checkForm(t, p, form, a)
			}
		} else {
			for _, form := range v6Forms(a) {
				checkForm(t, p, form, a)
			}
		}
	})
}

type fixedResolver struct{ a netip.Addr }

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{r.a}, nil
}

// FuzzHostText: any host text (not only well-formed addresses) that the proxy accepts as an IP literal is checked as
// that literal, and any it accepts as a name is not one inet_aton reads as an IPv4 address.
func FuzzHostText(f *testing.F) {
	for _, s := range []string{"127.0.0.1", "127.1", "0x7f.1", "2130706433", "017700000001", "[::ffff:127.0.0.1]:443",
		"example.com:443", "[fe80::1%25eth0]:443", "127.0.0.1.:443", "0177.0.0.1", "1.2.3.4.5", "[::127.0.0.1]",
		"localhost:443", "a.0x7f", "foo.0", "0x.0x", "1e2.1"} {
		f.Add(s)
	}
	p := &Proxy{}
	f.Fuzz(func(t *testing.T, s string) {
		for _, def := range []int{0, 80} {
			host, lit, port, err := parseAuthority(s, def)
			if err != nil {
				continue
			}
			if port < 1 || port > 65535 {
				t.Fatalf("parseAuthority(%q) port %d", s, port)
			}
			// canonical and idempotent: what is checked is what is dialed and what the allowlist compares
			h2, l2, err := normalizeHost(host)
			if err != nil || h2 != host || l2 != lit {
				t.Fatalf("parseAuthority(%q) host %q is not canonical: normalizeHost gives %q %v %v", s, host, h2, l2, err)
			}
			h3, l3, p3, err := parseAuthority(hostPort(host, port), 0)
			if err != nil || h3 != host || l3 != lit || p3 != port {
				t.Fatalf("parseAuthority(%q) = %q %v %d does not survive hostPort: %q %v %d %v", s, host, lit, port, h3, l3, p3, err)
			}
			if lit.IsValid() {
				if lit.Zone() != "" {
					t.Fatalf("parseAuthority(%q) kept zone %q", s, lit.Zone())
				}
				if oracleBlocked(lit) {
					if bad, _ := p.refused(lit); !bad {
						t.Fatalf("parseAuthority(%q) = %v, blocked by the oracle, not refused", s, lit)
					}
				}
				continue
			}
			if strings.ContainsAny(host, ":[]%@/\\ ") || strings.ToLower(host) != host {
				t.Fatalf("parseAuthority(%q) name %q has a character a name must not", s, host)
			}
			if v, ok := inetAton(host); ok {
				t.Fatalf("parseAuthority(%q) accepts %q as a name; inet_aton reads it as %08x", s, host, v)
			}
		}
	})
}
