package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"time"
)

type blockRange struct {
	prefix netip.Prefix
	why    string
}

// builtinBlocked are the ranges Box never connects to. Order matters only for the name reported.
var builtinBlocked = func() []blockRange {
	rows := [][2]string{
		{"0.0.0.0/8", "\"this network\" (0.0.0.0/8)"},
		{"10.0.0.0/8", "private (RFC 1918)"},
		{"100.64.0.0/10", "shared address space / CGNAT (RFC 6598)"},
		{"127.0.0.0/8", "loopback"},
		{"169.254.0.0/16", "link-local"},
		{"172.16.0.0/12", "private (RFC 1918)"},
		{"192.0.0.0/24", "IETF protocol assignments (RFC 6890)"},
		{"192.0.2.0/24", "documentation (TEST-NET-1)"},
		{"192.88.99.0/24", "6to4 relay anycast"},
		{"192.168.0.0/16", "private (RFC 1918)"},
		{"198.18.0.0/15", "benchmarking (RFC 2544)"},
		{"198.51.100.0/24", "documentation (TEST-NET-2)"},
		{"203.0.113.0/24", "documentation (TEST-NET-3)"},
		{"224.0.0.0/4", "multicast"},
		{"255.255.255.255/32", "broadcast"},
		{"240.0.0.0/4", "reserved (240.0.0.0/4)"},
		{"::/128", "unspecified"},
		{"::1/128", "loopback"},
		{"::/96", "IPv4-compatible IPv6 (deprecated)"},
		{"::ffff:0:0:0/96", "IPv4-translated IPv6 (SIIT)"},
		{"64:ff9b:1::/48", "local-use NAT64 (RFC 8215)"},
		{"100::/64", "discard-only (RFC 6666)"},
		{"2001::/32", "Teredo"},
		{"2001:db8::/32", "documentation"},
		{"2001::/23", "IETF protocol assignments"},
		{"2002::/16", "6to4"},
		{"3fff::/20", "documentation (RFC 9637)"},
		{"5f00::/16", "SRv6 segment identifiers (RFC 9602)"},
		{"fc00::/7", "unique local (ULA)"},
		{"fe80::/10", "link-local"},
		{"fec0::/10", "site-local (deprecated)"},
		{"ff00::/8", "multicast"},
	}
	out := make([]blockRange, len(rows))
	for i, r := range rows {
		out[i] = blockRange{netip.MustParsePrefix(r[0]), r[1]}
	}
	return out
}()

// nat64 is the well-known NAT64 prefix; the IPv4 address is in the last 32 bits.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// metadataAddrs are cloud instance-metadata and platform endpoints. They are refused even when AllowPrivate covers
// them: reaching one hands the guest the host's cloud credentials.
var metadataAddrs = map[netip.Addr]string{
	netip.MustParseAddr("169.254.169.254"): "cloud metadata service",
	netip.MustParseAddr("fd00:ec2::254"):   "cloud metadata service (AWS IPv6)",
	netip.MustParseAddr("169.254.170.2"):   "container credentials endpoint (AWS ECS)",
	netip.MustParseAddr("169.254.170.23"):  "pod identity endpoint (AWS EKS)",
	netip.MustParseAddr("fd00:ec2::23"):    "pod identity endpoint (AWS EKS IPv6)",
	netip.MustParseAddr("100.100.100.200"): "cloud metadata service (Alibaba)",
	netip.MustParseAddr("168.63.129.16"):   "platform endpoint (Azure WireServer)",
}

// Blocked reports whether a is refused by the built-in ranges, and which one. IPv4-mapped addresses are unwrapped
// first and NAT64 (64:ff9b::/96) addresses are judged by the IPv4 address they embed.
func Blocked(a netip.Addr) (bool, string) {
	if !a.IsValid() {
		return true, "invalid address"
	}
	a = a.Unmap().WithZone("")
	if why, ok := metadataAddrs[a]; ok {
		return true, why
	}
	if nat64.Contains(a) {
		b := a.As16()
		v4 := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		if bad, why := Blocked(v4); bad {
			return true, "NAT64 of " + why
		}
		return false, ""
	}
	for _, r := range builtinBlocked {
		if r.prefix.Contains(a) {
			return true, r.why
		}
	}
	return false, ""
}

// addrViews returns a (unmapped, no zone) and, for NAT64, the IPv4 address it embeds.
func addrViews(a netip.Addr) []netip.Addr {
	a = a.Unmap().WithZone("")
	if nat64.Contains(a) {
		b := a.As16()
		return []netip.Addr{a, netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})}
	}
	return []netip.Addr{a}
}

// normPrefixes masks prefixes and turns IPv4-mapped ones into IPv4.
func normPrefixes(what string, in []netip.Prefix) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() {
			return nil, fmt.Errorf("egress: %s: invalid prefix %v", what, p)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return nil, fmt.Errorf("egress: %s: %v mixes IPv4-mapped and IPv6", what, p)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// operatorBlocked names an address BlockPrefixes or BlockFunc refuses (the daemon blocks the host's own addresses).
const operatorBlocked = "an address of this host or one the operator blocked"

// refused applies the proxy's full address policy: metadata, BlockPrefixes and BlockFunc always, the built-in ranges
// unless AllowPrivate exempts the address. what names the address for a sentence ("a loopback address").
func (p *Proxy) refused(a netip.Addr) (bad bool, what string) {
	if !a.IsValid() {
		return true, "an invalid address"
	}
	for _, v := range addrViews(a) {
		if why, ok := metadataAddrs[v]; ok {
			return true, "a " + why + " address"
		}
		for _, bp := range p.blockPrefixes {
			// An IPv6 prefix that spans the IPv4-mapped range (::/0, ::/23) covers the IPv4 addresses there too:
			// Box connects to ::ffff:a.b.c.d as a.b.c.d.
			if bp.Contains(v) || v.Is4() && bp.Contains(netip.AddrFrom16(v.As16())) {
				return true, operatorBlocked
			}
		}
		if bad, what := p.blockFunc(v); bad {
			return true, what
		}
	}
	bad, why := Blocked(a)
	if !bad {
		return false, ""
	}
	u := a.Unmap().WithZone("")
	for _, ap := range p.allowPrivate {
		if ap.Contains(u) {
			return false, ""
		}
	}
	return true, "a " + why + " address"
}

// blockFunc asks Config.BlockFunc, the operator's live check; a panic refuses.
func (p *Proxy) blockFunc(a netip.Addr) (bad bool, what string) {
	if p.cfg.BlockFunc == nil {
		return false, ""
	}
	defer func() {
		if r := recover(); r != nil {
			bad, what = true, operatorBlocked+" (the operator's address check failed)"
		}
	}()
	bad, why := p.cfg.BlockFunc(a)
	if !bad {
		return false, ""
	}
	if why = printable(why, 100); why != "" {
		return true, operatorBlocked + " (" + why + ")"
	}
	return true, operatorBlocked
}

// resolveError is a refusal found while resolving: detail goes to events, public to the guest.
type resolveError struct {
	public, detail string
	status         int
}

func (e *resolveError) Error() string { return e.detail }

// resolve resolves host once and checks every address; any refused address refuses the host (a name that answers
// with one public and one private address is a rebinding attempt). The result is what the proxy dials, IPv4 first.
func (p *Proxy) resolve(ctx context.Context, host string, lit netip.Addr) ([]netip.Addr, error) {
	var addrs []netip.Addr
	if lit.IsValid() {
		addrs = []netip.Addr{lit}
	} else {
		// Rooted (trailing dot): the host's search domains must never turn a guest's name into an internal one.
		rctx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
		res, err := p.resolver.LookupNetIP(rctx, "ip", host+".")
		cancel()
		if err != nil {
			return nil, &resolveError{status: 502, public: "could not resolve the host name",
				detail: "could not resolve the host name: " + err.Error()}
		}
		addrs = res
	}
	seen := make(map[netip.Addr]bool, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if bad, why := p.refused(a); bad {
			return nil, &resolveError{status: 403,
				public: "it resolves to " + why + ", which Box never connects to",
				detail: fmt.Sprintf("it resolves to %v, %s, which Box never connects to", a, why)}
		}
		u := a.Unmap().WithZone("")
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil, &resolveError{status: 502, public: "the host name has no addresses",
			detail: "the host name has no addresses"}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Is4() && !out[j].Is4() })
	return out, nil
}

// dial connects to one of the checked addresses (never re-resolving), splitting DialTimeout across them.
func (p *Proxy) dial(ctx context.Context, addrs []netip.Addr, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()
	d := net.Dialer{Control: p.dialControl}
	var errs []string
	for i, a := range addrs {
		actx, acancel := ctx, context.CancelFunc(func() {})
		if dl, ok := ctx.Deadline(); ok && len(addrs)-i > 1 {
			per := time.Until(dl) / time.Duration(len(addrs)-i)
			if per < 2*time.Second {
				per = 2 * time.Second
			}
			actx, acancel = context.WithTimeout(ctx, per)
		}
		c, err := d.DialContext(actx, "tcp", netip.AddrPortFrom(a, uint16(port)).String())
		acancel()
		if err == nil {
			return c, nil
		}
		errs = append(errs, err.Error())
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		return nil, errors.New("no address to dial")
	}
	return nil, errors.New(strings.Join(errs, "; "))
}

// dialControl re-checks the exact address the socket connects to (defense in depth against a resolver bug).
func (p *Proxy) dialControl(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("refusing to dial %q: %v", address, err)
	}
	if bad, why := p.refused(ap.Addr()); bad {
		return fmt.Errorf("refusing to dial %s", why)
	}
	return nil
}
