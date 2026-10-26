package egress

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	ok := map[string]string{
		"Example.COM":                    "example.com",
		"example.com.":                   "example.com",
		"xn--bcher-kva.ch":               "xn--bcher-kva.ch",
		"a-b.c":                          "a-b.c",
		"1.2.3.4":                        "1.2.3.4",
		"2001:DB8::1":                    "2001:db8::1",
		"::ffff:10.0.0.1":                "10.0.0.1", // IPv4-mapped: the IPv4 address, as the allowlist matches it
		"::FFFF:1.2.3.4":                 "1.2.3.4",
		"::ffff:0:1.2.3.4":               "::ffff:0:102:304", // SIIT is not mapped and stays IPv6
		"api.github.com":                 "api.github.com",
		"s3.amazonaws.com":               "s3.amazonaws.com",
		"x1.example.co.uk.":              "x1.example.co.uk",
		strings.Repeat("a", 63) + ".com": strings.Repeat("a", 63) + ".com",
	}
	for in, want := range ok {
		got, _, err := normalizeHost(in)
		if err != nil || got != want {
			t.Errorf("normalizeHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "exa_mple.com", "tkbox_GH_x.evil.com", "bücher.ch", "Kelvin.com", // Kelvin sign folds to k
		"a..b", ".a.b", "-a.com", "a-.com", "127.1", "2130706433", "0x7f.1", "1.2.3.04",
		"fe80::1%en0", "a b.com", "a/b", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com",
		"example.com..",
	}
	for _, in := range bad {
		if got, _, err := normalizeHost(in); err == nil {
			t.Errorf("normalizeHost(%q) = %q, want an error", in, got)
		}
	}
}

func TestParseAuthority(t *testing.T) {
	cases := []struct {
		in   string
		def  int
		host string
		port int
	}{
		{"example.com:443", 0, "example.com", 443},
		{"EXAMPLE.com.:8443", 0, "example.com", 8443},
		{"[2001:db8::1]:443", 0, "2001:db8::1", 443},
		{"example.com", 80, "example.com", 80},
		{"[::1]", 80, "::1", 80},
		{"1.2.3.4:80", 0, "1.2.3.4", 80},
		{"[::ffff:1.2.3.4]:443", 0, "1.2.3.4", 443},
	}
	for _, c := range cases {
		h, _, p, err := parseAuthority(c.in, c.def)
		if err != nil || h != c.host || p != c.port {
			t.Errorf("parseAuthority(%q) = %q %d %v; want %q %d", c.in, h, p, err, c.host, c.port)
		}
	}
	for _, in := range []string{"example.com", "example.com:", "example.com:0", "example.com:65536", "example.com:+443",
		"example.com:44 3", "2001:db8::1:443", "[1.2.3.4]:443", "[::1", "[::1]x", "user@example.com:443", "example.com:443/x",
		"exa%41mple.com:443", ":443"} {
		if h, _, p, err := parseAuthority(in, 0); err == nil {
			t.Errorf("parseAuthority(%q) = %q %d, want an error", in, h, p)
		}
	}
}

func TestPatternsMatchPorts(t *testing.T) {
	ps, err := parsePatterns("allow", []string{"example.com", "*.wild.com", "api.test:8443", "1.2.3.4", "[2001:db8::1]:8443"}, true)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"example.com", 443, true},
		{"example.com", 80, true},
		{"example.com", 22, false},
		{"sub.example.com", 443, false},
		{"wild.com", 443, false}, // the apex is not a subdomain
		{"a.wild.com", 443, true},
		{"a.b.wild.com", 80, true},
		{"xwild.com", 443, false},
		{"api.test", 8443, true},
		{"api.test", 443, false},
		{"1.2.3.4", 80, true},
		{"1.2.3.4", 8080, false},
		{"::ffff:1.2.3.4", 443, true},
		{"2001:db8::1", 8443, true},
		{"2001:db8::1", 443, false},
	}
	for _, c := range cases {
		h, a, err := normalizeHost(c.host)
		if err != nil {
			t.Fatal(err)
		}
		if got := ps.match(h, a, c.port); got != c.want {
			t.Errorf("match(%s:%d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}

func TestExpand(t *testing.T) {
	allow, models, err := Expand([]string{"pypi", "GitHub", "anthropic", "claude-code", "debian", "Api.Example.com.", "*.corp.example:8443",
		"10.1.2.3:8080", "[2001:db8::5]", "pypi"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pypi.org", "files.pythonhosted.org", "github.com", "api.github.com", "codeload.github.com",
		"objects.githubusercontent.com", "raw.githubusercontent.com", "api.anthropic.com", "statsig.anthropic.com",
		"deb.debian.org", "security.debian.org", "api.example.com", "*.corp.example:8443", "10.1.2.3:8080", "2001:db8::5"} {
		if !slices.Contains(allow, want) {
			t.Errorf("Expand: %q missing from %v", want, allow)
		}
	}
	if n := len(allow); n != len(slices.Compact(slices.Sorted(slices.Values(allow)))) {
		t.Errorf("Expand returned duplicates: %v", allow)
	}
	if !slices.Equal(models, []string{"api.anthropic.com"}) {
		t.Errorf("model hosts = %v", models)
	}
	_, models, _ = Expand([]string{"openai", "api.anthropic.com"})
	if !slices.Equal(models, []string{"api.openai.com", "api.anthropic.com"}) {
		t.Errorf("model hosts = %v", models)
	}
	for _, bad := range []string{"pypy", "https://example.com", "*.com", "*", "ex*mple.com", "example.com:http", "a_b.com", ""} {
		_, _, err := Expand([]string{"github", bad})
		if err == nil || !strings.Contains(err.Error(), "\""+bad+"\"") {
			t.Errorf("Expand(%q) error = %v, want one naming the entry", bad, err)
		}
	}
	for name, p := range Presets() {
		if _, err := parsePatterns(name, p.Hosts, true); err != nil {
			t.Errorf("preset %s: %v", name, err)
		}
	}
	ps := Presets()
	ps["pypi"].Hosts[0] = "evil.com"
	if Presets()["pypi"].Hosts[0] != "pypi.org" {
		t.Error("Presets returned shared state")
	}
	for _, name := range []string{"github", "pypi", "npm", "anthropic", "openai", "apt-ubuntu", "go-proxy", "debian", "claude-code"} {
		if _, ok := Presets()[name]; !ok {
			t.Errorf("preset %s missing", name)
		}
	}
}

func TestBlocked(t *testing.T) {
	blocked := []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.255", "127.0.0.1", "127.255.0.1", "169.254.1.1",
		"169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.8", "192.0.2.1", "192.88.99.1", "192.168.1.1",
		"198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.9", "224.0.0.1", "239.255.255.250", "240.0.0.1",
		"255.255.255.255", "168.63.129.16",
		"::", "::1", "::127.0.0.1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "fc00::1", "fd12::1",
		"fe80::1", "fec0::1", "ff02::1", "100::1", "2001::1", "2001:0:4136:e378::1", "2001:db8::1", "2002:7f00:1::1",
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::a00:1", "64:ff9b:1::1", "fd00:ec2::254", "3fff::1",
	}
	for _, s := range blocked {
		if bad, why := Blocked(netip.MustParseAddr(s)); !bad || why == "" {
			t.Errorf("Blocked(%s) = %v %q, want blocked", s, bad, why)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "100.63.255.255", "100.128.0.1", "172.32.0.1", "192.169.0.1",
		"2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2600::1"}
	for _, s := range allowed {
		if bad, why := Blocked(netip.MustParseAddr(s)); bad {
			t.Errorf("Blocked(%s) = blocked (%s), want allowed", s, why)
		}
	}
	if bad, _ := Blocked(netip.Addr{}); !bad {
		t.Error("the zero address is not blocked")
	}
	if _, why := Blocked(netip.MustParseAddr("::ffff:192.168.0.1")); why != "private (RFC 1918)" {
		t.Errorf("mapped address reason = %q", why)
	}
}

func TestRefusedAllowPrivate(t *testing.T) {
	p := &Proxy{}
	var err error
	p.allowPrivate, err = normPrefixes("", []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
	if err != nil {
		t.Fatal(err)
	}
	p.blockPrefixes, _ = normPrefixes("", []netip.Prefix{netip.MustParsePrefix("::ffff:10.9.0.0/112"), netip.MustParsePrefix("8.8.8.0/24")})
	for _, s := range []string{"169.254.169.254", "::ffff:169.254.169.254", "fd00:ec2::254", "169.254.170.2", "10.9.1.1",
		"8.8.8.8", "::ffff:8.8.8.8", "64:ff9b::808:808", "64:ff9b::a9fe:a9fe"} {
		if bad, _ := p.refused(netip.MustParseAddr(s)); !bad {
			t.Errorf("refused(%s) = false with AllowPrivate everything; want true", s)
		}
	}
	for _, s := range []string{"10.0.0.1", "127.0.0.1", "::1", "192.168.1.1"} {
		if bad, why := p.refused(netip.MustParseAddr(s)); bad {
			t.Errorf("refused(%s) = %s, want exempt", s, why)
		}
	}
}
