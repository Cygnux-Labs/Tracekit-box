package egress

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// maxHostLen is the longest host name we accept (RFC 1035).
const maxHostLen = 253

// normalizeHost validates a host as the client sent it (no port, no brackets) and returns it in canonical form:
// lower case, no trailing dot, only [a-z0-9.-] for names (IDNs must arrive as punycode), or an IP literal.
// addr is valid when the host is an IP literal.
func normalizeHost(s string) (string, netip.Addr, error) {
	if s == "" {
		return "", netip.Addr{}, errors.New("empty host")
	}
	if len(s) > maxHostLen+1 {
		return "", netip.Addr{}, fmt.Errorf("host longer than %d characters", maxHostLen)
	}
	if strings.Contains(s, ":") {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is6() {
			return "", netip.Addr{}, errors.New("not a valid IPv6 address")
		}
		if a.Zone() != "" {
			return "", netip.Addr{}, errors.New("IPv6 zones are not allowed")
		}
		return a.String(), a, nil
	}
	// ASCII only, checked before lower-casing: strings.ToLower would fold look-alikes such as the Kelvin sign into "k".
	b := []byte(s)
	for i, c := range b {
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '.', c == '-':
		case 'A' <= c && c <= 'Z':
			b[i] = c + 'a' - 'A'
		default:
			return "", netip.Addr{}, fmt.Errorf("host has character %q; only letters, digits, '.' and '-' are allowed (IDNs as punycode)", c)
		}
	}
	h := strings.TrimSuffix(string(b), ".")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.String(), a, nil
	}
	if err := checkHostName(h); err != nil {
		return "", netip.Addr{}, err
	}
	return h, netip.Addr{}, nil
}

// checkHostName checks an already lower-cased name.
func checkHostName(h string) error {
	if h == "" {
		return errors.New("empty host")
	}
	if len(h) > maxHostLen {
		return fmt.Errorf("host longer than %d characters", maxHostLen)
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" {
			return errors.New("host has an empty label")
		}
		if len(l) > 63 {
			return errors.New("host has a label longer than 63 characters")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("host label starts or ends with '-'")
		}
	}
	// Resolvers parse "127.1", "2130706433" or "0x7f.1" as IPv4; refuse anything that looks numeric at the top.
	last := labels[len(labels)-1]
	if strings.Trim(last, "0123456789") == "" || (strings.HasPrefix(last, "0x") && strings.Trim(last[2:], "0123456789abcdef") == "") {
		return errors.New("host looks like a numeric IPv4 address; write IPv4 as a dotted quad (1.2.3.4)")
	}
	return nil
}

// parsePort parses a decimal TCP port 1..65535 (no sign, no spaces).
func parsePort(s string) (int, error) {
	if s == "" || len(s) > 5 || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("port %q is not a number from 1 to 65535", s)
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q is not a number from 1 to 65535", s)
	}
	return n, nil
}

// parseAuthority parses "host:port", "[v6]:port" or, with defaultPort > 0, a bare host.
func parseAuthority(raw string, defaultPort int) (host string, addr netip.Addr, port int, err error) {
	if raw == "" {
		return "", netip.Addr{}, 0, errors.New("empty host")
	}
	if strings.ContainsAny(raw, "@/?#%\\ \t") {
		return "", netip.Addr{}, 0, errors.New("host has a character that is not allowed")
	}
	h, p := raw, ""
	switch {
	case strings.HasPrefix(raw, "["):
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return "", netip.Addr{}, 0, errors.New("unclosed '[' in host")
		}
		h, p = raw[1:end], raw[end+1:]
		if p != "" {
			if p[0] != ':' {
				return "", netip.Addr{}, 0, errors.New("junk after ']' in host")
			}
			p = p[1:]
			if p == "" {
				return "", netip.Addr{}, 0, errors.New("empty port")
			}
		}
		if !strings.Contains(h, ":") {
			return "", netip.Addr{}, 0, errors.New("only IPv6 addresses go in brackets")
		}
	case strings.Count(raw, ":") > 1:
		return "", netip.Addr{}, 0, errors.New("IPv6 addresses must be in brackets, e.g. [2001:db8::1]:443")
	case strings.Contains(raw, ":"):
		i := strings.LastIndexByte(raw, ':')
		h, p = raw[:i], raw[i+1:]
		if p == "" {
			return "", netip.Addr{}, 0, errors.New("empty port")
		}
	}
	if p == "" {
		if defaultPort <= 0 {
			return "", netip.Addr{}, 0, errors.New("missing port (want host:port)")
		}
		port = defaultPort
	} else if port, err = parsePort(p); err != nil {
		return "", netip.Addr{}, 0, err
	}
	host, addr, err = normalizeHost(h)
	return host, addr, port, err
}

// hostPort joins host and port, bracketing IPv6.
func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// hostPattern is one allowlist entry (or a secret host, a model host, a CA name constraint).
type hostPattern struct {
	host     string     // exact host, or the parent domain of a wildcard
	addr     netip.Addr // set for IP literals
	wildcard bool       // "*.host": subdomains only, never the apex
	port     int        // 0 = ports 80 and 443
}

func (h hostPattern) String() string {
	s := h.host
	if h.wildcard {
		s = "*." + s
	}
	if h.port == 0 {
		return s
	}
	return hostPort(s, h.port)
}

// matchHost reports whether host (canonical) matches, ignoring the port.
func (h hostPattern) matchHost(host string, addr netip.Addr) bool {
	if h.addr.IsValid() {
		return addr.IsValid() && addr.Unmap() == h.addr.Unmap()
	}
	if addr.IsValid() {
		return false
	}
	if h.wildcard {
		return len(host) > len(h.host)+1 && strings.HasSuffix(host, h.host) && host[len(host)-len(h.host)-1] == '.'
	}
	return host == h.host
}

func (h hostPattern) match(host string, addr netip.Addr, port int) bool {
	if !h.matchHost(host, addr) {
		return false
	}
	if h.port == 0 {
		return port == 80 || port == 443
	}
	return port == h.port
}

// parsePattern parses "host", "*.host", "host:port", "*.host:port", "1.2.3.4", "1.2.3.4:8443", "2001:db8::1",
// "[2001:db8::1]" or "[2001:db8::1]:8443".
func parsePattern(entry string, allowPort bool) (hostPattern, error) {
	s := strings.TrimSpace(entry)
	if s == "" {
		return hostPattern{}, errors.New("empty entry")
	}
	var pat hostPattern
	if strings.HasPrefix(s, "*.") {
		pat.wildcard = true
		s = s[2:]
	}
	var hostPart, portPart string
	switch {
	case strings.HasPrefix(s, "["):
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return hostPattern{}, errors.New("unclosed '['")
		}
		hostPart, portPart = s[1:end], s[end+1:]
		if portPart != "" {
			if portPart[0] != ':' || len(portPart) == 1 {
				return hostPattern{}, errors.New("want [ipv6]:port")
			}
			portPart = portPart[1:]
		}
		if !strings.Contains(hostPart, ":") {
			return hostPattern{}, errors.New("only IPv6 addresses go in brackets")
		}
	case strings.Count(s, ":") > 1:
		hostPart = s // bare IPv6, no port
	case strings.Contains(s, ":"):
		i := strings.LastIndexByte(s, ':')
		hostPart, portPart = s[:i], s[i+1:]
		if portPart == "" {
			return hostPattern{}, errors.New("empty port")
		}
	default:
		hostPart = s
	}
	if portPart != "" {
		if !allowPort {
			return hostPattern{}, errors.New("no port allowed here")
		}
		p, err := parsePort(portPart)
		if err != nil {
			return hostPattern{}, err
		}
		pat.port = p
	}
	if strings.Contains(hostPart, "*") {
		return hostPattern{}, errors.New("'*' is only allowed as a leading \"*.\"")
	}
	h, a, err := normalizeHost(hostPart)
	if err != nil {
		return hostPattern{}, err
	}
	if !a.IsValid() && !strings.Contains(h, ".") {
		return hostPattern{}, errors.New("not a preset, and a host needs a domain (example.com)")
	}
	if pat.wildcard {
		if a.IsValid() {
			return hostPattern{}, errors.New("a wildcard needs a domain, not an IP address")
		}
		if !strings.Contains(h, ".") {
			return hostPattern{}, fmt.Errorf("*.%s is too broad: name a domain with at least two labels", h)
		}
	}
	pat.host, pat.addr = h, a
	return pat, nil
}

type patterns []hostPattern

func (ps patterns) match(host string, addr netip.Addr, port int) bool {
	for _, p := range ps {
		if p.match(host, addr, port) {
			return true
		}
	}
	return false
}

func (ps patterns) matchHost(host string, addr netip.Addr) bool {
	for _, p := range ps {
		if p.matchHost(host, addr) {
			return true
		}
	}
	return false
}

func parsePatterns(what string, entries []string, allowPort bool) (patterns, error) {
	out := make(patterns, 0, len(entries))
	for _, e := range entries {
		p, err := parsePattern(e, allowPort)
		if err != nil {
			return nil, fmt.Errorf("egress: %s %q: %v", what, e, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Presets. Hosts are what the tools contact by default; anything they redirect to must be listed too.
var presets = map[string]Preset{
	// git over HTTPS, the REST/GraphQL API, archives, raw files, release assets and LFS objects.
	"github": {Hosts: []string{
		"github.com", "api.github.com", "codeload.github.com", "uploads.github.com",
		"raw.githubusercontent.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
		"github-releases.githubusercontent.com", "media.githubusercontent.com", "gist.githubusercontent.com",
	}},
	// pip, uv and poetry: the index and the file CDN (no upload.pypi.org: publishing is not installing).
	"pypi": {Hosts: []string{"pypi.org", "files.pythonhosted.org"}},
	// npm, pnpm and yarn (classic yarn defaults to its own registry alias).
	"npm":       {Hosts: []string{"registry.npmjs.org", "registry.yarnpkg.com"}},
	"anthropic": {Hosts: []string{"api.anthropic.com"}, Model: true},
	"openai":    {Hosts: []string{"api.openai.com"}, Model: true},
	// Claude Code: the model API plus Anthropic's feature-flag host. Deliberately not sentry.io or statsig.com:
	// multi-tenant upload endpoints anyone can receive data on. Set CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1.
	"claude-code": {Hosts: []string{"api.anthropic.com", "statsig.anthropic.com"}},
	// apt on Ubuntu images: plain HTTP on port 80 (amd64 from archive/security, arm64 from ports).
	"apt-ubuntu": {Hosts: []string{"archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com"}},
	// apt on Debian images: bookworm/trixie debian.sources use deb.debian.org for both the archive and security;
	// older images use security.debian.org.
	"debian": {Hosts: []string{"deb.debian.org", "security.debian.org"}},
	// The Go module proxy and checksum database (GOPROXY's "direct" fallback needs the VCS hosts as well).
	"go-proxy": {Hosts: []string{"proxy.golang.org", "sum.golang.org"}},
}

// presetNames lists the presets for error messages.
func presetNames() string {
	names := make([]string, 0, len(presets))
	for n := range presets {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func clonePreset(p Preset) Preset {
	return Preset{Hosts: append([]string(nil), p.Hosts...), Model: p.Model}
}

// Preset is a named group of hosts.
type Preset struct {
	Hosts []string
	Model bool // requests to these hosts are model calls
}

// Presets returns the built-in presets: github, pypi, npm, anthropic, openai, claude-code, apt-ubuntu, debian,
// go-proxy. The map is a copy.
func Presets() map[string]Preset {
	out := make(map[string]Preset, len(presets))
	for k, v := range presets {
		out[k] = clonePreset(v)
	}
	return out
}

// Expand turns presets and host entries into Allow patterns and model hosts; an entry that is neither a preset nor a
// valid host pattern is an error naming it. A host is a model host when a model preset lists it, however it was
// allowed.
func Expand(entries []string) (allow, modelHosts []string, err error) {
	model := map[string]bool{}
	for _, p := range presets {
		if p.Model {
			for _, h := range p.Hosts {
				model[h] = true
			}
		}
	}
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			allow = append(allow, s)
		}
	}
	for _, e := range entries {
		if p, ok := presets[strings.ToLower(strings.TrimSpace(e))]; ok {
			for _, h := range p.Hosts {
				add(h)
			}
			continue
		}
		pat, perr := parsePattern(e, true)
		if perr != nil {
			return nil, nil, fmt.Errorf("egress: allow entry %q: %v; use a preset (%s) or a host such as example.com, *.example.com or example.com:8443",
				e, perr, presetNames())
		}
		add(pat.String())
	}
	mseen := map[string]bool{}
	for _, a := range allow {
		pat, _ := parsePattern(a, true)
		if !pat.wildcard && !pat.addr.IsValid() && (pat.port == 0 || pat.port == 443) && model[pat.host] && !mseen[pat.host] {
			mseen[pat.host] = true
			modelHosts = append(modelHosts, pat.host)
		}
	}
	return allow, modelHosts, nil
}
