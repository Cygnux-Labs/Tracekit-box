package egress

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strings"
)

const placeholderPrefix = "tkbox_"

// NewPlaceholder returns "tkbox_<name>_<32 random hex>".
func NewPlaceholder(name string) (string, error) {
	if !validSecretName(name) {
		return "", fmt.Errorf("egress: secret name %q: use letters, digits and '_' (an environment variable name)", name)
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("egress: placeholder: %w", err)
	}
	return placeholderPrefix + name + "_" + hex.EncodeToString(b[:]), nil
}

func validSecretName(name string) bool {
	if name == "" || len(name) > 128 || ('0' <= name[0] && name[0] <= '9') {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func validPlaceholder(name, ph string) bool {
	rest, ok := strings.CutPrefix(ph, placeholderPrefix+name+"_")
	if !ok || len(rest) != 32 {
		return false
	}
	return strings.Trim(rest, "0123456789abcdef") == ""
}

// hopByHop are stripped from every forwarded request and response (RFC 9110 7.6.1, plus the proxy's own).
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// secretRule is a validated Secret.
type secretRule struct {
	Secret
	hosts   patterns
	lowerPH string
}

func newSecretRule(s Secret) (*secretRule, error) {
	if !validSecretName(s.Name) {
		return nil, fmt.Errorf("egress: secret %q: name must be an environment variable name", s.Name)
	}
	if !validPlaceholder(s.Name, s.Placeholder) {
		return nil, fmt.Errorf("egress: secret %s: placeholder must come from NewPlaceholder(%q)", s.Name, s.Name)
	}
	if s.Value == "" {
		return nil, fmt.Errorf("egress: secret %s: empty value", s.Name)
	}
	for i := 0; i < len(s.Value); i++ {
		if c := s.Value[i]; c < 0x20 || c == 0x7f {
			// It goes into a header: CR/LF would let the value split the request.
			return nil, fmt.Errorf("egress: secret %s: value has a control character; secrets are sent in HTTP headers", s.Name)
		}
	}
	if strings.Contains(s.Value, placeholderPrefix) {
		return nil, fmt.Errorf("egress: secret %s: value contains %q", s.Name, placeholderPrefix)
	}
	if len(s.Hosts) == 0 {
		return nil, fmt.Errorf("egress: secret %s: no hosts; bind it to the hosts that should receive it", s.Name)
	}
	hosts, err := parsePatterns("secret "+s.Name+" host", s.Hosts, false)
	if err != nil {
		return nil, err
	}
	if s.Header != "" {
		if !validHeaderName(s.Header) {
			return nil, fmt.Errorf("egress: secret %s: header %q is not a valid header name", s.Name, s.Header)
		}
		s.Header = textproto.CanonicalMIMEHeaderKey(s.Header)
		if s.Header == "Host" || isHopByHop(s.Header) {
			return nil, fmt.Errorf("egress: secret %s: header %s is never forwarded; bind a request header such as Authorization", s.Name, s.Header)
		}
	}
	return &secretRule{Secret: s, hosts: hosts, lowerPH: asciiLower(s.Placeholder)}, nil
}

func (s *secretRule) boundTo(host string) bool {
	h, a, err := normalizeHost(host)
	return err == nil && s.hosts.matchHost(h, a)
}

func validHeaderName(h string) bool {
	if h == "" {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

func isHopByHop(canon string) bool {
	for _, h := range hopByHop {
		if canon == h {
			return true
		}
	}
	return false
}

func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// find returns the secrets whose placeholder occurs in s (case-insensitively when fold is set).
func (p *Proxy) find(s string, fold bool) []*secretRule {
	if len(p.secrets) == 0 {
		return nil
	}
	if fold {
		s = asciiLower(s)
		if !strings.Contains(s, placeholderPrefix) {
			return nil
		}
	} else if !strings.Contains(s, placeholderPrefix) {
		return nil
	}
	var out []*secretRule
	for _, r := range p.secrets {
		ph := r.Placeholder
		if fold {
			ph = r.lowerPH
		}
		if strings.Contains(s, ph) {
			out = append(out, r)
		}
	}
	return out
}

// findTarget looks for placeholders in a request target, raw and percent-decoded.
func (p *Proxy) findTarget(target string) []*secretRule {
	if f := p.find(target, false); f != nil {
		return f
	}
	if u, err := url.PathUnescape(target); err == nil {
		if f := p.find(u, false); f != nil {
			return f
		}
	}
	if u, err := url.QueryUnescape(target); err == nil {
		return p.find(u, false)
	}
	return nil
}

// redact replaces every placeholder in s with "[secret NAME]" so events never carry one.
func (p *Proxy) redact(s string) string {
	if len(p.secrets) == 0 || s == "" {
		return s
	}
	low := asciiLower(s)
	if !strings.Contains(low, placeholderPrefix) {
		return s
	}
	for _, r := range p.secrets {
		for {
			i := strings.Index(low, r.lowerPH)
			if i < 0 {
				break
			}
			repl := "[secret " + r.Name + "]"
			s = s[:i] + repl + s[i+len(r.Placeholder):]
			low = low[:i] + asciiLower(repl) + low[i+len(r.Placeholder):]
		}
	}
	return s
}

// leakError is a placeholder going somewhere it may not.
type leakError struct {
	secret *secretRule
	reason string // for the event and the guest; never holds a placeholder or a value
	todo   string
}

func (e *leakError) Error() string { return e.reason }

// swapHeaders checks every header for placeholders. On a bound host (swap) a placeholder in the secret's header
// (or any header when the secret has none) is replaced by the value; anywhere else it is a leak. Authorization
// Basic credentials are decoded so git's "x-access-token:<token>" form works.
func (p *Proxy) swapHeaders(h http.Header, host string, swap bool) (used []*secretRule, leak *leakError) {
	if len(p.secrets) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	usedSet := map[*secretRule]bool{}
	for _, name := range names {
		if f := p.find(name, true); f != nil {
			return nil, &leakError{secret: f[0], reason: fmt.Sprintf("a placeholder for secret %s is in a header name", f[0].Name),
				todo: "Send secrets only as header values"}
		}
		canon := textproto.CanonicalMIMEHeaderKey(name)
		vals := h[name]
		for i, v := range vals {
			nv, u, l := p.swapValue(canon, v, host, swap)
			if l != nil {
				return nil, l
			}
			if u == nil {
				continue
			}
			vals[i] = nv
			for _, r := range u {
				if !usedSet[r] {
					usedSet[r] = true
					used = append(used, r)
				}
			}
		}
	}
	return used, nil
}

func (p *Proxy) swapValue(canon, v, host string, swap bool) (string, []*secretRule, *leakError) {
	found := p.find(v, false)
	basic := ""
	if canon == "Authorization" && len(v) > 6 && strings.EqualFold(v[:6], "basic ") {
		if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[6:])); err == nil {
			basic = string(dec)
			for _, r := range p.find(basic, false) {
				if !containsRule(found, r) {
					found = append(found, r)
				}
			}
		}
	}
	if len(found) == 0 {
		return v, nil, nil
	}
	for _, r := range found {
		if l := p.checkUse(r, canon, host, swap); l != nil {
			return "", nil, l
		}
	}
	if basic != "" && p.find(basic, false) != nil {
		for _, r := range found {
			basic = strings.ReplaceAll(basic, r.Placeholder, r.Value)
		}
		v = v[:6] + base64.StdEncoding.EncodeToString([]byte(basic))
	}
	for _, r := range found {
		v = strings.ReplaceAll(v, r.Placeholder, r.Value)
	}
	return v, found, nil
}

func containsRule(rs []*secretRule, r *secretRule) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

// checkUse decides whether secret r may be swapped into header canon on a request to host.
func (p *Proxy) checkUse(r *secretRule, canon, host string, swap bool) *leakError {
	switch {
	case !swap:
		return &leakError{secret: r, reason: fmt.Sprintf("secret %s would go over plain HTTP; Box swaps secrets only into HTTPS requests", r.Name),
			todo: "Use https:// for this host"}
	case !r.boundTo(host):
		return &leakError{secret: r, reason: fmt.Sprintf("secret %s is not bound to this host", r.Name),
			todo: fmt.Sprintf("Send it only to %s, or bind it to this host in the box's secrets", strings.Join(r.Hosts, ", "))}
	case r.Header != "" && canon != r.Header:
		return &leakError{secret: r, reason: fmt.Sprintf("secret %s is only sent in the %s header, not %s", r.Name, r.Header, canon),
			todo: "Put the placeholder in the " + r.Header + " header"}
	}
	return nil
}

// redactValues replaces secret values echoed in response headers with their placeholders.
func (p *Proxy) redactValues(h http.Header) {
	for _, r := range p.secrets {
		if len(r.Value) < 8 {
			continue // too short to tell from ordinary text
		}
		for k, vs := range h {
			for i, v := range vs {
				if strings.Contains(v, r.Value) {
					h[k][i] = strings.ReplaceAll(v, r.Value, r.Placeholder)
				}
			}
		}
	}
}

var errLeak = errors.New("placeholder in request body")

// scanReader passes a body through while holding back enough bytes that no placeholder leaves before it is seen
// whole. On a hit it stops (the request is cut off upstream) and calls onLeak once.
type scanReader struct {
	p      *Proxy
	r      io.Reader
	hold   int // longest placeholder - 1
	buf    []byte
	tmp    []byte
	srcErr error
	onLeak func(*secretRule)
}

func (p *Proxy) newScanReader(r io.Reader, onLeak func(*secretRule)) *scanReader {
	hold := 0
	for _, s := range p.secrets {
		if len(s.Placeholder) > hold {
			hold = len(s.Placeholder)
		}
	}
	return &scanReader{p: p, r: r, hold: max(hold-1, 0), tmp: make([]byte, 32<<10), onLeak: onLeak}
}

func (s *scanReader) Read(b []byte) (int, error) {
	for {
		if len(s.buf) > 0 {
			safe := len(s.buf) - s.hold
			if s.srcErr != nil {
				safe = len(s.buf)
			}
			if safe > 0 {
				n := copy(b, s.buf[:safe])
				s.buf = s.buf[n:]
				return n, nil
			}
		}
		if s.srcErr != nil {
			return 0, s.srcErr
		}
		n, err := s.r.Read(s.tmp)
		if n > 0 {
			s.buf = append(s.buf, s.tmp[:n]...)
			if f := s.p.find(string(s.buf), false); f != nil {
				s.buf, s.srcErr = nil, errLeak
				if s.onLeak != nil {
					s.onLeak(f[0])
				}
				return 0, errLeak
			}
		}
		if err != nil {
			s.srcErr = err
		}
	}
}
