package egress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// MaxCALifetime caps a box CA's validity.
const MaxCALifetime = 7 * 24 * time.Hour

// clockSkew backdates certificates so a guest whose clock lags the host still accepts them.
const clockSkew = time.Hour

// maxLeaves bounds the per-host leaf cache.
const maxLeaves = 1024

// CA is a per-box MITM certificate authority (ECDSA P-256), valid for the box's lifetime only. The key lives only in
// this process's memory.
type CA struct {
	boxID   string
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
	leafKey *ecdsa.PrivateKey // one key for every leaf: leaves are cheap, keys are not
	permit  patterns          // nil: unconstrained

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// CAOptions tighten a box CA.
type CAOptions struct {
	// Lifetime is the validity from now: the box's timeout. 0 or more than MaxCALifetime means MaxCALifetime.
	Lifetime time.Duration
	// Hosts are the only hosts the CA may impersonate, written into critical X.509 name constraints: the bound
	// secrets' hosts (exact, "*.example.com" or IP literals) and, with Inspect "all", the allowlist hosts.
	// nil means unconstrained; an empty, non-nil list means no host at all (the certificate permits only the
	// reserved .invalid names and no IP address).
	Hosts []string
}

// NewCA creates a CA for one box, valid for MaxCALifetime and unconstrained. NewCAWith tightens both.
func NewCA(boxID string) (*CA, error) { return NewCAWith(boxID, CAOptions{}) }

// NewCAWith creates a CA for one box with a lifetime and name constraints.
func NewCAWith(boxID string, opts CAOptions) (*CA, error) {
	life := opts.Lifetime
	if life <= 0 || life > MaxCALifetime {
		life = MaxCALifetime
	}
	var permit patterns
	if opts.Hosts != nil {
		var err error
		if permit, err = parsePatterns("CA host", opts.Hosts, false); err != nil {
			return nil, err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("egress: CA key: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("egress: leaf key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	ski := sha256.Sum256(pub)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Tracekit Box"}, CommonName: "tkbox box CA " + printable(boxID, 32)},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(life),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski[:20],
	}
	if permit != nil {
		constrain(tmpl, permit)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("egress: CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		boxID:   boxID,
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
		leafKey: leafKey,
		permit:  permit,
		leaves:  make(map[string]*tls.Certificate),
	}, nil
}

// constrain writes critical name constraints. Exact names and wildcard parents go in as plain DNS constraints
// ("example.com" also admits its subdomains): leading-dot forms are not understood by every TLS library guests use
// (GnuTLS behind Debian's git). IP SANs are limited to the IP hosts, or excluded entirely.
func constrain(tmpl *x509.Certificate, permit patterns) {
	tmpl.PermittedDNSDomainsCritical = true
	var ips []*net.IPNet
	for _, p := range permit {
		if p.addr.IsValid() {
			a := p.addr.Unmap()
			ips = append(ips, &net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(a.BitLen(), a.BitLen())})
			continue
		}
		tmpl.PermittedDNSDomains = append(tmpl.PermittedDNSDomains, p.host)
	}
	if len(permit) == 0 {
		// No hosts at all: with no DNS subtree every name would be permitted, so permit only the reserved .invalid
		// (RFC 6761), which no real name is under. (IP-only lists keep DNS open: OpenSSL checks an IP leaf's
		// common name against DNS subtrees.)
		tmpl.PermittedDNSDomains = []string{"invalid"}
	}
	if len(ips) > 0 {
		tmpl.PermittedIPRanges = ips
	} else {
		tmpl.ExcludedIPRanges = []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
	}
}

// CertPEM is the CA certificate the guest trusts (never the key).
func (c *CA) CertPEM() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.certPEM...)
}

// Permits reports whether the CA may impersonate host (canonical form).
func (c *CA) Permits(host string) bool {
	if c == nil || c.key == nil {
		return false
	}
	if c.permit == nil {
		return true
	}
	h, a, err := normalizeHost(host)
	if err != nil {
		return false
	}
	return c.permit.matchHost(h, a)
}

func (c *CA) usable() bool { return c != nil && c.key != nil && c.leafKey != nil && c.cert != nil }

// leaf returns the cached certificate for host, minting it on first use.
func (c *CA) leaf(host string) (*tls.Certificate, error) {
	if !c.Permits(host) {
		return nil, fmt.Errorf("the box CA may not impersonate %s", host)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.leaves[host]; ok && time.Now().Before(l.Leaf.NotAfter) {
		return l, nil
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	nb := now.Add(-clockSkew)
	if nb.Before(c.cert.NotBefore) {
		nb = c.cert.NotBefore
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             nb,
		NotAfter:              c.cert.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        c.cert.SubjectKeyId,
	}
	if a, err := netip.ParseAddr(host); err == nil {
		tmpl.IPAddresses = []net.IP{net.IP(a.AsSlice())}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &c.leafKey.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("leaf certificate for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if len(c.leaves) >= maxLeaves {
		clear(c.leaves)
	}
	tc := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: c.leafKey, Leaf: leaf}
	c.leaves[host] = tc
	return tc, nil
}

func randSerial() (*big.Int, error) {
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, errors.New("egress: random serial: " + err.Error())
	}
	return s.Add(s, big.NewInt(1)), nil
}

// printable keeps printable ASCII and truncates to n bytes.
func printable(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < n; i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}
