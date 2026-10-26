package egress

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestNewPlaceholder(t *testing.T) {
	re := regexp.MustCompile(`^tkbox_GH_TOKEN_[0-9a-f]{32}$`)
	a, err := NewPlaceholder("GH_TOKEN")
	if err != nil || !re.MatchString(a) {
		t.Fatalf("NewPlaceholder = %q, %v", a, err)
	}
	b, _ := NewPlaceholder("GH_TOKEN")
	if a == b {
		t.Fatal("placeholders repeat")
	}
	if !validPlaceholder("GH_TOKEN", a) {
		t.Fatal("own placeholder invalid")
	}
	for _, bad := range []string{"", "1X", "A-B", "A B", "Ä", strings.Repeat("A", 129)} {
		if _, err := NewPlaceholder(bad); err == nil {
			t.Errorf("NewPlaceholder(%q) succeeded", bad)
		}
	}
}

func TestCA(t *testing.T) {
	ca, err := NewCA("box-1")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := ca.CertPEM()
	if strings.Contains(string(pemBytes), "PRIVATE") {
		t.Fatal("CertPEM holds a key")
	}
	blk, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA || cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Error("CA basic constraints wrong")
	}
	if life := cert.NotAfter.Sub(cert.NotBefore); life > MaxCALifetime+clockSkew+time.Minute {
		t.Errorf("CA valid for %v", life)
	}
	short, _ := NewCAWith("b", CAOptions{Lifetime: time.Hour})
	if d := time.Until(short.cert.NotAfter); d > time.Hour+time.Minute {
		t.Errorf("Lifetime ignored: %v", d)
	}
	long, _ := NewCAWith("b", CAOptions{Lifetime: 30 * 24 * time.Hour})
	if d := time.Until(long.cert.NotAfter); d > MaxCALifetime+time.Minute {
		t.Errorf("lifetime not capped: %v", d)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	leaf, err := ca.leaf("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "api.example.com", Roots: roots}); err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}
	if again, _ := ca.leaf("api.example.com"); again != leaf {
		t.Error("leaf not cached")
	}
	ipLeaf, err := ca.leaf("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipLeaf.Leaf.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: roots}); err != nil {
		t.Fatalf("IP leaf does not verify: %v", err)
	}
}

func TestCANameConstraints(t *testing.T) {
	ca, err := NewCAWith("box-2", CAOptions{Hosts: []string{"api.github.com", "*.anthropic.com"}})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if !ca.cert.PermittedDNSDomainsCritical {
		t.Error("name constraints are not critical")
	}
	for _, h := range []string{"api.github.com", "api.anthropic.com"} {
		l, err := ca.leaf(h)
		if err != nil {
			t.Fatalf("leaf(%s): %v", h, err)
		}
		if _, err := l.Leaf.Verify(x509.VerifyOptions{DNSName: h, Roots: roots}); err != nil {
			t.Errorf("Go's verifier refuses a permitted name %s: %v", h, err)
		}
	}
	for _, h := range []string{"evil.com", "github.com", "anthropic.com", "x.api.github.com", "1.2.3.4"} {
		if _, err := ca.leaf(h); err == nil {
			t.Errorf("leaf(%s) minted outside the constraints", h)
		}
	}
	// Even a certificate minted around Permits fails verification. (The X.509 constraints are coarser than Permits:
	// "*.anthropic.com" is written as anthropic.com, which also admits the apex.)
	for _, h := range []string{"evil.com", "github.com", "1.2.3.4"} {
		mustVerifyFails(t, ca, roots, h)
	}
	if _, err := New(Config{Decider: nopDecider{}, Sink: nopSink{}, CA: ca, Secrets: []Secret{mkSecret(t, "GH", "", "github.com")}}); err == nil {
		t.Error("New accepted a secret host outside the CA's constraints")
	}
	if _, err := New(Config{Decider: nopDecider{}, Sink: nopSink{}, CA: ca, Secrets: []Secret{mkSecret(t, "GH", "", "api.github.com")}}); err != nil {
		t.Errorf("New refused a permitted secret host: %v", err)
	}
}

// An empty, non-nil host list (inspect all with no allow entries and no secrets) is a CA for no host at all, in
// Permits and in the certificate: with no DNS subtree written, X.509 would permit every name.
func TestCAEmptyHostsPermitsNothing(t *testing.T) {
	ca, err := NewCAWith("box-3", CAOptions{Hosts: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	for _, h := range []string{"evil.example", "github.com", "8.8.8.8", "2606:4700::1111"} {
		if ca.Permits(h) {
			t.Errorf("Permits(%s) with no hosts", h)
		}
		if _, err := ca.leaf(h); err == nil {
			t.Errorf("leaf(%s) minted with no hosts", h)
		}
		mustVerifyFails(t, ca, roots, h)
	}
}

// mustVerifyFails mints a leaf for host directly (bypassing Permits) and checks Go's verifier refuses it.
func mustVerifyFails(t *testing.T, ca *CA, roots *x509.CertPool, host string) bool {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	if ip := parseIP(host); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &ca.leafKey.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	if _, err := c.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err == nil {
		t.Errorf("Go's verifier accepts %s outside the name constraints", host)
		return false
	}
	return true
}
