package main

import (
	"crypto/x509"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
)

// #9: the daemon's egress flags reach daemon.Options. Dropping one on the way (EgressBlock: the operator's block
// list, such as the host's NAT'd public IP on a cloud VM) would leave every box without it and the rest of the suite
// green.
func TestDaemonOptionsCarryEgressBlock(t *testing.T) {
	block, private := stringList{split: true}, stringList{split: true}
	if err := block.Set("203.0.113.7,2001:db8::/32"); err != nil {
		t.Fatal(err)
	}
	if err := private.Set("10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	ca, err := egress.NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "upstream.pem")
	if err := os.WriteFile(caPath, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	opts, err := daemonOptions(daemonSetup{stateDir: state, maxBoxes: 3, approvalTimeout: time.Minute,
		egressBlock: block.vals, allowPrivate: private.vals, upstreamCA: caPath, logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32"), netip.MustParsePrefix("2001:db8::/32")}; !slices.Equal(opts.EgressBlock, want) {
		t.Errorf("EgressBlock %v, want %v", opts.EgressBlock, want)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}; !slices.Equal(opts.EgressAllowPrivate, want) {
		t.Errorf("EgressAllowPrivate %v, want %v", opts.EgressAllowPrivate, want)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertPEM())
	if opts.EgressUpstreamRoots == nil || !opts.EgressUpstreamRoots.Equal(roots) {
		t.Error("EgressUpstreamRoots is not the --upstream-ca file's certificate")
	}
	if opts.StateDir != state || opts.MaxBoxes != 3 || opts.ApprovalTimeout != time.Minute {
		t.Errorf("options %+v", opts)
	}

	// Without the test-only flags, nothing is exempted and the system roots stay.
	opts, err = daemonOptions(daemonSetup{stateDir: state, egressBlock: block.vals, logger: log.New(io.Discard, "", 0)})
	if err != nil || len(opts.EgressBlock) != 2 || opts.EgressAllowPrivate != nil || opts.EgressUpstreamRoots != nil {
		t.Errorf("options %+v, %v", opts, err)
	}
	if _, err := daemonOptions(daemonSetup{egressBlock: []string{"not-a-cidr"}, logger: log.New(io.Discard, "", 0)}); err == nil {
		t.Error("a bad --egress-block passed")
	}
}
