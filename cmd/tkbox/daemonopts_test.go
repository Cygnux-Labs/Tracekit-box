package main

import (
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/daemon"
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

// L2 (final check, #9): what tkbox daemon's flags say reaches daemonOptions. cmdDaemon hands it the setup it took
// from its flags, and the hook sees that setup before anything touches the host, so dropping a flag on the way
// (--egress-block above all) fails here.
func TestDaemonFlagsReachDaemonOptions(t *testing.T) {
	ca, err := egress.NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "upstream.pem")
	if err := os.WriteFile(caPath, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	var got daemon.Options
	errStop := errors.New("stopped by the test")
	daemonFlagsHook = func(s daemonSetup) error {
		opts, err := daemonOptions(s)
		if err != nil {
			return err
		}
		got = opts
		return errStop
	}
	t.Cleanup(func() { daemonFlagsHook = nil })
	state := t.TempDir()
	code, _, errs := run(t, "", "daemon", "--state-dir", state, "--max-boxes", "3", "--approval-timeout", "1m",
		"--egress-block", "203.0.113.7,2001:db8::/32", "--egress-allow-private", "10.0.0.0/8", "--upstream-ca", caPath)
	if code == 0 || !strings.Contains(errs, errStop.Error()) {
		t.Fatalf("tkbox daemon: exit %d, %q", code, errs)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32"), netip.MustParsePrefix("2001:db8::/32")}; !slices.Equal(got.EgressBlock, want) {
		t.Errorf("EgressBlock %v, want %v", got.EgressBlock, want)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}; !slices.Equal(got.EgressAllowPrivate, want) {
		t.Errorf("EgressAllowPrivate %v, want %v", got.EgressAllowPrivate, want)
	}
	if got.EgressUpstreamRoots == nil || got.StateDir != state || got.MaxBoxes != 3 || got.ApprovalTimeout != time.Minute {
		t.Errorf("options %+v", got)
	}
}
