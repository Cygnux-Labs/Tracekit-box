package main

import (
	"net/netip"
	"strings"
	"testing"
)

// L6: --egress-block takes CIDRs and bare addresses (repeatable, comma-separated) and refuses anything else before the
// daemon starts.
func TestReview1EgressBlockFlag(t *testing.T) {
	got, err := parseEgressBlock([]string{"203.0.113.7", "198.51.100.0/24", "2001:db8::1", "10.1.2.3/8"})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8::1/128"), netip.MustParsePrefix("10.0.0.0/8")}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	code, _, errs := run(t, "", "daemon", "--state-dir", t.TempDir(), "--egress-block", "203.0.113.7,not-a-cidr")
	if code == 0 || !strings.Contains(errs, `--egress-block "not-a-cidr"`) {
		t.Fatalf("bad --egress-block: exit %d, %q", code, errs)
	}
}
