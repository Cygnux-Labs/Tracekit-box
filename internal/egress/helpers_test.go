package egress

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
)

type nopDecider struct{}

func (nopDecider) Decide(context.Context, Request) (Verdict, error) { return Verdict{}, nil }

type nopSink struct{}

func (nopSink) Emit(Event) {}

func parseIP(s string) net.IP {
	if a, err := netip.ParseAddr(s); err == nil {
		return net.IP(a.AsSlice())
	}
	return nil
}

func mkSecret(t *testing.T, name, header string, hosts ...string) Secret {
	t.Helper()
	ph, err := NewPlaceholder(name)
	if err != nil {
		t.Fatal(err)
	}
	return Secret{Name: name, Placeholder: ph, Value: "real-" + strings.ToLower(name) + "-value-0123456789", Hosts: hosts, Header: header}
}

func TestNewValidates(t *testing.T) {
	ca, _ := NewCA("b")
	gh := mkSecret(t, "GH", "Authorization", "api.github.com")
	cases := map[string]Config{
		"no decider":     {Sink: nopSink{}},
		"no sink":        {Decider: nopDecider{}},
		"no CA":          {Decider: nopDecider{}, Sink: nopSink{}, Secrets: []Secret{gh}},
		"no CA all":      {Decider: nopDecider{}, Sink: nopSink{}, Inspect: InspectAll},
		"bad inspect":    {Decider: nopDecider{}, Sink: nopSink{}, Inspect: "some"},
		"no hosts":       {Decider: nopDecider{}, Sink: nopSink{}, CA: ca, Secrets: []Secret{{Name: "GH", Placeholder: gh.Placeholder, Value: "v"}}},
		"crlf value":     {Decider: nopDecider{}, Sink: nopSink{}, CA: ca, Secrets: []Secret{{Name: "GH", Placeholder: gh.Placeholder, Value: "v\r\nX: y", Hosts: []string{"a.com"}}}},
		"bad allow":      {Decider: nopDecider{}, Sink: nopSink{}, Allow: []string{"http://x"}},
		"bad header":     {Decider: nopDecider{}, Sink: nopSink{}, CA: ca, Secrets: []Secret{{Name: "GH", Placeholder: gh.Placeholder, Value: "v", Hosts: []string{"a.com"}, Header: "Proxy-Authorization"}}},
		"bad ph":         {Decider: nopDecider{}, Sink: nopSink{}, CA: ca, Secrets: []Secret{{Name: "GH", Placeholder: "x", Value: "v", Hosts: []string{"a.com"}}}},
		"dup secret":     {Decider: nopDecider{}, Sink: nopSink{}, CA: ca, Secrets: []Secret{gh, gh}},
		"host with port": {Decider: nopDecider{}, Sink: nopSink{}, CA: ca, Secrets: []Secret{{Name: "GH", Placeholder: gh.Placeholder, Value: "v", Hosts: []string{"a.com:443"}}}},
		"neg timeout":    {Decider: nopDecider{}, Sink: nopSink{}, IdleTimeout: -1},
		"zero CA":        {Decider: nopDecider{}, Sink: nopSink{}, CA: &CA{}, Secrets: []Secret{gh}},
	}
	for name, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	p, err := New(Config{Decider: nopDecider{}, Sink: nopSink{}, CA: ca, Secrets: []Secret{gh}, Allow: []string{"github.com", "*.x.com:8443"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.cfg.MaxConns != DefaultMaxConns || p.cfg.DecideTimeout != DefaultDecideTimeout || p.cfg.Inspect != InspectBound {
		t.Error("defaults not applied")
	}
	p.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Serve(l); err == nil {
		t.Error("Serve after Close succeeded")
	}
}

func TestRedactAndFind(t *testing.T) {
	gh := mkSecret(t, "GH", "", "a.com")
	r, err := newSecretRule(gh)
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{secrets: []*secretRule{r}}
	in := "x" + strings.ToUpper(gh.Placeholder) + ".evil.com/" + gh.Placeholder
	if out := p.redact(in); strings.Contains(strings.ToLower(out), "tkbox_") || out != "x[secret GH].evil.com/[secret GH]" {
		t.Errorf("redact = %q", out)
	}
	if f := p.findTarget("/a%5F" + strings.TrimPrefix(gh.Placeholder, "tkbox_")); f != nil {
		t.Error("found a placeholder that is not there")
	}
	if f := p.findTarget("/" + strings.Replace(gh.Placeholder, "_", "%5F", 1)); len(f) != 1 {
		t.Error("percent-encoded placeholder not found")
	}
}
