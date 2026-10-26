package egress

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
	"time"
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

// Events and refusals are redacted of every value form in any case, and a value that its own marker contains
// ("secret" in "[secret SECRET]") is replaced once, not forever.
func TestRedactFoldsEveryForm(t *testing.T) {
	gh := mkSecret(t, "GH", "", "a.com")
	gh.Value = "Secret/Value+0123"
	sec := mkSecret(t, "SECRET", "", "b.com")
	sec.Value = "secret"
	var rules []*secretRule
	for _, s := range []Secret{gh, sec} {
		r, err := newSecretRule(s)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, r)
	}
	p := &Proxy{secrets: rules[:1]}
	in := "a " + strings.ToUpper(gh.Value) + " b " + strings.ToUpper(hex.EncodeToString([]byte(gh.Value))) +
		" c " + hex.EncodeToString([]byte(gh.Value)) + " d " + strings.ToLower(url.QueryEscape(gh.Value))
	if out, want := p.redact(in), "a [secret GH] b [secret GH] c [secret GH] d [secret GH]"; out != want {
		t.Errorf("redact = %q, want %q", out, want)
	}
	p = &Proxy{secrets: rules[1:]}
	done := make(chan string, 1)
	go func() { done <- p.redact("SECRET and secret") }()
	select {
	case out := <-done:
		if want := "[secret SECRET] and [secret SECRET]"; out != want {
			t.Errorf("redact = %q, want %q", out, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("redact did not return: it keeps matching the value inside its own marker")
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

// A marker never rebuilds a value with the bytes around it, and is never the value itself: value "a*****" in
// "aa*****", "******" alone, "]abc…" before its own tail. That holds in bodies however they are split, and in
// headers, where a case-changed echo gets a marker.
func TestMarkerNeverRebuildsValue(t *testing.T) {
	for _, c := range []struct{ value, text string }{
		{"a*****", "aa*****"},
		{"******", "******"},
		{"[redacted]", "x[redacted]y"},
		{"]abcdefghijklmnop", "]abcdefghijklmnopabcdefghijklmnop"},
		{"tkbox: redacted*", "[tkbox: redacted**]"},
		{"ghp_ordinaryValue0123", "echo ghp_ordinaryValue0123 and GHP_ORDINARYVALUE0123"},
	} {
		s := mkSecret(t, "S", "", "a.example.com")
		s.Value = c.value
		r, err := newSecretRule(s)
		if err != nil {
			t.Fatal(err)
		}
		p := &Proxy{secrets: []*secretRule{r}}
		p.valMatch = newMatcher(p.valuePatterns())
		for name, src := range map[string]io.Reader{"whole": strings.NewReader(c.text), "bytewise": iotest.OneByteReader(strings.NewReader(c.text))} {
			out, err := io.ReadAll(newRedactReader(p.valMatch, src))
			if err != nil || len(out) != len(c.text) || p.valMatch.findString(string(out)) != nil {
				t.Errorf("value %q, %s body %q: redacted to %q (%v)", c.value, name, c.text, out, err)
			}
		}
		for _, v := range []string{c.text, strings.ToUpper(c.text)} {
			h := http.Header{"X-Echo": {v}}
			p.redactValues(h)
			if got := h.Get("X-Echo"); p.valMatch.findString(got) != nil {
				t.Errorf("value %q, header %q: redacted to %q", c.value, v, got)
			}
		}
	}
	// A value that shares nothing with the marker text keeps the readable marker.
	s := mkSecret(t, "S", "", "a.example.com")
	r, _ := newSecretRule(s)
	m := newMatcher((&Proxy{secrets: []*secretRule{r}}).valuePatterns())
	if out, _ := io.ReadAll(newRedactReader(m, strings.NewReader(s.Value))); !strings.HasPrefix(string(out), "[tkbox: redacted") {
		t.Errorf("an ordinary value redacts to %q", out)
	}
}
