package egress

import (
	"encoding/base64"
	"io"
	"net/url"
	"strings"
	"testing"
)

// review-1 L3 follow-up (#5): a bound host that echoes a Basic credential inside JSON that escapes "/" (PHP), or
// percent-encoded in a URL (a query escapes "+" and "/", Python's quote() only "+", a path segment only "/"), must not
// hand the value to the guest.
func TestEscapedBase64EchoRedacted(t *testing.T) {
	v := "ghp_ab?cd?ef?gh?ij>kl>mn" // its base64 after "x:" holds both "/" and "+"
	s := mkSecret(t, "GH", "", "api.example.com")
	s.Value = v
	r, err := newSecretRule(s)
	if err != nil {
		t.Fatal(err)
	}
	m := newMatcher((&Proxy{secrets: []*secretRule{r}}).valuePatterns())
	b := base64.StdEncoding.EncodeToString([]byte("x:" + v))
	if !strings.Contains(b, "/") || !strings.Contains(b, "+") {
		t.Fatalf("test value's base64 %q lacks / or +", b)
	}
	for name, in := range map[string]string{"json-escaped": strings.ReplaceAll(b, "/", `\/`), "percent": url.QueryEscape(b),
		"plus only": strings.ReplaceAll(b, "+", "%2B"), "slash only": strings.ReplaceAll(b, "/", "%2F")} {
		out, _ := io.ReadAll(newRedactReader(m, strings.NewReader(in)))
		if string(out) == in {
			t.Errorf("%s base64 %q reached the guest unredacted", name, in)
		}
	}
}

// #5, as the docs say: a value of 6 bytes or more that is ordinary text is redacted wherever that text appears, in any
// case; a shorter value has no forms at all, so it is neither redacted nor blocked.
func TestWeakValueRedactedInAnyCase(t *testing.T) {
	for _, c := range []struct{ value, text, want string }{
		{"Secret", "SECRETARY", "[****]ARY"},
		{"Short", "Short", "Short"},
	} {
		s := mkSecret(t, "S", "", "api.example.com")
		s.Value = c.value
		r, err := newSecretRule(s)
		if err != nil {
			t.Fatal(err)
		}
		m := newMatcher((&Proxy{secrets: []*secretRule{r}}).valuePatterns())
		if out, _ := io.ReadAll(newRedactReader(m, strings.NewReader(c.text))); string(out) != c.want {
			t.Errorf("value %q: %q redacts to %q, want %q", c.value, c.text, out, c.want)
		}
	}
}
