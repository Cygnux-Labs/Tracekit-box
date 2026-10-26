package egress

import (
	"encoding/base64"
	"io"
	"net/url"
	"strings"
	"testing"
)

// review-1 L3 follow-up: a bound host that echoes a Basic credential inside JSON that escapes "/" (PHP), or in a
// URL query (base64 percent-encoded), must not hand the value to the guest.
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
	if !strings.ContainsAny(b, "/+") {
		t.Fatalf("test value's base64 %q has neither / nor +", b)
	}
	for name, in := range map[string]string{"json-escaped": strings.ReplaceAll(b, "/", `\/`), "percent": url.QueryEscape(b)} {
		out, _ := io.ReadAll(newRedactReader(m, strings.NewReader(in)))
		if string(out) == in {
			t.Errorf("%s base64 %q reached the guest unredacted", name, in)
		}
	}
}
