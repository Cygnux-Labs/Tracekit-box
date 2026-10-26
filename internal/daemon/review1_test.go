package daemon

import (
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
)

// L10: a per-exec env may not set anything that changes which program runs or what it loads.
func TestReview1ExecEnvDenyList(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "env"})
	for _, k := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "BASH_ENV", "ENV", "PROMPT_COMMAND",
		"PATH", "NODE_OPTIONS", "PYTHONPATH", "PERL5OPT", "RUBYOPT", "JAVA_TOOL_OPTIONS", "GCONV_PATH",
		"GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_GLOBAL",
		"GIT_CONFIG_SYSTEM", "GIT_CONFIG_PARAMETERS"} {
		_, e2 := e.d.prepareExec("env", api.ExecRequest{Argv: []string{"ls"}, Env: map[string]string{k: "/x"}})
		if e2 == nil || e2.Code != api.CodeBadRequest || !strings.Contains(e2.Message, k) {
			t.Errorf("per-exec env %s: %v", k, e2)
		}
	}
	for _, k := range []string{"HOME", "LANG", "GIT_AUTHOR_NAME", "MY_PATH", "NODE_ENV"} {
		if _, e2 := e.d.prepareExec("env", api.ExecRequest{Argv: []string{"ls"}, Env: map[string]string{k: "x"}}); e2 != nil {
			t.Errorf("per-exec env %s refused: %v", k, e2)
		}
	}
}

// L2 (daemon part): inspect all with no allow entries and no secrets gives a CA that may impersonate nothing, never an
// unconstrained one (egress.CAOptions reads nil hosts as unconstrained).
func TestReview1CAHostsNeverUnconstrained(t *testing.T) {
	hosts := caHosts(nil, []string{}, egress.InspectAll)
	if hosts == nil || len(hosts) != 0 {
		t.Fatalf("caHosts = %#v, want an empty non-nil list", hosts)
	}
	ca, err := egress.NewCAWith("tkb-test", egress.CAOptions{Hosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"evil.example", "8.8.8.8", "api.github.com"} {
		if ca.Permits(h) {
			t.Errorf("the CA of a box with nothing to inspect may impersonate %s", h)
		}
	}
	// what it may impersonate is still exactly the bound and (inspect all) allowed hosts
	got := caHosts([]egress.Secret{{Name: "T", Hosts: []string{"api.example.com"}}}, []string{"pypi.org", "h.example:8443"}, egress.InspectAll)
	if strings.Join(got, ",") != "api.example.com,pypi.org,h.example" {
		t.Fatalf("caHosts = %v", got)
	}
}
