package daemon

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
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

// L1: the first records of a box (created, task) never carry a secret value or placeholder, and env values (the box's
// and a command's) that hold a secret's value are refused, naming the env key but never the value.
func TestReview1NoSecretValuesInFirstRecordsOrEnv(t *testing.T) {
	const val = "s3cret-value-1234"
	secrets := map[string]api.SecretSpec{"TOK": {Value: val, Hosts: []string{"api.example.com"}}}
	e := newTestEnv(t, nil)
	_, err := e.d.Create(context.Background(), api.CreateBoxRequest{Image: "x", Secrets: secrets, Env: map[string]string{"COPY": "Bearer " + val}})
	if errCode(err) != api.CodeBadRequest || !strings.Contains(err.Error(), "env COPY holds the value of secret TOK") || strings.Contains(err.Error(), val) {
		t.Fatalf("box env with a secret value: %v", err)
	}
	e.create(api.CreateBoxRequest{Name: "l1", Secrets: secrets, Env: map[string]string{"PLAIN": "1"},
		Task: "use the token " + val + " to call the API"})
	var ph string
	for _, s := range e.box("l1").secrets {
		ph = s.Placeholder
	}
	sawCreated, sawTask := false, false
	for _, r := range e.run(0).Records {
		if r.Method != "observe" {
			continue
		}
		js, _ := json.Marshal(r.Value)
		if strings.Contains(string(js), val) || strings.Contains(string(js), ph) {
			t.Fatalf("%s record carries a secret: %s", r.Source, js)
		}
		switch r.Source {
		case tracekit.SourceBox:
			sawCreated = sawCreated || strings.Contains(string(js), `"created"`)
		case tracekit.SourceTask:
			sawTask = strings.Contains(string(js), "use the token [secret TOK] to call the API")
		}
	}
	if !sawCreated || !sawTask {
		t.Fatalf("created %v, task scrubbed %v: %v", sawCreated, sawTask, e.run(0).Records)
	}
	_, e2 := e.d.prepareExec("l1", api.ExecRequest{Argv: []string{"env"}, Env: map[string]string{"AUTH": "x" + val + "y"}})
	if e2 == nil || e2.Code != api.CodeBadRequest || !strings.Contains(e2.Message, "env AUTH holds the value of secret TOK") ||
		strings.Contains(e2.Error(), val) {
		t.Fatalf("per-exec env with a secret value: %v", e2)
	}
	if _, e2 := e.d.prepareExec("l1", api.ExecRequest{Argv: []string{"env"}, Env: map[string]string{"AUTH": ph}}); e2 != nil {
		t.Fatalf("per-exec env with the placeholder: %v", e2)
	}
}

// L6: the daemon's extra block prefixes (--egress-block: e.g. a cloud VM's NAT'd public IP, which is on no interface)
// reach every box's proxy alongside the host's own addresses.
func TestReview1EgressBlockReachesEveryBox(t *testing.T) {
	pub := netip.MustParsePrefix("203.0.113.7/32")
	e := newTestEnv(t, func(o *Options) { o.EgressBlock = []netip.Prefix{pub, netip.MustParsePrefix("198.51.100.9/24")} })
	e.create(api.CreateBoxRequest{Name: "b1"})
	e.create(api.CreateBoxRequest{Name: "b2"})
	for i := range 2 {
		bp := e.proxy(i).cfg.BlockPrefixes
		if !slices.Contains(bp, pub) || !slices.Contains(bp, netip.MustParsePrefix("198.51.100.0/24")) {
			t.Fatalf("box %d BlockPrefixes %v", i, bp)
		}
	}
}
