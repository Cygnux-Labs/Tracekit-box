package daemon

import (
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
)

// R1 (verify5, L1): a secret value never reaches the decided command line. It joins argv with spaces, so a value
// with a space split over bare words (`echo correct horse battery`) is in it; and it names each per-exec env
// variable, so a value used as an env name (`env AKIA…=1 ls`) is too.
func TestVerify5SecretValueInDecidedCommandRefused(t *testing.T) {
	e := newTestEnv(t, nil)
	e.create(api.CreateBoxRequest{Name: "r1", Secrets: map[string]api.SecretSpec{
		"PW": {Value: "correct horse battery", Hosts: []string{"api.example.com"}},
		"K":  {Value: "AKIAPROBEVALUE1234", Hosts: []string{"api.example.com"}},
	}})
	for _, c := range []struct {
		req    api.ExecRequest
		secret string
	}{
		{api.ExecRequest{Argv: []string{"echo", "correct", "horse", "battery"}}, "PW"},
		{api.ExecRequest{Argv: []string{"ls"}, Env: map[string]string{"AKIAPROBEVALUE1234": "1"}}, "K"},
	} {
		_, e2 := e.d.prepareExec("r1", c.req)
		if e2 == nil || e2.Code != api.CodeBadRequest || !strings.Contains(e2.Message, "holds the value of secret "+c.secret) {
			t.Errorf("%+v: %v", c.req, e2)
		}
	}
	// the words on their own, and a value-free env, still run
	if _, e2 := e.d.prepareExec("r1", api.ExecRequest{Argv: []string{"echo", "correct", "horse"}, Env: map[string]string{"AKIA": "1"}}); e2 != nil {
		t.Fatalf("an exec without a value: %v", e2)
	}
}
