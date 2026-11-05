package agentchannel

import "testing"

// An observe source Box reserves (tkbox.*) used to be matched as a case-sensitive ASCII prefix, so a lookalike passed:
// another case, a leading space, a one-dot leader or fullwidth dot, a zero-width prefix.
func TestReservedObserveSourceLookalikes(t *testing.T) {
	for _, src := range []string{"TKBOX.egress", "Tkbox.exec", " tkbox.egress", "tkbox․egress", "tkbox．egress", "​tkbox.egress"} {
		if _, err := Decode([]byte(`{"method":"observe","run_id":"r","source":"` + src + `","trust":"trusted","value":{}}`)); err == nil {
			t.Errorf("observe source %q passes", src)
		}
	}
}
