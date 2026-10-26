package daemon

import (
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
)

// verify4: a "[secret NAME]" tag (or the decision's tkbox_NAME_… mark for a placeholder) never rebuilds a value
// with the text around it, nor holds one: value "]abcdefg" before its own tail, "secret S]" inside the tag,
// "[secret S]" itself, "]tail12" after a placeholder's tag, and "T_…tail" after another secret's mark. That holds for
// the scrubber (events, observes, approvals) and for what an exec's decision shows.
func TestVerify4SecretTagNeverRebuildsValue(t *testing.T) {
	phS, err := egress.NewPlaceholder("S")
	if err != nil {
		t.Fatal(err)
	}
	phT, err := egress.NewPlaceholder("T")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ value, text string }{
		{"]abcdefg", "]abcdefgabcdefg"},
		{"]ab*cd", "]ab*cdab*cd"}, // filled with another byte than "*"
		{"secret S]", "secret S]"},
		{"[secret S]", "x[secret S]y"},
		{"]tail12", phS + "tail12"},
		{"T_…tail", phT + "tail"},
		{"ordinary-value", "echo ordinary-value"},
	} {
		secrets := []egress.Secret{{Name: "S", Placeholder: phS, Value: c.value}, {Name: "T", Placeholder: phT, Value: "t-value-0123456789"}}
		b := &box{secrets: secrets}
		for what, out := range map[string]string{"scrubber": newScrubber(secrets).str(c.text), "decision": b.redactor()(c.text)} {
			if strings.Contains(out, c.value) || strings.Contains(out, phS) || strings.Contains(out, phT) {
				t.Errorf("value %q, %s: %q comes out as %q", c.value, what, c.text, out)
			}
		}
	}
}
