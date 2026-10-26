package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
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

// R4 (verify5, docs): the checkout's own .gitattributes reaches the scratch apply only when the patch changes it (it
// is then copied in with the other files it touches; changing it needs --allow-sensitive), and then its conversions
// apply: eol=crlf writes "new\r\n". The signer decides the converted bytes, so the record names what lands. A patch
// that leaves .gitattributes alone gets no conversion.
func TestVerify5RepoAttributesOnlyWhenThePatchChangesThem(t *testing.T) {
	needGit(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	attrs := "diff --git a/.gitattributes b/.gitattributes\nindex 1111111..2222222 100644\n--- a/.gitattributes\n" +
		"+++ b/.gitattributes\n@@ -1 +1,2 @@\n a.txt text eol=crlf\n+b.txt text eol=crlf\n"
	for _, c := range []struct{ name, patch, want string }{
		{"attrs", attrs + modify("a.txt"), "new\r\n"},
		{"plain", modify("a.txt"), "new\n"},
	} {
		e := newTestEnv(t, nil)
		ws, _ := filepath.EvalSymlinks(t.TempDir())
		gitInit(t, ws)
		os.WriteFile(filepath.Join(ws, ".gitattributes"), []byte("a.txt text eol=crlf\n"), 0o644)
		os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
		e.guest.Patch = c.patch
		e.create(api.CreateBoxRequest{Name: c.name, Workspace: ws})
		e.d.Stop(context.Background(), c.name, api.StopRequest{})
		if res, err := e.d.Apply(context.Background(), c.name, api.ApplyRequest{AllowSensitive: true}); err != nil {
			t.Fatalf("%s: apply %+v %v", c.name, res, err)
		}
		if got := readFile(t, filepath.Join(ws, "a.txt")); got != c.want {
			t.Errorf("%s: a.txt written as %q, want %q", c.name, got, c.want)
		}
		sum := sha256.Sum256([]byte(c.want))
		decided := false
		for _, r := range e.run(0).Records {
			if r.Method == "decide" && r.Call.Tool == tracekit.ToolWrite && r.Call.Args["file_path"] == filepath.Join(ws, "a.txt") {
				decided = r.Call.Args["sha256"] == hex.EncodeToString(sum[:])
			}
		}
		if !decided {
			t.Errorf("%s: the signer did not decide a.txt as the bytes written", c.name)
		}
	}
}
