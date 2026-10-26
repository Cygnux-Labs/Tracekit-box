//go:build e2e

// Package e2e boots real boxes: it needs Linux with /dev/kvm, e2fsprogs, git, internet access, a running Tracekit
// 1.4.2 dev signer (`tracekit up`) and the binaries from `make build` in $TKBOX_BIN. Run it with `make e2e`.
package e2e

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const secretValue = "s3cr3t-e2e-token-value"

type env struct {
	bin      string
	state    string
	sock     string
	work     string
	upstream *httptest.Server
	port     string
}

func setup(t *testing.T) *env {
	t.Helper()
	bin := os.Getenv("TKBOX_BIN")
	if bin == "" {
		t.Skip("TKBOX_BIN not set (run make e2e)")
	}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		t.Skipf("no usable /dev/kvm: %v", err)
	} else {
		f.Close()
	}
	e := &env{bin: bin, state: t.TempDir()}
	e.sock = filepath.Join(e.state, "run", "tkbox.sock")

	// a stand-in for api.github.com: answers 200 only when the real secret arrives in Authorization
	e.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+secretValue {
			fmt.Fprint(w, "auth-ok")
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "auth-bad")
	}))
	t.Cleanup(e.upstream.Close)
	e.port = strings.TrimPrefix(e.upstream.URL, "https://127.0.0.1:")
	caFile := filepath.Join(e.state, "upstream-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.upstream.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// the checkout the box works on: a git repo with a tracked file and an ignored secret that must stay out
	e.work = t.TempDir()
	run(t, e.work, "git", "init", "-q")
	os.WriteFile(filepath.Join(e.work, "README.md"), []byte("hello\n"), 0o644)
	os.WriteFile(filepath.Join(e.work, ".gitignore"), []byte(".env\n"), 0o644)
	os.WriteFile(filepath.Join(e.work, ".env"), []byte("LEAK=1\n"), 0o600)
	run(t, e.work, "git", "add", ".")
	run(t, e.work, "git", "-c", "user.email=e2e@example.com", "-c", "user.name=e2e", "commit", "-q", "-m", "init")

	ctx, cancel := context.WithCancel(context.Background())
	d := exec.CommandContext(ctx, filepath.Join(bin, "tkbox"), "daemon", "--state-dir", e.state,
		"--approval-timeout", "5s", "--egress-allow-private", "127.0.0.1/32", "--upstream-ca", caFile)
	d.Stdout, d.Stderr = os.Stderr, os.Stderr
	d.Cancel = func() error { return d.Process.Signal(os.Interrupt) }
	d.WaitDelay = 30 * time.Second
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); d.Wait() })
	for i := 0; ; i++ {
		if _, _, code := e.tk(t, "ls"); code == 0 {
			break
		}
		if i > 600 { // assets download on first run
			t.Fatal("daemon did not come up")
		}
		time.Sleep(200 * time.Millisecond)
	}
	return e
}

func run(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	c := exec.Command(name, args...)
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func (e *env) tk(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	c := exec.Command(filepath.Join(e.bin, "tkbox"), args...)
	c.Env = append(os.Environ(), "TKBOX_SOCKET="+e.sock, "TK_SECRET="+secretValue)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("tkbox %v: %v", args, err)
	}
	t.Logf("tkbox %s → %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out.String(), errb.String())
	return out.String(), errb.String(), code
}

func (e *env) exec(t *testing.T, box string, argv ...string) (string, string, int) {
	return e.tk(t, append([]string{"exec", box, "--"}, argv...)...)
}

const py = "python3"

// countSleepsPy prints how many `sleep 302` processes run in the box (slim images have no ps or pgrep).
const countSleepsPy = `import os
n = 0
for p in os.listdir("/proc"):
    if p.isdigit():
        try:
            n += open("/proc/" + p + "/cmdline", "rb").read().split(b"\0")[:2] == [b"sleep", b"302"]
        except OSError:
            pass
print(n)`

func TestBox(t *testing.T) {
	e := setup(t)
	host := "127.0.0.1:" + e.port
	_, _, code := e.tk(t, "run", "--image", "python:3.12-slim", "--allow", "pypi", "--allow", host,
		"--workspace", e.work, "--name", "e2e", "--timeout", "20m",
		"--secret", "TK=env:TK_SECRET@127.0.0.1#Authorization")
	if code != 0 {
		t.Fatalf("run failed: %d", code)
	}
	t.Cleanup(func() { e.tk(t, "rm", "e2e") })

	t.Run("exec", func(t *testing.T) {
		out, _, code := e.exec(t, "e2e", py, "-c", "print(1+1)")
		if code != 0 || strings.TrimSpace(out) != "2" {
			t.Fatalf("got %q %d", out, code)
		}
		if _, _, code := e.exec(t, "e2e", "sh", "-c", "exit 7"); code != 7 {
			t.Fatalf("exit code %d, want 7", code)
		}
	})

	// a command that never reads its 2 MB of stdin still gets Ctrl-C, and dies when the client is killed (both used
	// to leave it running until the exec timeout)
	countSleeps := func(t *testing.T) string {
		out, _, _ := e.exec(t, "e2e", py, "-c", countSleepsPy)
		return strings.TrimSpace(out)
	}
	for _, how := range []string{"interrupt", "kill"} {
		t.Run("unread-stdin-"+how, func(t *testing.T) {
			c := exec.Command(filepath.Join(e.bin, "tkbox"), "exec", "-i", "e2e", "--", "sleep", "302")
			c.Env = append(os.Environ(), "TKBOX_SOCKET="+e.sock)
			c.Stdin = bytes.NewReader(make([]byte, 2_000_000))
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- c.Wait() }()
			defer c.Process.Kill()
			for i := 0; countSleeps(t) != "1"; i++ {
				if i > 60 {
					t.Fatal("sleep 302 did not start")
				}
				time.Sleep(500 * time.Millisecond)
			}
			time.Sleep(time.Second) // stdin backs up behind the child
			start := time.Now()
			if how == "interrupt" {
				c.Process.Signal(os.Interrupt)
			} else {
				c.Process.Kill()
			}
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("the client did not exit")
			}
			for countSleeps(t) != "0" {
				if time.Since(start) > 20*time.Second {
					t.Fatalf("sleep 302 still runs %s after the client's %s", time.Since(start).Round(time.Second), how)
				}
				time.Sleep(500 * time.Millisecond)
			}
			t.Logf("sleep 302 gone within %s of the %s", time.Since(start).Round(100*time.Millisecond), how)
		})
	}

	t.Run("signer-deny", func(t *testing.T) {
		if _, stderr, code := e.exec(t, "e2e", "pkill", "tracekitd"); code != 126 || !strings.Contains(stderr, "TK-D007") {
			t.Fatalf("pkill tracekitd: code %d", code)
		}
	})

	t.Run("workspace-excludes-ignored", func(t *testing.T) {
		out, _, _ := e.exec(t, "e2e", "ls", "-a", "/workspace")
		if !strings.Contains(out, "README.md") || strings.Contains(out, ".env") || strings.Contains(out, ".git\n") {
			t.Fatalf("workspace listing: %q", out)
		}
	})

	t.Run("no-network-card", func(t *testing.T) {
		out, _, _ := e.exec(t, "e2e", "cat", "/proc/net/dev")
		for _, l := range strings.Split(out, "\n")[2:] {
			if f := strings.Fields(l); len(f) > 0 && f[0] != "lo:" {
				t.Fatalf("unexpected interface %q", f[0])
			}
		}
	})

	fetch := func(url, header string) []string {
		return []string{py, "-c", fmt.Sprintf(`import os,urllib.request as u
r=u.Request(%q)
h=%q
if h: r.add_header(h, "Bearer "+os.environ["TK"])
try:
    print(u.urlopen(r, timeout=60).read().decode())
except Exception as e:
    print("ERR", e); raise SystemExit(3)`, url, header)}
	}

	t.Run("egress-unlisted-blocked", func(t *testing.T) {
		out, stderr, code := e.exec(t, "e2e", fetch("https://example.com/", "")...)
		if code == 0 || !strings.Contains(stderr, "tkbox approve") {
			t.Fatalf("example.com: %q %d", out, code)
		}
	})

	t.Run("egress-preset-allowed", func(t *testing.T) {
		if _, _, code := e.exec(t, "e2e", "pip", "install", "-q", "--disable-pip-version-check", "requests"); code != 0 {
			t.Fatalf("pip install: %d", code)
		}
	})

	t.Run("egress-metadata-refused", func(t *testing.T) {
		out, _, code := e.exec(t, "e2e", fetch("http://169.254.169.254/latest/meta-data/", "")...)
		if code == 0 {
			t.Fatalf("metadata reachable: %q", out)
		}
	})

	t.Run("secret-swap", func(t *testing.T) {
		out, _, code := e.exec(t, "e2e", fetch("https://"+host+"/user", "Authorization")...)
		if code != 0 || strings.TrimSpace(out) != "auth-ok" {
			t.Fatalf("swap: %q %d", out, code)
		}
		out, _, _ = e.exec(t, "e2e", "sh", "-c", "echo $TK")
		if strings.Contains(out, secretValue) || !strings.HasPrefix(strings.TrimSpace(out), "tkbox_TK_") {
			t.Fatalf("the VM sees %q", out)
		}
	})

	t.Run("secret-leak-blocked", func(t *testing.T) {
		out, stderr, code := e.exec(t, "e2e", fetch("https://"+host+"/user", "X-Smuggle")...)
		if code == 0 || strings.Contains(out, "auth") {
			t.Fatalf("leak: %q %d", out, code)
		}
		_ = stderr
	})

	t.Run("diff-and-apply", func(t *testing.T) {
		if _, _, code := e.exec(t, "e2e", "sh", "-c", "echo hi > /workspace/x.txt && echo more >> /workspace/README.md"); code != 0 {
			t.Fatal("write failed")
		}
		out, _, code := e.tk(t, "diff", "e2e")
		if code != 0 || !strings.Contains(out, "x.txt") || !strings.Contains(out, "+more") {
			t.Fatalf("diff: %q", out)
		}
	})

	t.Run("stop-export-verify", func(t *testing.T) {
		if _, _, code := e.tk(t, "stop", "e2e"); code != 0 {
			t.Fatal("stop failed")
		}
		if _, _, code := e.tk(t, "apply", "e2e"); code != 0 {
			t.Fatal("apply failed")
		}
		if b, err := os.ReadFile(filepath.Join(e.work, "x.txt")); err != nil || string(b) != "hi\n" {
			t.Fatalf("x.txt after apply: %q %v", b, err)
		}
		bundle := filepath.Join(t.TempDir(), "e2e.tkb")
		if _, _, code := e.tk(t, "export", "e2e", "-o", bundle); code != 0 {
			t.Fatal("export failed")
		}
		trust := strings.TrimSuffix(bundle, ".tkb") + ".trust.json"
		out, err := exec.Command("tracekit", "verify", bundle, "--trust", trust).CombinedOutput()
		t.Logf("verify: %s", out)
		if err != nil || !strings.Contains(string(out), "VERIFIED") || strings.Contains(string(out), "(open)") {
			t.Fatalf("verify: %v", err)
		}
	})
}

// TestFailClosed: without a signer the daemon refuses to start.
func TestFailClosed(t *testing.T) {
	bin := os.Getenv("TKBOX_BIN")
	if bin == "" {
		t.Skip("TKBOX_BIN not set")
	}
	state := t.TempDir()
	c := exec.Command(filepath.Join(bin, "tkbox"), "daemon", "--state-dir", state,
		"--signer", filepath.Join(t.TempDir(), "nothing.sock"))
	out, err := c.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "tracekit up") {
		t.Fatalf("daemon started without a signer: %v\n%s", err, out)
	}
	// it refuses before downloading anything: no signer must not wait on (or be masked by) the network
	if _, err := os.Stat(filepath.Join(state, "images", "assets")); !os.IsNotExist(err) {
		t.Fatalf("the daemon fetched assets before checking the signer (%v)", err)
	}
}
