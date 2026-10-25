package tracekit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func systemConfigIs(t *testing.T, cfg map[string]any, err error) {
	t.Helper()
	old := loadSystemConfig
	loadSystemConfig = func() (map[string]any, error) { return cfg, err }
	t.Cleanup(func() { loadSystemConfig = old })
}

func TestDiscoverOrder(t *testing.T) {
	t.Setenv("TRACEKIT_SIGNER", "/run/env.sock")
	systemConfigIs(t, nil, nil)
	if d, err := discoverSigner(Options{}); err != nil || d.path != "/run/env.sock" || d.source != sourceEnv {
		t.Fatalf("%+v %v", d, err)
	}
	if d, err := discoverSigner(Options{Signer: "/run/opt.sock"}); err != nil || d.path != "/run/opt.sock" {
		t.Fatalf("%+v %v", d, err)
	}

	// system mode: its signer, a conflicting env var or option refused, the same one accepted
	systemConfigIs(t, map[string]any{"signer": "/run/sys.sock"}, nil)
	if _, err := discoverSigner(Options{}); err == nil || !strings.Contains(err.Error(), "is not the system signer") {
		t.Fatalf("conflicting TRACEKIT_SIGNER: %v", err)
	}
	if _, err := discoverSigner(Options{Signer: "/run/opt.sock"}); err == nil {
		t.Fatal("conflicting option accepted")
	}
	t.Setenv("TRACEKIT_SIGNER", "/run/sys.sock")
	if d, err := discoverSigner(Options{}); err != nil || d.path != "/run/sys.sock" || d.source != sourceSystem {
		t.Fatalf("%+v %v", d, err)
	}
	t.Setenv("TRACEKIT_SIGNER", "")
	if d, err := discoverSigner(Options{}); err != nil || d.path != "/run/sys.sock" {
		t.Fatalf("%+v %v", d, err)
	}

	// system mode with no signer: never the dev signer
	systemConfigIs(t, map[string]any{"fail_mode": "closed"}, nil)
	if _, err := discoverSigner(Options{}); err == nil || !strings.Contains(err.Error(), "names no signer") {
		t.Fatalf("%v", err)
	}
	// a system config that can't be trusted: refused
	systemConfigIs(t, nil, errors.New("must be owned by root"))
	if _, err := discoverSigner(Options{Signer: "/x"}); err == nil {
		t.Fatal("an untrusted system config was ignored")
	}
	// not a Unix socket
	systemConfigIs(t, nil, nil)
	if _, err := discoverSigner(Options{Signer: "https://signer:8443"}); err == nil {
		t.Fatal("https signer accepted")
	}
}

func TestSystemConfigMustBeRootOwned(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("as root")
	}
	p := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(p, []byte(`{"signer":"/evil.sock"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	old := systemConfigPath
	systemConfigPath = p
	t.Cleanup(func() { systemConfigPath = old })
	if _, err := systemConfig(); err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Fatalf("%v", err)
	}
	systemConfigPath = filepath.Join(t.TempDir(), "none.json")
	if cfg, err := systemConfig(); cfg != nil || err != nil {
		t.Fatalf("%v %v", cfg, err)
	}
}

func TestDevRuntimeDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TRACEKIT_RUNTIME_DIR", "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000/")
	t.Setenv("XDG_DATA_HOME", "")
	d, _ := devRuntimeDir()
	data, _ := devDataDir()
	if runtime.GOOS == "darwin" {
		want := home + "/Library/Application Support/tracekit/run"
		if len(want+"/signer.sock") > 103 {
			want = fmt.Sprintf("/tmp/tk-%d", os.Getuid())
		}
		if d != want || data != home+"/Library/Application Support/tracekit/data" {
			t.Fatalf("%s %s", d, data)
		}
		t.Setenv("HOME", "/Users/"+strings.Repeat("a", 80))
		if d, _ := devRuntimeDir(); d != fmt.Sprintf("/tmp/tk-%d", os.Getuid()) {
			t.Fatalf("long HOME: %s", d)
		}
	} else {
		if d != "/run/user/1000/tracekit" || data != home+"/.local/share/tracekit" {
			t.Fatalf("%s %s", d, data)
		}
		t.Setenv("XDG_RUNTIME_DIR", "")
		t.Setenv("XDG_DATA_HOME", "/xdg/data")
		d, _ := devRuntimeDir()
		data, _ := devDataDir()
		if d != fmt.Sprintf("/tmp/tracekit-%d", os.Getuid()) || data != "/xdg/data/tracekit" {
			t.Fatalf("%s %s", d, data)
		}
	}
	t.Setenv("TRACEKIT_RUNTIME_DIR", "/custom")
	if d, _ := devRuntimeDir(); d != "/custom" {
		t.Fatal(d)
	}
}

func TestDevSignerDir(t *testing.T) {
	systemConfigIs(t, nil, nil)
	t.Setenv("TRACEKIT_SIGNER", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	rt := shortTempDir(t)
	t.Setenv("TRACEKIT_RUNTIME_DIR", rt)
	if err := os.Chmod(rt, 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := discoverSigner(Options{})
	data, _ := devDataDir()
	sum := sha256.Sum256([]byte(realPath(data)))
	side := rt + "-" + hex.EncodeToString(sum[:])[:12]
	if err != nil || d.path != rt+"/signer.sock" || d.source != sourceDev || d.alt != side+"/signer.sock" {
		t.Fatalf("%+v %v", d, err)
	}
	// while this data dir's signer holds the sibling's lock, the sibling
	if err := os.Mkdir(side, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(side) })
	lock, err := os.Create(side + "/signer.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if d, err := discoverSigner(Options{}); err != nil || d.path != side+"/signer.sock" {
		t.Fatalf("%+v %v", d, err)
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if lockHeld(side + "/signer.lock") {
		t.Fatal("lock still held")
	}
	// a runtime dir others can read is refused
	if err := os.Chmod(rt, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := discoverSigner(Options{}); err == nil || !strings.Contains(err.Error(), "mode 0700") {
		t.Fatalf("%v", err)
	}
}

func TestDialDevSignerOfAnotherHome(t *testing.T) {
	// the runtime dir's signer serves another data dir: Dial goes to this HOME's, in the sibling dir
	systemConfigIs(t, nil, nil)
	t.Setenv("TRACEKIT_SIGNER", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", "")
	rt := shortTempDir(t)
	_ = os.Chmod(rt, 0o700)
	t.Setenv("TRACEKIT_RUNTIME_DIR", rt)
	data, _ := devDataDir()
	sum := sha256.Sum256([]byte(realPath(data)))
	side := rt + "-" + hex.EncodeToString(sum[:])[:12]
	if err := os.Mkdir(side, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(side) })
	theirs := newFakeSignerAt(t, rt+"/signer.sock")
	theirs.hello["data_dir"] = "/home/someone-else/.local/share/tracekit"
	ours := newFakeSignerAt(t, side+"/signer.sock")
	ours.hello["data_dir"] = data
	c, err := Dial(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Where() != side+"/signer.sock" || len(theirs.all()) != 0 {
		t.Fatalf("where %s", c.Where())
	}
}

func TestRealPath(t *testing.T) {
	d := t.TempDir()
	r, _ := filepath.EvalSymlinks(d)
	if got := realPath(d + "/missing/child"); got != r+"/missing/child" {
		t.Fatalf("%s", got)
	}
}
