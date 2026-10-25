package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const good = `
name: demo
task: fix the tests
image: python:3.12-slim
allow: [pypi, api.example.com:8443]
secrets:
  GITHUB_TOKEN:
    from_env: GH_TOKEN
    hosts: [api.github.com, "*.githubusercontent.com"]
    header: Authorization
  KEY:
    from_file: key.txt
    hosts: [api.anthropic.com]
env:
  FOO: bar
limits:
  cpus: 4
  memory: 2GiB
  disk: 512MiB
  timeout: 1h
  exec_timeout: 90s
workspace: .
inspect: all
`

func TestParseGood(t *testing.T) {
	f, err := Parse([]byte(good), "tkbox.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if f.Image != "python:3.12-slim" || f.Limits.CPUs != 4 || f.Limits.Memory != 2048 || f.Limits.Disk != 512 ||
		time.Duration(f.Limits.Timeout) != time.Hour || time.Duration(f.Limits.ExecTimeout) != 90*time.Second {
		t.Fatalf("parsed %+v", f)
	}
	if f.Name != "demo" || f.Task != "fix the tests" {
		t.Fatalf("name/task %q %q", f.Name, f.Task)
	}
	g, err := Parse([]byte("image: x\nlimits:\n  memory: 1024\n  disk: 64\n"), "tkbox.yaml")
	if err != nil || g.Limits.Memory != 1024 || g.Limits.Disk != 64 {
		t.Fatalf("integer MiB: %+v %v", g, err)
	}
	if s := f.Secrets["GITHUB_TOKEN"]; s.FromEnv != "GH_TOKEN" || len(s.Hosts) != 2 || s.Header != "Authorization" {
		t.Fatalf("secret %+v", s)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"unknown key":        {"image: x\nimagee: y\n", "line 2: unknown key imagee"},
		"unknown limit key":  {"image: x\nlimits:\n  cpu: 2\n", "line 3: unknown key cpu"},
		"unknown secret key": {"secrets:\n  A:\n    from_env: B\n    hosts: [h]\n    value: s3cret\n", "line 5: unknown key value"},
		"duplicate key":      {"image: x\nimage: y\n", "already defined"},
		"bad memory":         {"limits:\n  memory: -2\n", "line 2"},
		"bad memory unit":    {"limits:\n  memory: 2Gb\n", "unknown or missing unit"},
		"memory range":       {"limits:\n  memory: 64MiB\n", "limits.memory"},
		"cpus range":         {"limits:\n  cpus: 99\n", "limits.cpus 99: use 1..32"},
		"bad timeout":        {"limits:\n  timeout: forever\n", "line 2: duration"},
		"timeout range":      {"limits:\n  timeout: 1s\n", "limits.timeout"},
		"secret no hosts":    {"secrets:\n  A:\n    from_env: B\n", "hosts is empty"},
		"secret no source":   {"secrets:\n  A:\n    hosts: [h]\n", "from_env or from_file"},
		"secret both":        {"secrets:\n  A:\n    from_env: B\n    from_file: c\n    hosts: [h]\n", "not both"},
		"secret name":        {"secrets:\n  lower:\n    from_env: B\n    hosts: [h]\n", "upper case"},
		"secret wildcard":    {"secrets:\n  A:\n    from_env: B\n    hosts: [\"*\"]\n", "exact host"},
		"inspect":            {"inspect: some\n", "inspect"},
		"wrong kind":         {"allow: pypi\n", "line 1"},
		"two docs":           {"image: x\n---\nimage: y\n", "more than one"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml), "tkbox.yaml")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int{"2GiB": 2048, "512MiB": 512, "2G": 2048, "1.5GiB": 1536, "1GB": 954, "100KiB": 1} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "2", "GiB", "-1GiB", "2 parsecs"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) accepted", in)
		}
	}
}

func TestRequestMergesFlagsAndResolvesSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.txt"), []byte("sk-file-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "tkbox.yaml")
	if err := os.WriteFile(p, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"GH_TOKEN": "ghp_envvalue", "OTHER": "other-value"}
	r := Resolver{Getenv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}
	_, flagSecret, err := ParseSecretFlag("EXTRA=env:OTHER@example.com")
	if err != nil {
		t.Fatal(err)
	}
	req, err := Request(f, Flags{Image: "alpine:3", Allow: []string{"github"}, Memory: "1GiB", CPUs: 1,
		Env: map[string]string{"FOO": "flag"}, Secrets: map[string]Secret{"EXTRA": flagSecret}, Name: "flagname"}, r)
	if err != nil {
		t.Fatal(err)
	}
	if req.Image != "alpine:3" || req.Limits.MemoryMiB != 1024 || req.Limits.CPUs != 1 || req.Limits.DiskMiB != 512 {
		t.Fatalf("flags did not override: %+v", req)
	}
	if strings.Join(req.Allow, ",") != "pypi,api.example.com:8443,github" || req.Env["FOO"] != "flag" {
		t.Fatalf("lists did not merge: %v %v", req.Allow, req.Env)
	}
	if req.Name != "flagname" || req.Task != "fix the tests" {
		t.Fatalf("name/task %q %q", req.Name, req.Task)
	}
	if req.Workspace != dir {
		t.Fatalf("workspace %q, want the file's dir %q", req.Workspace, dir)
	}
	if req.Secrets["GITHUB_TOKEN"].Value != "ghp_envvalue" || req.Secrets["KEY"].Value != "sk-file-value" ||
		req.Secrets["EXTRA"].Value != "other-value" || req.Secrets["GITHUB_TOKEN"].Header != "Authorization" {
		t.Fatalf("secrets %+v", req.Secrets)
	}
}

func TestRequestSecretErrorsNeverHoldValues(t *testing.T) {
	f := &File{Image: "x", Secrets: map[string]Secret{
		"A": {FromEnv: "MISSING", Hosts: []string{"h"}},
		"B": {FromEnv: "MULTI", Hosts: []string{"h"}},
	}}
	r := Resolver{Getenv: func(k string) (string, bool) {
		if k == "MULTI" {
			return "line1\nsupersecret", true
		}
		return "", false
	}}
	_, err := Request(f, Flags{}, r)
	if err == nil || !strings.Contains(err.Error(), "$MISSING is not set") || !strings.Contains(err.Error(), "line break") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "supersecret") {
		t.Fatal("error holds the secret value")
	}
	_, err = Request(&File{Image: "x", Secrets: map[string]Secret{"C": {FromFile: "/nope/x", Hosts: []string{"h"}}}}, Flags{},
		Resolver{Getenv: os.LookupEnv, ReadFile: func(string) ([]byte, error) {
			return nil, &os.PathError{Op: "open", Path: "/nope/x", Err: errors.New("no such file")}
		}})
	if err == nil || !strings.Contains(err.Error(), "cannot read /nope/x") {
		t.Fatalf("err = %v", err)
	}
	if _, err := Request(nil, Flags{}, Resolver{}); err == nil || !strings.Contains(err.Error(), "no image") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseSecretFlag(t *testing.T) {
	name, s, err := ParseSecretFlag("GH=env:GITHUB_TOKEN@api.github.com,uploads.github.com#Authorization")
	if err != nil || name != "GH" || s.FromEnv != "GITHUB_TOKEN" || len(s.Hosts) != 2 || s.Hosts[1] != "uploads.github.com" ||
		s.Header != "Authorization" {
		t.Fatalf("%s %+v %v", name, s, err)
	}
	name, s, err = ParseSecretFlag("KEY=file:/home/me/a@b/key.txt@API.Anthropic.com")
	if err != nil || name != "KEY" || s.FromFile != "/home/me/a@b/key.txt" || s.Hosts[0] != "api.anthropic.com" || s.Header != "" {
		t.Fatalf("%s %+v %v", name, s, err)
	}
	for in, want := range map[string]string{
		"GH":                       "missing NAME=",
		"gh=env:X@h":               "upper case",
		"GH=env:X":                 "missing @hosts",
		"GH=env:X@":                "hosts is empty",
		"GH=ghp_literalvalue@h":    "env: or file:",
		"GH=env:@h":                "env var name",
		"GH=file:@h":               "needs a path",
		"GH=env:X@h#Bad Header":    "header",
		"GH=env:X@*":               "exact host",
		"GH=env:X@h.example/path":  "exact host",
		"GH=sk-ant-literal@h#Auth": "env: or file:",
	} {
		_, _, err := ParseSecretFlag(in)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseSecretFlag(%q) err = %v, want %q", in, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), "ghp_literalvalue") || strings.Contains(err.Error(), "sk-ant-literal")) {
			t.Errorf("error echoes a literal value: %v", err)
		}
	}
}
