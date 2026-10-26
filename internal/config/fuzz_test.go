package config

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// F6 (fuzz): --secret checks the source (env: or file:) before anything else after NAME=, so a pasted value is never
// quoted in an error, not even its tail after the last @ (which used to be checked, and quoted, as a host).
func TestFuzzF6SecretFlagNeverEchoesTheValue(t *testing.T) {
	for _, c := range []struct{ flag, tail string }{
		{"DB=hunter2@x/y", "x/y"},
		{"DB=pa@ss word", "ss word"},
		{"GH=ghp_abc@def:ghi", "def:ghi"},
		{"GH=ghp_abc@a.com#Bad Header", "a.com"},
		{"GH=ghp_abc@*.example.com", "example"},
	} {
		_, _, err := ParseSecretFlag(c.flag)
		if err == nil {
			t.Fatalf("%s accepted", c.flag)
		}
		name, _, _ := strings.Cut(c.flag, "=")
		if strings.Contains(err.Error(), c.tail) || !strings.Contains(err.Error(), strconv.Quote(name+"=…")) ||
			!strings.Contains(err.Error(), "the source must start with env: or file:") {
			t.Errorf("--secret %s: %v", c.flag, err)
		}
	}
	// a real source still gets its host checked (and named: no value is in it)
	if _, _, err := ParseSecretFlag("GH=env:GH_TOKEN@x/y"); err == nil || !strings.Contains(err.Error(), `host "x/y"`) {
		t.Fatalf("env source with a bad host: %v", err)
	}
}

// FuzzParse: any tkbox.yaml either fails with an error or yields a config whose every limit is zero (the daemon's
// default) or inside its range, whose secrets name exactly one source and exact hosts, and which validates again.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"image: python:3.12-slim\nallow: [pypi, github]\nlimits:\n  cpus: 2\n  memory: 2GiB\n  disk: 4GiB\n  timeout: 30m\n  exec_timeout: 1m\n",
		"secrets:\n  GH:\n    from_env: GH_TOKEN\n    hosts: [api.github.com]\n    header: Authorization\n",
		"secrets:\n  GH:\n    from_file: ~/tok\n    hosts: [\"*.github.com\"]\n",
		"limits: {memory: 512, disk: 0.5TiB, cpus: 33}\n", "inspect: all\nenv: {A: b}\n", "a: &a [*a]\n", "---\n---\n",
		"limits:\n  memory: 99999999999999999999GiB\n", "limits:\n  timeout: -1s\n", "limits:\n  memory: !!int 0x10\n",
		"secrets: {GH: {from_env: X, from_file: y, hosts: []}}\n", "workspace: ~/src\nname: x\ntask: t\nagent: a\n",
		"limits:\n  memory: 1e3MiB\n", "limits:\n  memory: .\n", "env:\n  GH: x\nsecrets:\n  GH: {from_env: GH, hosts: [a.com]}\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			return
		}
		cfg, err := Parse(b, "tkbox.yaml")
		if err != nil {
			if cfg != nil {
				t.Fatal("config and error")
			}
			return
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Parse accepted a config that does not validate: %v", err)
		}
		l := cfg.Limits
		if l.CPUs != 0 && (l.CPUs < MinCPUs || l.CPUs > MaxCPUs) || l.Memory != 0 && (l.Memory < MinMemoryMiB || l.Memory > MaxMemoryMiB) ||
			l.Disk != 0 && (l.Disk < MinDiskMiB || l.Disk > MaxDiskMiB) || l.Memory < 0 || l.Disk < 0 || l.CPUs < 0 {
			t.Fatalf("limits out of range: %+v", l)
		}
		if d := time.Duration(l.Timeout); d != 0 && (d < MinTimeout || d > MaxTimeout) {
			t.Fatalf("timeout out of range: %v", d)
		}
		if d := time.Duration(l.ExecTimeout); d != 0 && (d < MinExecTimeout || d > MaxExecTimeout) {
			t.Fatalf("exec_timeout out of range: %v", d)
		}
		for n, s := range cfg.Secrets {
			if !secretNameRE.MatchString(n) || (s.FromEnv == "") == (s.FromFile == "") || len(s.Hosts) == 0 {
				t.Fatalf("secret %q accepted: %+v", n, s)
			}
			for _, h := range s.Hosts {
				if strings.ContainsAny(h, "*/@#: ") && strings.TrimSpace(h) == h {
					t.Fatalf("secret %q host %q accepted", n, h)
				}
			}
			if s.Header != "" && !headerRE.MatchString(s.Header) {
				t.Fatalf("secret %q header %q accepted", n, s.Header)
			}
			if _, clash := cfg.Env[n]; clash {
				t.Fatalf("secret %q is also an env", n)
			}
		}
		for k := range cfg.Env {
			if !envNameRE.MatchString(k) {
				t.Fatalf("env %q accepted", k)
			}
		}
		switch cfg.Inspect {
		case "", "bound", "all":
		default:
			t.Fatalf("inspect %q accepted", cfg.Inspect)
		}
		// merging with flags and resolving values: never a panic, never a value with a line break
		env := map[string]string{}
		for _, s := range cfg.Secrets {
			if s.FromEnv != "" {
				env[s.FromEnv] = "v\r\nX: y"
			}
		}
		_, err = Request(cfg, Flags{Image: "x"}, Resolver{
			Getenv:   func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			ReadFile: func(string) ([]byte, error) { return []byte("val\nue\n"), nil },
		})
		if len(cfg.Secrets) > 0 && err == nil {
			t.Fatal("a secret value with a line break was accepted")
		}
	})
}

// FuzzParseSecretFlag: --secret parses only to a valid name, one source, exact hosts and a header; a refused flag's
// error shows only NAME=… unless the source is env: or file: (anything else may be a pasted value).
func FuzzParseSecretFlag(f *testing.F) {
	for _, s := range []string{"GH=env:GH_TOKEN@api.github.com", "GH=file:~/t@a.com,b.com#X-Key", "GH=ghp_realvalue123@x.com",
		"GH=env:X@*.github.com", "gh=env:X@a", "GH=env:X@", "=x", "GH=file:@a.com", "GH=ghp_abc#def@a.com#Bad Header",
		"DB=hunter2@x/y", "DB=pa@ss word"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		name, sec, err := ParseSecretFlag(s)
		if err != nil {
			flagName, rest, ok := strings.Cut(s, "=")
			if !ok || strings.HasPrefix(rest, "env:") || strings.HasPrefix(rest, "file:") {
				return
			}
			msg := err.Error()
			shown := strconv.Quote(flagName + "=…") // the NAME= part is shown on purpose, nothing after it
			if !strings.HasPrefix(msg, "--secret "+shown+": ") {
				t.Fatalf("error does not show only NAME=…: %q", msg)
			}
			// with no env: or file: source, the reason is one of the fixed texts: nothing from the value part
			msg = strings.TrimPrefix(msg, "--secret "+shown+": ")
			const want = " (want NAME=env:VAR@host1,host2[#Header] or NAME=file:PATH@hosts[#Header])"
			switch strings.TrimSuffix(msg, want) {
			case "the source must start with env: or file: (values are never given on the command line)",
				"NAME must be upper case, digits and _", "missing NAME=":
			default:
				t.Fatalf("a refusal of a flag with no env:/file: source says more than a fixed reason: %q", err)
			}
			return
		}
		if !secretNameRE.MatchString(name) || (sec.FromEnv == "") == (sec.FromFile == "") {
			t.Fatalf("ParseSecretFlag(%q) = %q %+v", s, name, sec)
		}
		if err := checkHosts(sec.Hosts); err != nil {
			t.Fatalf("ParseSecretFlag(%q) hosts %q: %v", s, sec.Hosts, err)
		}
		if sec.Header != "" && !headerRE.MatchString(sec.Header) {
			t.Fatalf("ParseSecretFlag(%q) header %q", s, sec.Header)
		}
	})
}
