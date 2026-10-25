// Package config loads and validates tkbox.yaml, the file `tkbox run` reads (./tkbox.yaml by default), and parses the
// CLI's --secret flag. Decoding is strict: an unknown key, a duplicate key or a value of the wrong kind is an error
// naming its line. Secret values are resolved here, in the CLI's process, from its env or files; the file itself only
// names where they come from.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
)

// DefaultFile is the config `tkbox run` reads when --config is not given and the file exists.
const DefaultFile = "tkbox.yaml"

// Limit ranges, shared with the daemon (it validates again and is the authority).
const (
	MinCPUs, MaxCPUs           = 1, 32
	MinMemoryMiB, MaxMemoryMiB = 128, 65536
	MinDiskMiB, MaxDiskMiB     = 64, 1048576
	MinTimeout, MaxTimeout     = 10 * time.Second, 7 * 24 * time.Hour
	MinExecTimeout             = time.Second
	MaxExecTimeout             = 24 * time.Hour
	MaxSecretBytes             = 64 << 10
)

var (
	secretNameRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	envNameRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	headerRE     = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

// File is tkbox.yaml.
type File struct {
	Name      string            `yaml:"name"`
	Image     string            `yaml:"image"`
	Allow     []string          `yaml:"allow"`
	Secrets   map[string]Secret `yaml:"secrets"`
	Env       map[string]string `yaml:"env"`
	Limits    Limits            `yaml:"limits"`
	Workspace string            `yaml:"workspace"` // relative paths are relative to the file's dir
	Inspect   string            `yaml:"inspect"`   // "bound" (default) or "all"
	Agent     string            `yaml:"agent"`     // agent name recorded in the Tracekit run
	Task      string            `yaml:"task"`      // recorded as trusted content of the run

	dir string // the file's dir, for relative paths ("" for flags: the working dir)
	// limitNames names a limit in errors ("limits.cpus" in a file, "--cpus" for a flag)
	limitNames map[string]string
}

// WorkspacePath is the file's workspace as an absolute, clean path ("~/" expanded, relative paths taken from the
// file's dir); "" when it names none.
func (f *File) WorkspacePath() string {
	if f == nil || f.Workspace == "" {
		return ""
	}
	return absWorkspace(f.Workspace, f.dir)
}

func absWorkspace(ws, dir string) string {
	if strings.HasPrefix(ws, "~/") || ws == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			ws = filepath.Join(home, strings.TrimPrefix(ws, "~"))
		}
	}
	if !filepath.IsAbs(ws) {
		if dir != "" {
			ws = filepath.Join(dir, ws)
		} else if a, err := filepath.Abs(ws); err == nil {
			ws = a
		}
	}
	return filepath.Clean(ws)
}

// Secret names where one secret's value comes from. Exactly one of FromEnv and FromFile.
type Secret struct {
	FromEnv  string   `yaml:"from_env"`
	FromFile string   `yaml:"from_file"`
	Hosts    []string `yaml:"hosts"`
	Header   string   `yaml:"header"`

	line int
}

// Limits of a box; zero means the daemon's default.
type Limits struct {
	CPUs        int      `yaml:"cpus"`
	Memory      Size     `yaml:"memory"` // "2GiB"
	Disk        Size     `yaml:"disk"`   // "4GiB"
	Timeout     Duration `yaml:"timeout"`
	ExecTimeout Duration `yaml:"exec_timeout"`
}

// Size is a byte size written with a unit ("512MiB", "2GiB", "2G") or a plain integer of MiB; it holds MiB, rounded
// up.
type Size int

// Duration is a Go duration string ("90s", "1h").
type Duration time.Duration

func (s *Secret) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: a secret is a mapping with from_env or from_file, hosts and header", n.Line)
	}
	// Node.Decode does not inherit KnownFields, so check the keys here.
	for i := 0; i+1 < len(n.Content); i += 2 {
		switch k := n.Content[i]; k.Value {
		case "from_env", "from_file", "hosts", "header":
		default:
			return fmt.Errorf("line %d: unknown key %s in a secret (keys: from_env, from_file, hosts, header)", k.Line, k.Value)
		}
	}
	type plain Secret
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*s = Secret(p)
	s.line = n.Line
	return nil
}

func (s *Size) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: want a size like \"2GiB\"", n.Line)
	}
	if n.Tag == "!!int" {
		v, err := strconv.Atoi(n.Value)
		if err != nil || v <= 0 {
			return fmt.Errorf("line %d: size %s: want a positive number of MiB or a size like \"2GiB\"", n.Line, n.Value)
		}
		*s = Size(v)
		return nil
	}
	v, err := ParseSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*s = Size(v)
	return nil
}

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: want a duration like \"30m\"", n.Line)
	}
	v, err := ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// ParseSize parses "512MiB", "2GiB", "2G" (binary), "2GB" (decimal) into MiB, rounded up. A bare number is refused:
// say the unit.
func ParseSize(s string) (int, error) {
	t := strings.TrimSpace(s)
	i := 0
	for i < len(t) && (t[i] >= '0' && t[i] <= '9' || t[i] == '.') {
		i++
	}
	num, unit := t[:i], strings.TrimSpace(t[i:])
	if num == "" {
		return 0, fmt.Errorf("size %q: want a number and a unit, like \"2GiB\" or \"512MiB\"", s)
	}
	mult := map[string]float64{
		"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
		"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40,
		"KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
	}[unit]
	if mult == 0 {
		return 0, fmt.Errorf("size %q: unknown or missing unit; use KiB, MiB, GiB or TiB (e.g. \"2GiB\")", s)
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil || f <= 0 {
		return 0, fmt.Errorf("size %q: want a positive number and a unit, like \"2GiB\"", s)
	}
	mib := math.Ceil(f * mult / (1 << 20))
	if mib > math.MaxInt32 {
		return 0, fmt.Errorf("size %q is too large", s)
	}
	return int(mib), nil
}

// ParseDuration parses a Go duration ("90s", "30m", "1h30m"); "0" and negative values are refused.
func ParseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("duration %q: want a value like \"30m\" or \"1h\"", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return d, nil
}

// Load reads and validates a config file.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	f, err := Parse(b, path)
	if err != nil {
		return nil, err
	}
	f.dir = filepath.Dir(abs)
	return f, nil
}

// Parse decodes and validates a config. name is used in error messages.
func Parse(b []byte, name string) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %s", name, cleanYAMLError(err))
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: more than one YAML document; keep one", name)
	}
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &f, nil
}

func cleanYAMLError(err error) string {
	s := strings.TrimPrefix(err.Error(), "yaml: ")
	s = strings.TrimPrefix(s, "unmarshal errors:\n")
	s = strings.ReplaceAll(s, " in type config.File", "")
	s = strings.ReplaceAll(s, " in type config.plain", "")
	s = strings.ReplaceAll(s, " in type config.Limits", "")
	s = strings.ReplaceAll(s, "field ", "unknown key ")
	s = strings.ReplaceAll(s, " not found", "")
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "; ")
}

// Validate checks what can be checked without the daemon.
func (f *File) Validate() error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	for _, a := range f.Allow {
		if strings.TrimSpace(a) == "" || strings.ContainsAny(a, " \t/@") {
			add("allow: %q is not a preset or a host (e.g. \"pypi\", \"api.example.com\", \"h:8443\")", a)
		}
	}
	names := make([]string, 0, len(f.Secrets))
	for n := range f.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := f.Secrets[n]
		at := ""
		if s.line > 0 {
			at = fmt.Sprintf("line %d: ", s.line)
		}
		if !secretNameRE.MatchString(n) {
			add("%ssecret %q: the name is the env var the box sees; use upper case, digits and _ (e.g. GITHUB_TOKEN)", at, n)
		}
		switch {
		case s.FromEnv == "" && s.FromFile == "":
			add("%ssecret %s: say where the value comes from with from_env or from_file", at, n)
		case s.FromEnv != "" && s.FromFile != "":
			add("%ssecret %s: give from_env or from_file, not both", at, n)
		case s.FromEnv != "" && !envNameRE.MatchString(s.FromEnv):
			add("%ssecret %s: from_env %q is not an env var name", at, n, s.FromEnv)
		}
		if err := checkHosts(s.Hosts); err != nil {
			add("%ssecret %s: %v", at, n, err)
		}
		if s.Header != "" && !headerRE.MatchString(s.Header) {
			add("%ssecret %s: header %q is not a valid HTTP header name", at, n, s.Header)
		}
	}
	for k := range f.Env {
		if !envNameRE.MatchString(k) {
			add("env: %q is not an env var name", k)
		}
		if _, ok := f.Secrets[k]; ok {
			add("env: %s is also a secret; keep it in secrets only", k)
		}
	}
	if err := f.Limits.validate(f.limitNames); err != nil {
		add("%v", err)
	}
	switch f.Inspect {
	case "", "bound", "all":
	default:
		add("inspect: %q: use \"bound\" (MITM only hosts with a bound secret) or \"all\"", f.Inspect)
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func checkHosts(hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("hosts is empty: name the hosts the secret may be sent to (e.g. [api.github.com])")
	}
	for _, h := range hosts {
		hl := strings.ToLower(strings.TrimSpace(h))
		if hl == "" || hl == "*" || strings.ContainsAny(hl, " /@#:") || strings.Count(hl, "*") > 1 ||
			(strings.Contains(hl, "*") && !strings.HasPrefix(hl, "*.")) {
			return fmt.Errorf("host %q: want an exact host name or \"*.example.com\"", h)
		}
	}
	return nil
}

// Validate checks the ranges; zero values mean the daemon's default.
func (l Limits) Validate() error { return l.validate(nil) }

// validate checks the ranges, naming each limit as names says (default "limits.<key>").
func (l Limits) validate(names map[string]string) error {
	name := func(k string) string {
		if n, ok := names[k]; ok {
			return n
		}
		return "limits." + k
	}
	var errs []string
	if l.CPUs != 0 && (l.CPUs < MinCPUs || l.CPUs > MaxCPUs) {
		errs = append(errs, fmt.Sprintf("%s %d: use %d..%d", name("cpus"), l.CPUs, MinCPUs, MaxCPUs))
	}
	if l.Memory != 0 && (l.Memory < MinMemoryMiB || l.Memory > MaxMemoryMiB) {
		errs = append(errs, fmt.Sprintf("%s %dMiB: use 128MiB..64GiB", name("memory"), l.Memory))
	}
	if l.Disk != 0 && (l.Disk < MinDiskMiB || l.Disk > MaxDiskMiB) {
		errs = append(errs, fmt.Sprintf("%s %dMiB: use 64MiB..1TiB", name("disk"), l.Disk))
	}
	if t := time.Duration(l.Timeout); t != 0 && (t < MinTimeout || t > MaxTimeout) {
		errs = append(errs, fmt.Sprintf("%s %s: use 10s..168h", name("timeout"), t))
	}
	if t := time.Duration(l.ExecTimeout); t != 0 && (t < MinExecTimeout || t > MaxExecTimeout) {
		errs = append(errs, fmt.Sprintf("%s %s: use 1s..24h", name("exec_timeout"), t))
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Flags are `tkbox run`'s flags. Scalars override the file's values; Allow, Env and Secrets append to the file's (a
// key given both ways takes the flag's value).
type Flags struct {
	Image     string
	Allow     []string // already split on commas
	Workspace string
	Name      string
	Secrets   map[string]Secret // from ParseSecretFlag
	Env       map[string]string
	CPUs      int
	Memory    string
	Disk      string
	Timeout   string
	Inspect   string
	Task      string
	Agent     string
}

// Env and file lookups, swappable in tests.
type Resolver struct {
	Getenv   func(string) (string, bool)
	ReadFile func(string) ([]byte, error)
}

// Request merges the file (nil: none) with the flags, resolves secret values and returns the create request.
func Request(f *File, fl Flags, r Resolver) (api.CreateBoxRequest, error) {
	if r.Getenv == nil {
		r.Getenv = os.LookupEnv
	}
	if r.ReadFile == nil {
		r.ReadFile = os.ReadFile
	}
	m := File{}
	if f != nil {
		m = *f
	}
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if fl.Image != "" {
		m.Image = fl.Image
	}
	if fl.Inspect != "" {
		m.Inspect = fl.Inspect
	}
	if fl.Agent != "" {
		m.Agent = fl.Agent
	}
	if fl.Name != "" {
		m.Name = fl.Name
	}
	if fl.Task != "" {
		m.Task = fl.Task
	}
	m.Allow = append(append([]string(nil), m.Allow...), fl.Allow...)
	m.Env = mergeMap(m.Env, fl.Env)
	secrets := map[string]Secret{}
	for k, v := range m.Secrets {
		secrets[k] = v
	}
	wsDir := m.dir
	if fl.Workspace != "" {
		m.Workspace, wsDir = fl.Workspace, ""
	}
	m.limitNames = map[string]string{}
	if fl.CPUs != 0 {
		m.Limits.CPUs = fl.CPUs
		m.limitNames["cpus"] = "--cpus"
	}
	if fl.Memory != "" {
		m.limitNames["memory"] = "--memory"
	}
	if fl.Disk != "" {
		m.limitNames["disk"] = "--disk"
	}
	if fl.Timeout != "" {
		m.limitNames["timeout"] = "--timeout"
	}
	if fl.Memory != "" {
		v, err := ParseSize(fl.Memory)
		if err != nil {
			add("--memory: %v", err)
		}
		m.Limits.Memory = Size(v)
	}
	if fl.Disk != "" {
		v, err := ParseSize(fl.Disk)
		if err != nil {
			add("--disk: %v", err)
		}
		m.Limits.Disk = Size(v)
	}
	if fl.Timeout != "" {
		v, err := ParseDuration(fl.Timeout)
		if err != nil {
			add("--timeout: %v", err)
		}
		m.Limits.Timeout = Duration(v)
	}
	if m.Image == "" {
		add("no image: pass --image (e.g. --image python:3.12-slim) or set image: in %s", DefaultFile)
	}
	flagSecrets := map[string]bool{}
	for k, v := range fl.Secrets {
		secrets[k] = v
		flagSecrets[k] = true
	}
	m.Secrets = secrets
	if len(errs) == 0 {
		if err := m.Validate(); err != nil {
			add("%v", err)
		}
	}
	req := api.CreateBoxRequest{
		Name: m.Name, Image: m.Image, Allow: m.Allow, Env: m.Env, Inspect: m.Inspect, Agent: m.Agent, Task: m.Task,
		Limits: api.Limits{CPUs: m.Limits.CPUs, MemoryMiB: int(m.Limits.Memory), DiskMiB: int(m.Limits.Disk),
			Timeout: api.Duration(m.Limits.Timeout), ExecTimeout: api.Duration(m.Limits.ExecTimeout)},
	}
	if m.Workspace != "" {
		req.Workspace = absWorkspace(m.Workspace, wsDir)
	}
	if len(secrets) > 0 {
		req.Secrets = map[string]api.SecretSpec{}
	}
	names := make([]string, 0, len(secrets))
	for n := range secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := secrets[n]
		baseDir := m.dir
		if flagSecrets[n] {
			baseDir = ""
		}
		v, err := resolveValue(n, s, baseDir, r)
		if err != nil {
			add("%v", err)
			continue
		}
		hosts := make([]string, len(s.Hosts))
		for i, h := range s.Hosts {
			hosts[i] = strings.ToLower(strings.TrimSpace(h))
		}
		req.Secrets[n] = api.SecretSpec{Value: v, Hosts: hosts, Header: s.Header}
	}
	if len(errs) > 0 {
		return api.CreateBoxRequest{}, errors.New(strings.Join(errs, "; "))
	}
	return req, nil
}

func mergeMap(a, b map[string]string) map[string]string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// resolveValue reads a secret's value. Errors name the secret and its source, never the value.
func resolveValue(name string, s Secret, baseDir string, r Resolver) (string, error) {
	var v string
	if s.FromEnv != "" {
		val, ok := r.Getenv(s.FromEnv)
		if !ok || val == "" {
			return "", fmt.Errorf("secret %s: $%s is not set in this shell; export it or use from_file", name, s.FromEnv)
		}
		v = val
	} else {
		p := s.FromFile
		if strings.HasPrefix(p, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				p = filepath.Join(home, p[2:])
			}
		}
		if !filepath.IsAbs(p) && baseDir != "" {
			p = filepath.Join(baseDir, p)
		}
		b, err := r.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("secret %s: cannot read %s: %v", name, p, errors.Unwrap(err))
		}
		v = strings.TrimRight(string(b), "\r\n")
	}
	switch {
	case v == "":
		return "", fmt.Errorf("secret %s: the value is empty", name)
	case len(v) > MaxSecretBytes:
		return "", fmt.Errorf("secret %s: the value is over 64 KiB", name)
	case strings.ContainsAny(v, "\r\n\x00"):
		return "", fmt.Errorf("secret %s: the value has a line break or NUL; a header value can't carry one", name)
	}
	return v, nil
}

// ParseSecretFlag parses --secret NAME=env:VAR@host1,host2[#Header] or NAME=file:PATH@hosts[#Header].
func ParseSecretFlag(s string) (string, Secret, error) {
	bad := func(why string) (string, Secret, error) {
		return "", Secret{}, fmt.Errorf("--secret %q: %s (want NAME=env:VAR@host1,host2[#Header] or NAME=file:PATH@hosts[#Header])", redactFlag(s), why)
	}
	name, rest, ok := strings.Cut(s, "=")
	if !ok || name == "" {
		return bad("missing NAME=")
	}
	if !secretNameRE.MatchString(name) {
		return bad("NAME must be upper case, digits and _")
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return bad("missing @hosts: name the hosts the secret may be sent to")
	}
	src, hostPart := rest[:at], rest[at+1:]
	var sec Secret
	if h, hdr, ok := strings.Cut(hostPart, "#"); ok {
		hostPart, sec.Header = h, hdr
		if !headerRE.MatchString(hdr) {
			return bad("the #Header is not a valid HTTP header name")
		}
	}
	for _, h := range strings.Split(hostPart, ",") {
		if h = strings.TrimSpace(h); h != "" {
			sec.Hosts = append(sec.Hosts, strings.ToLower(h))
		}
	}
	if err := checkHosts(sec.Hosts); err != nil {
		return bad(err.Error())
	}
	switch {
	case strings.HasPrefix(src, "env:"):
		sec.FromEnv = strings.TrimPrefix(src, "env:")
		if !envNameRE.MatchString(sec.FromEnv) {
			return bad("env:VAR needs an env var name")
		}
	case strings.HasPrefix(src, "file:"):
		sec.FromFile = strings.TrimPrefix(src, "file:")
		if sec.FromFile == "" {
			return bad("file:PATH needs a path")
		}
	default:
		return bad("the source must start with env: or file: (values are never given on the command line)")
	}
	return name, sec, nil
}

// redactFlag keeps only the NAME= part of a flag in an error, in case someone pasted a value.
func redactFlag(s string) string {
	if n, rest, ok := strings.Cut(s, "="); ok {
		if strings.HasPrefix(rest, "env:") || strings.HasPrefix(rest, "file:") {
			return s
		}
		return n + "=…"
	}
	return "…"
}
