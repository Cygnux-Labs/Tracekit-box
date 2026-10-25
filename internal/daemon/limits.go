package daemon

import (
	"fmt"
	"net/netip"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/config"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
)

var (
	secretNameRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	envNameRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	headerRE     = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

// Env names the box sets itself; a request may not override them.
var reservedEnv = map[string]bool{
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "http_proxy": true, "https_proxy": true, "NO_PROXY": true, "no_proxy": true,
	"SSL_CERT_FILE": true, "NODE_EXTRA_CA_CERTS": true, "REQUESTS_CA_BUNDLE": true, "GIT_SSL_CAINFO": true,
	"CURL_CA_BUNDLE": true, "ALL_PROXY": true, "all_proxy": true,
}

func limitErr(format string, hint string, a ...any) *api.ErrorDetail {
	return &api.ErrorDetail{Code: api.CodeLimit, Message: fmt.Sprintf(format, a...), Hint: hint}
}

// checkLimits checks filled-in limits against the ranges in docs/limits.md.
func checkLimits(l api.Limits) *api.ErrorDetail {
	switch {
	case l.CPUs < config.MinCPUs || l.CPUs > config.MaxCPUs:
		return limitErr("cpus %d is outside 1..32", "pass --cpus between 1 and 32", l.CPUs)
	case l.MemoryMiB < config.MinMemoryMiB || l.MemoryMiB > config.MaxMemoryMiB:
		return limitErr("memory %dMiB is outside 128MiB..64GiB", "pass --memory between 128MiB and 64GiB (e.g. --memory 2GiB)", l.MemoryMiB)
	case l.DiskMiB < config.MinDiskMiB || l.DiskMiB > config.MaxDiskMiB:
		return limitErr("disk %dMiB is outside 64MiB..1TiB", "pass --disk between 64MiB and 1TiB (e.g. --disk 4GiB)", l.DiskMiB)
	case time.Duration(l.Timeout) < config.MinTimeout || time.Duration(l.Timeout) > config.MaxTimeout:
		return limitErr("timeout %s is outside 10s..168h", "pass --timeout between 10s and 168h (e.g. --timeout 1h)", time.Duration(l.Timeout))
	case time.Duration(l.ExecTimeout) < config.MinExecTimeout || time.Duration(l.ExecTimeout) > config.MaxExecTimeout:
		return limitErr("exec timeout %s is outside 1s..24h", "set limits.exec_timeout between 1s and 24h", time.Duration(l.ExecTimeout))
	}
	return nil
}

// spec is a validated create request.
type spec struct {
	req        api.CreateBoxRequest
	limits     api.Limits
	allow      []string
	modelHosts []string
	secrets    []egress.Secret // placeholders filled later
	inspect    string
	agent      string
	// this host's own addresses, which the proxy refuses
	blockPrefixes []netip.Prefix
}

// validate checks a create request and fills in defaults. Errors never hold a secret value.
func (d *Daemon) validate(req api.CreateBoxRequest) (*spec, *api.ErrorDetail) {
	bad := func(hint, format string, a ...any) (*spec, *api.ErrorDetail) {
		return nil, errf(api.CodeBadRequest, hint, format, a...)
	}
	if req.Name != "" && !nameRE.MatchString(req.Name) {
		return bad("use lower case letters, digits and -, starting with a letter or digit (at most 63)", "name %q is not valid", req.Name)
	}
	if strings.HasPrefix(req.Name, "tkb-") {
		return bad("pick a name that does not start with tkb- (ids do)", "name %q looks like a box id", req.Name)
	}
	req.Image = strings.TrimSpace(req.Image)
	if req.Image == "" || strings.ContainsAny(req.Image, " \t\n") {
		return bad("pass --image, e.g. --image python:3.12-slim", "image %q is not an OCI reference", req.Image)
	}
	l := req.Limits
	def := d.opts.Defaults
	if l.CPUs == 0 {
		l.CPUs = def.CPUs
	}
	if l.MemoryMiB == 0 {
		l.MemoryMiB = def.MemoryMiB
	}
	if l.DiskMiB == 0 {
		l.DiskMiB = def.DiskMiB
	}
	if l.Timeout == 0 {
		l.Timeout = def.Timeout
	}
	if l.ExecTimeout == 0 {
		l.ExecTimeout = def.ExecTimeout
	}
	if e := checkLimits(l); e != nil {
		return nil, e
	}
	s := &spec{req: req, limits: l, agent: req.Agent}
	if s.agent == "" {
		s.agent = "tkbox"
	}
	switch req.Inspect {
	case "", egress.InspectBound:
		s.inspect = egress.InspectBound
	case egress.InspectAll:
		s.inspect = egress.InspectAll
	default:
		return bad("use \"bound\" or \"all\"", "inspect %q is not valid", req.Inspect)
	}
	if len(req.Allow) > 0 {
		allow, model, err := d.eg.expand(req.Allow)
		if err != nil {
			// the egress package's message names the presets and says what to do
			return bad("", "%s", strings.TrimPrefix(err.Error(), "egress: "))
		}
		s.allow, s.modelHosts = allow, model
	}
	if s.allow == nil {
		s.allow = []string{}
	}
	names := make([]string, 0, len(req.Secrets))
	for n := range req.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sec := req.Secrets[n]
		if !secretNameRE.MatchString(n) {
			return bad("secret names are env var names: upper case, digits and _", "secret %q: bad name", n)
		}
		if reservedEnv[n] {
			return bad("pick another name", "secret %s: the box sets %s itself", n, n)
		}
		if sec.Value == "" {
			return bad("the CLI resolves values from its env or files; check the source", "secret %s has no value", n)
		}
		if len(sec.Value) > config.MaxSecretBytes {
			return nil, limitErr("secret %s is over 64 KiB", "secrets are header values; keep them under 64 KiB", n)
		}
		if strings.ContainsAny(sec.Value, "\r\n\x00") {
			return bad("a header value can't carry a line break", "secret %s has a line break or NUL", n)
		}
		if len(sec.Hosts) == 0 {
			return bad("bind it to the hosts that need it, e.g. NAME=env:VAR@api.github.com", "secret %s has no hosts", n)
		}
		hosts := make([]string, len(sec.Hosts))
		for i, h := range sec.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" || h == "*" || strings.ContainsAny(h, " /@#:") || strings.Count(h, "*") > 1 ||
				(strings.Contains(h, "*") && !strings.HasPrefix(h, "*.")) {
				return bad("use exact host names or *.example.com", "secret %s: host %q is not valid", n, sec.Hosts[i])
			}
			hosts[i] = h
		}
		header := ""
		if sec.Header != "" {
			if !headerRE.MatchString(sec.Header) {
				return bad("use an HTTP header name such as Authorization", "secret %s: header %q is not valid", n, sec.Header)
			}
			header = textproto.CanonicalMIMEHeaderKey(sec.Header)
		}
		s.secrets = append(s.secrets, egress.Secret{Name: n, Value: sec.Value, Hosts: hosts, Header: header})
		// a secret's hosts join the allowlist: binding a key to a host means talking to it (ports 80 and 443)
		for _, h := range hosts {
			if !slices.Contains(s.allow, h) {
				s.allow = append(s.allow, h)
			}
		}
	}
	for k, v := range req.Env {
		if !envNameRE.MatchString(k) {
			return bad("env names are letters, digits and _", "env %q is not a valid name", k)
		}
		if reservedEnv[k] {
			return bad("the box routes every connection through its proxy itself", "env %s is set by the box and can't be overridden", k)
		}
		if _, ok := req.Secrets[k]; ok {
			return bad("keep it in secrets only", "env %s is also a secret", k)
		}
		if strings.ContainsRune(v, 0) {
			return bad("remove the NUL byte", "env %s has a NUL byte", k)
		}
	}
	if req.Workspace != "" {
		ws := req.Workspace
		if !filepath.IsAbs(ws) || filepath.Clean(ws) != ws {
			return bad("pass an absolute path (the CLI resolves --workspace for you)", "workspace %q is not an absolute, clean path", ws)
		}
		fi, err := os.Stat(ws)
		if err != nil || !fi.IsDir() {
			return bad("pass an existing directory", "workspace %s is not a directory the daemon can read", ws)
		}
	}
	if len(req.Task) > 64<<10 {
		return nil, limitErr("task is over 64 KiB", "shorten the task text")
	}
	return s, nil
}
