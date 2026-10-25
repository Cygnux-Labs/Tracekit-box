package image

import (
	"fmt"
	"strings"
)

// reference is a parsed image reference such as "python:3.12-slim" or "ghcr.io/org/app@sha256:…".
type reference struct {
	Domain string // registry as users write it: "docker.io", "ghcr.io", "localhost:5000"
	Repo   string // "library/python"
	Tag    string // empty when only a digest was given
	Digest string // "sha256:…" or empty
}

// Name is the normalised reference, e.g. "docker.io/library/python:3.12-slim".
func (r reference) Name() string {
	s := r.Domain + "/" + r.Repo
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// apiHost is the host serving the registry API: Docker Hub's lives at registry-1.docker.io.
func (r reference) apiHost() string {
	if r.Domain == "docker.io" {
		return "registry-1.docker.io"
	}
	return r.Domain
}

// manifestRef is what to ask the registry for: the digest when pinned, else the tag.
func (r reference) manifestRef() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

func parseReference(s string) (reference, error) {
	orig := s
	bad := func(why string) (reference, error) {
		return reference{}, fmt.Errorf("image reference %q: %s (expected [registry/]name[:tag][@sha256:digest], e.g. python:3.12-slim)", orig, why)
	}
	if s == "" {
		return bad("empty")
	}
	if len(s) > 1024 {
		return bad("too long")
	}
	var r reference
	if i := strings.IndexByte(s, '@'); i >= 0 {
		r.Digest = s[i+1:]
		s = s[:i]
		if err := checkDigest(r.Digest); err != nil {
			return bad(err.Error())
		}
	}
	if i := strings.LastIndexByte(s, ':'); i > strings.LastIndexByte(s, '/') {
		r.Tag = s[i+1:]
		s = s[:i]
		if !validTag(r.Tag) {
			return bad("invalid tag " + fmt.Sprintf("%q", r.Tag))
		}
	}
	path := s
	r.Domain = "docker.io"
	if i := strings.IndexByte(s, '/'); i >= 0 {
		if first := s[:i]; strings.ContainsAny(first, ".:") || first == "localhost" {
			r.Domain, path = strings.ToLower(first), s[i+1:]
			if !validDomain(r.Domain) {
				return bad("invalid registry host " + fmt.Sprintf("%q", first))
			}
		}
	}
	if r.Domain == "index.docker.io" || r.Domain == "registry-1.docker.io" {
		r.Domain = "docker.io"
	}
	if r.Domain == "docker.io" && !strings.Contains(path, "/") {
		path = "library/" + path
	}
	if len(path) > 255 {
		return bad("repository name longer than 255 characters")
	}
	for _, c := range strings.Split(path, "/") {
		if !validPathComponent(c) {
			return bad(fmt.Sprintf("invalid name component %q (lowercase letters, digits and separators . _ __ - only)", c))
		}
	}
	r.Repo = path
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r, nil
}

// checkDigest accepts only sha256 digests in canonical form. Digests end up in URLs and cache file names, so this is
// also what keeps a hostile manifest from naming a path.
func checkDigest(d string) error {
	hex, ok := strings.CutPrefix(d, "sha256:")
	if !ok {
		return fmt.Errorf("digest %q is not sha256 (only sha256 digests are supported)", d)
	}
	if len(hex) != 64 {
		return fmt.Errorf("digest %q is not 64 hex characters", d)
	}
	for i := 0; i < len(hex); i++ {
		if c := hex[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return fmt.Errorf("digest %q is not lowercase hex", d)
		}
	}
	return nil
}

func validTag(t string) bool {
	if t == "" || len(t) > 128 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		word := c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
		if !word && (i == 0 || c != '.' && c != '-') {
			return false
		}
	}
	return true
}

func validDomain(d string) bool {
	host, port, hasPort := strings.Cut(d, ":")
	if host == "" || len(d) > 255 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	if hasPort {
		if port == "" || len(port) > 5 {
			return false
		}
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				return false
			}
		}
	}
	return true
}

// validPathComponent matches [a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*.
func validPathComponent(c string) bool {
	if c == "" {
		return false
	}
	alnum := func(b byte) bool { return 'a' <= b && b <= 'z' || '0' <= b && b <= '9' }
	for i := 0; i < len(c); {
		if !alnum(c[i]) {
			return false
		}
		for i < len(c) && alnum(c[i]) {
			i++
		}
		if i == len(c) {
			return true
		}
		switch {
		case c[i] == '.':
			i++
		case strings.HasPrefix(c[i:], "__"):
			i += 2
		case c[i] == '_':
			i++
		case c[i] == '-':
			for i < len(c) && c[i] == '-' {
				i++
			}
		default:
			return false
		}
		if i == len(c) {
			return false
		}
	}
	return true
}
