package egress

import (
	"errors"
	"net"
	"net/netip"
)

// STUB: agent D replaces this file (keep these signatures).

// Proxy is one box's egress proxy.
type Proxy struct{}

// New validates cfg and returns a proxy. A missing Decider or Sink, a secret without hosts, or a missing CA when
// MITM is needed is an error.
func New(cfg Config) (*Proxy, error) { return nil, errors.New("egress: not implemented") }

// Serve accepts connections from l (the box's vsock UDS for PortEgress) until l is closed or Close is called.
func (p *Proxy) Serve(l net.Listener) error { return errors.New("egress: not implemented") }

// Close stops accepting and closes every open connection.
func (p *Proxy) Close() error { return nil }

// Preset is a named group of hosts.
type Preset struct {
	Hosts []string
	Model bool // requests to these hosts are model calls
}

// Presets returns the built-in presets: github, pypi, npm, anthropic, openai, apt-ubuntu, go-proxy.
func Presets() map[string]Preset { return nil }

// Expand turns presets and host entries into Allow patterns and model hosts; an entry that is neither a preset nor a
// valid host pattern is an error naming it.
func Expand(entries []string) (allow, modelHosts []string, err error) {
	return nil, nil, errors.New("egress: not implemented")
}

// NewPlaceholder returns "tkbox_<name>_<32 random hex>".
func NewPlaceholder(name string) (string, error) { return "", errors.New("egress: not implemented") }

// Blocked reports whether a is refused by the built-in ranges, and which one.
func Blocked(a netip.Addr) (bool, string) { return true, "not implemented" }

// CA is a per-box MITM certificate authority (ECDSA P-256), valid for the box's lifetime only.
type CA struct{}

// NewCA creates a CA for one box.
func NewCA(boxID string) (*CA, error) { return nil, errors.New("egress: not implemented") }

// CertPEM is the CA certificate the guest trusts (never the key).
func (c *CA) CertPEM() []byte { return nil }
