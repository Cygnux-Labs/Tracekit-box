// Package egress is the only way out of a box: an HTTP proxy the guest reaches over vsock. It speaks HTTP CONNECT and
// absolute-form HTTP, resolves names on the host once and dials the resolved address (no DNS rebinding), refuses
// loopback/private/link-local/metadata addresses, asks a Decider about every new connection, and MITMs only hosts
// that have a bound secret (or every allowed host with Inspect "all") to swap secret placeholders for real values.
// The types here are the contract (lead); proxy.go and friends implement them (agent D).
package egress

import (
	"context"
	"crypto/x509"
	"net/netip"
	"time"
)

// Request is what the Decider is asked about one new connection (CONNECT) or one absolute-form HTTP request.
type Request struct {
	BoxID       string
	Scheme      string // "https" for CONNECT, "http" for an absolute-form request
	Host        string // lower case, no trailing dot; a name or an IP literal as the client sent it
	Port        int
	URL         string       // canonical "<scheme>://<host>:<port>", the WebFetch args url
	OnAllowlist bool         // the host:port matches the box's allowlist
	Addrs       []netip.Addr // what Host resolved to; all of them passed the address checks
}

// Verdict is the Decider's answer.
type Verdict struct {
	Allow   bool
	Reason  string   // why; sent to the client in the 403 body and recorded
	RuleIDs []string // signer rule ids behind a refusal
}

// Decider decides one connection before the proxy dials it. It may block (a person approving); the proxy bounds the
// wait with Config.DecideTimeout. An error refuses the connection (fail closed).
type Decider interface {
	Decide(ctx context.Context, req Request) (Verdict, error)
}

// Event kinds (same strings as api.Event*).
const (
	EventAllowed    = "egress.allowed"
	EventDenied     = "egress.denied"
	EventClosed     = "egress.closed"
	EventSecretUse  = "secret.use"
	EventSecretLeak = "secret.leak"
	EventModelCall  = "model.call"
)

// Event is something that happened at the network door. It never holds a secret value or a placeholder.
type Event struct {
	Time     time.Time
	Kind     string
	Host     string
	Port     int
	Method   string // MITM'd or plain-HTTP requests only
	Path     string // URL path without the query string
	Status   int    // upstream response status (model.call, egress.closed of an HTTP request)
	BytesIn  int64  // from upstream to the guest
	BytesOut int64  // from the guest to upstream
	Secret   string // the secret's name, for secret.use and secret.leak
	Reason   string // for egress.denied and secret.leak
	RuleIDs  []string
}

// Sink receives events. Emit must not block for long; the proxy calls it from connection goroutines.
type Sink interface {
	Emit(Event)
}

// Secret is one bound secret. The guest only ever sees Placeholder.
type Secret struct {
	Name        string   // env var name, e.g. "GH"
	Placeholder string   // NewPlaceholder(Name)
	Value       string   // the real value: never logged, never in an Event
	Hosts       []string // exact lower-case hosts, or "*.example.com" (any subdomain, not the apex)
	Header      string   // the request header it is swapped in (canonical form); "" = any request header
}

// Resolver resolves host names; net.DefaultResolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Inspect modes.
const (
	InspectBound = "bound" // MITM only hosts with a bound secret
	InspectAll   = "all"   // MITM every allowed HTTPS host (leak checks everywhere; breaks certificate pinning)
)

// Config configures one box's proxy.
type Config struct {
	BoxID string
	// Allow is the expanded allowlist (see Expand): "example.com" (ports 80 and 443), "*.example.com" (subdomains,
	// ports 80 and 443), "example.com:8443" (that port only), or an IP literal with the same forms.
	Allow      []string
	ModelHosts []string // hosts whose requests emit model.call events (the anthropic and openai presets)
	Secrets    []Secret
	Inspect    string // InspectBound (default) or InspectAll
	CA         *CA    // required when Secrets is non-empty or Inspect is InspectAll
	Decider    Decider
	Sink       Sink
	Resolver   Resolver // nil: net.DefaultResolver
	// BlockPrefixes are refused in addition to the built-in ranges (e.g. the signer's own address).
	BlockPrefixes []netip.Prefix
	// AllowPrivate exempts ranges from the built-in private-address block. Tests and explicit operator opt-in only;
	// never exempts the metadata address 169.254.169.254 or BlockPrefixes.
	AllowPrivate []netip.Prefix
	// UpstreamRoots verifies upstream TLS on MITM'd connections; nil means the host's system roots.
	UpstreamRoots  *x509.CertPool
	DialTimeout    time.Duration // default 10s
	IdleTimeout    time.Duration // default 5m of no traffic in either direction
	DecideTimeout  time.Duration // default 5m; a Decide still running then refuses the connection
	MaxConns       int           // concurrent connections; default 256
	MaxHeaderBytes int           // default 64 KiB for request heads the proxy reads
}

// Defaults.
const (
	DefaultDialTimeout    = 10 * time.Second
	DefaultIdleTimeout    = 5 * time.Minute
	DefaultDecideTimeout  = 5 * time.Minute
	DefaultMaxConns       = 256
	DefaultMaxHeaderBytes = 64 << 10
)
