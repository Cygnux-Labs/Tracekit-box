// Package daemon is the tkbox daemon: the box manager that wires vmm, image, egress, tracekit and agentrpc, the HTTP
// API on the Unix socket (internal/api), limits, timeouts and the kill switch.
//
// One box = one micro-VM + one egress proxy + one Tracekit run. Every door is decided before it opens: commands
// (Bash), connections (WebFetch, then the allowlist or a person), and host writes (Write). Without a signer nothing
// runs, unless the daemon was started unrecorded, which it says loudly everywhere.
package daemon

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/image"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
	"github.com/Cygnux-Labs/tracekit-box/internal/vmm"
)

// Defaults (docs/limits.md).
const (
	DefaultCPUs            = 2
	DefaultMemoryMiB       = 2048
	DefaultDiskMiB         = 4096
	DefaultTimeout         = time.Hour
	DefaultExecTimeout     = 30 * time.Minute
	DefaultApprovalTimeout = 2 * time.Minute
	DefaultMaxBoxes        = 8
	DefaultReadyTimeout    = 60 * time.Second
	DefaultContainmentPoll = 2 * time.Second
	// after DefaultContainmentFastFor a box's containment is checked every DefaultContainmentSlowPoll instead
	DefaultContainmentFastFor  = time.Minute
	DefaultContainmentSlowPoll = 15 * time.Second
	shutdownTimeout            = 10 * time.Second
	maxDiffBytes               = proto.DefaultMaxDiffBytes
)

// Proxy is what the daemon needs from a box's egress proxy (*egress.Proxy).
type Proxy interface {
	Serve(l net.Listener) error
	Close() error
}

// GateFunc runs one gated call (tracekit.Gate in production).
type GateFunc func(ctx context.Context, r tracekit.Run, call tracekit.Call, hooks tracekit.GateHooks) (tracekit.Outcome, error)

// Options configures a Daemon. Launcher, Builder, StateDir and KernelPath are required; Tracekit is required unless
// Unrecorded is set.
type Options struct {
	StateDir   string
	Launcher   vmm.Launcher
	Builder    image.Builder
	Tracekit   tracekit.Client // nil only with Unrecorded
	Unrecorded bool            // run boxes that record nothing (loud warnings everywhere)
	// GuestClient returns the agent client of a machine; default agentrpc.New over m.Dial(ctx, proto.PortAgent).
	GuestClient func(m vmm.Machine) agentrpc.Guest
	// NewProxy builds a box's egress proxy; default egress.New.
	NewProxy func(cfg egress.Config) (Proxy, error)
	// Gate runs a gated call; default tracekit.Gate.
	Gate       GateFunc
	KernelPath string
	Arch       string // "arm64" or "amd64"; default runtime.GOARCH
	Version    string // tkbox build version for /v1/health
	Defaults   api.Limits
	// ApprovalTimeout is how long a Box approval waits for a person (default 2m).
	ApprovalTimeout time.Duration
	MaxBoxes        int // boxes alive at once (default 8)
	// Test-only egress knobs (dangerous in production): private ranges the proxy may dial and the roots it trusts
	// upstream.
	EgressAllowPrivate  []netip.Prefix
	EgressUpstreamRoots *x509.CertPool
	// EgressBlock are extra prefixes no box may reach, on top of the built-in ranges and this host's own interface
	// addresses: e.g. the host's NAT'd public IP on a cloud VM, which is on no interface (`tkbox daemon --egress-block`).
	EgressBlock         []netip.Prefix
	Now                 func() time.Time
	ReadyTimeout        time.Duration // guest readiness (default 60s)
	ContainmentPoll     time.Duration // default 2s, for the first ContainmentFastFor of a box
	ContainmentFastFor  time.Duration // default 1m
	ContainmentSlowPoll time.Duration // default 15s (never shorter than ContainmentPoll)
	Logger              *log.Logger
}

// Daemon manages boxes.
type Daemon struct {
	opts      Options
	ctx       context.Context
	cancel    context.CancelFunc
	log       *log.Logger
	ownUID    int
	allowUID  func(uid int) bool // tests: replaces the own-uid-or-root rule
	eg        egressHooks
	hostAddrs hostAddrs // this host's own addresses, which no box may reach

	mu        sync.Mutex
	boxes     map[string]*box // by id
	approvals map[string]*approval
	closed    bool
	wg        sync.WaitGroup
}

// egressHooks are the egress package functions the daemon calls (swapped in tests).
type egressHooks struct {
	expand      func(entries []string) (allow, modelHosts []string, err error)
	placeholder func(name string) (string, error)
	newCA       func(boxID string, opts egress.CAOptions) (*egress.CA, string, error) // the CA and its certificate PEM
}

var defaultEgressHooks = egressHooks{
	expand:      egress.Expand,
	placeholder: egress.NewPlaceholder,
	newCA: func(boxID string, opts egress.CAOptions) (*egress.CA, string, error) {
		ca, err := egress.NewCAWith(boxID, opts)
		if err != nil {
			return nil, "", err
		}
		return ca, string(ca.CertPEM()), nil
	},
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// New checks opts, loads the boxes persisted under StateDir (boxes left alive by a previous daemon are marked failed)
// and returns a Daemon. It starts nothing; Serve starts the API.
func New(opts Options) (*Daemon, error) {
	if opts.StateDir == "" || !filepath.IsAbs(opts.StateDir) {
		return nil, errors.New("daemon: StateDir must be an absolute path")
	}
	if opts.Launcher == nil || opts.Builder == nil {
		return nil, errors.New("daemon: Launcher and Builder are required")
	}
	if opts.Tracekit == nil && !opts.Unrecorded {
		return nil, errors.New("daemon: no Tracekit client: start a signer (`tracekit up`) or run unrecorded")
	}
	if opts.Tracekit != nil && opts.Unrecorded {
		return nil, errors.New("daemon: Unrecorded with a Tracekit client: pick one")
	}
	if opts.KernelPath == "" {
		return nil, errors.New("daemon: KernelPath is required")
	}
	if opts.Arch == "" {
		opts.Arch = runtime.GOARCH
	}
	if opts.GuestClient == nil {
		opts.GuestClient = func(m vmm.Machine) agentrpc.Guest {
			return agentrpc.New(func(ctx context.Context) (net.Conn, error) { return m.Dial(ctx, proto.PortAgent) })
		}
	}
	if opts.NewProxy == nil {
		opts.NewProxy = func(cfg egress.Config) (Proxy, error) { return egress.New(cfg) }
	}
	if opts.Gate == nil {
		opts.Gate = tracekit.Gate
	}
	if opts.ApprovalTimeout <= 0 {
		opts.ApprovalTimeout = DefaultApprovalTimeout
	}
	if opts.MaxBoxes <= 0 {
		opts.MaxBoxes = DefaultMaxBoxes
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ReadyTimeout <= 0 {
		opts.ReadyTimeout = DefaultReadyTimeout
	}
	if opts.ContainmentPoll <= 0 {
		opts.ContainmentPoll = DefaultContainmentPoll
	}
	if opts.ContainmentFastFor <= 0 {
		opts.ContainmentFastFor = DefaultContainmentFastFor
	}
	if opts.ContainmentSlowPoll <= 0 {
		opts.ContainmentSlowPoll = DefaultContainmentSlowPoll
	}
	if opts.Logger == nil {
		opts.Logger = log.New(os.Stderr, "tkbox: ", log.LstdFlags)
	}
	block := make([]netip.Prefix, 0, len(opts.EgressBlock))
	for _, p := range opts.EgressBlock {
		if !p.IsValid() {
			return nil, fmt.Errorf("daemon: EgressBlock: %v is not a valid prefix", p)
		}
		block = append(block, p.Masked())
	}
	opts.EgressBlock = block
	d := opts.Defaults
	if d.CPUs == 0 {
		d.CPUs = DefaultCPUs
	}
	if d.MemoryMiB == 0 {
		d.MemoryMiB = DefaultMemoryMiB
	}
	if d.DiskMiB == 0 {
		d.DiskMiB = DefaultDiskMiB
	}
	if d.Timeout == 0 {
		d.Timeout = api.Duration(DefaultTimeout)
	}
	if d.ExecTimeout == 0 {
		d.ExecTimeout = api.Duration(DefaultExecTimeout)
	}
	if err := checkLimits(d); err != nil {
		return nil, fmt.Errorf("daemon: default limits: %s", err.Message)
	}
	opts.Defaults = d
	for _, sub := range []string{"", "boxes", "images", "run"} {
		p := filepath.Join(opts.StateDir, sub)
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, fmt.Errorf("daemon: %w", err)
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return nil, fmt.Errorf("daemon: %w", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	dm := &Daemon{opts: opts, ctx: ctx, cancel: cancel, log: opts.Logger, ownUID: os.Getuid(), eg: defaultEgressHooks,
		boxes: map[string]*box{}, approvals: map[string]*approval{}}
	if err := dm.load(); err != nil {
		cancel()
		return nil, err
	}
	if opts.Unrecorded {
		dm.log.Printf("WARNING: unrecorded: boxes record nothing in Tracekit and cannot be exported; the allowlist and Box approvals still apply")
	}
	return dm, nil
}

func (d *Daemon) now() time.Time { return d.opts.Now() }

func (d *Daemon) boxDir(id string) string { return filepath.Join(d.opts.StateDir, "boxes", id) }

// SocketPath is where the API listens.
func (d *Daemon) SocketPath() string { return filepath.Join(d.opts.StateDir, "run", "tkbox.sock") }

// persisted is box.json: the public view plus what a restarted daemon needs. Never a secret value.
type persisted struct {
	api.Box
	CID         uint32 `json:"cid"`
	RunClosed   bool   `json:"run_closed,omitempty"`    // close_run was accepted
	RunClosedBy string `json:"run_closed_by,omitempty"` // "export", "failed", "quarantine", "shutdown", "rm"
	CloseReason string `json:"close_reason,omitempty"`
}

// load reads boxes/*/box.json. A box a previous daemon left alive died with it: mark it failed.
func (d *Daemon) load() error {
	ents, err := os.ReadDir(filepath.Join(d.opts.StateDir, "boxes"))
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := d.boxDir(e.Name())
		b, err := os.ReadFile(filepath.Join(dir, "box.json"))
		if err != nil {
			d.log.Printf("skipping %s: %v", dir, err)
			continue
		}
		var p persisted
		if err := json.Unmarshal(b, &p); err != nil || p.ID != e.Name() {
			d.log.Printf("skipping %s: unreadable box.json", dir)
			continue
		}
		bx := newBox(d, p.Box, dir, p.CID)
		bx.runClosed, bx.runClosedBy, bx.closeReason = p.RunClosed, p.RunClosedBy, p.CloseReason
		switch p.State {
		case api.StateCreating, api.StateRunning, api.StatePaused, api.StateStopping:
			bx.info.State = api.StateFailed
			bx.info.Error = "daemon restarted; the VM was killed with it"
			bx.info.StopReason = "daemon restarted"
			if bx.info.StoppedAt.IsZero() {
				bx.info.StoppedAt = d.now()
			}
			if !bx.info.DiffSaved && bx.info.DiffError == "" {
				bx.info.DiffError = "the daemon stopped while the box was alive, so its workspace diff was not saved"
			}
			bx.persist()
			bx.event(api.EventBoxFailed, "lifecycle", bx.info.Error, nil)
		}
		if !bx.info.Unrecorded && bx.info.RunID != "" && !bx.runClosed {
			// the run token died with the previous daemon and Tracekit Box can't rebuild a run from its id: the run
			// stays open in the signer, can't be closed from here and so can't be exported
			bx.runLost = true
			bx.event(api.EventSignerProblem, "lifecycle", fmt.Sprintf("the Tracekit run %s was left open by a daemon that stopped without closing it (crashed or killed); this daemon can't close it, so the box can't be exported", bx.info.RunID), nil)
			d.log.Printf("WARNING: box %s: Tracekit run %s was left open by the previous daemon; it can't be closed or exported", p.ID, bx.info.RunID)
		}
		bx.events.release()
		bx.closeDone()
		d.boxes[p.ID] = bx
	}
	return nil
}

// lookup finds a box by id or name.
func (d *Daemon) lookup(ref string) (*box, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if b, ok := d.boxes[ref]; ok {
		return b, nil
	}
	for _, b := range d.boxes {
		if b.name() == ref {
			return b, nil
		}
	}
	return nil, &api.ErrorDetail{Code: api.CodeNotFound, Message: fmt.Sprintf("no box %q", ref),
		Hint: "list boxes with `tkbox ls`"}
}

// List returns every box, oldest first.
func (d *Daemon) List() []api.Box {
	d.mu.Lock()
	bs := make([]*box, 0, len(d.boxes))
	for _, b := range d.boxes {
		bs = append(bs, b)
	}
	d.mu.Unlock()
	out := make([]api.Box, len(bs))
	for i, b := range bs {
		out[i] = b.view()
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get returns one box by id or name.
func (d *Daemon) Get(ref string) (api.Box, error) {
	b, err := d.lookup(ref)
	if err != nil {
		return api.Box{}, err
	}
	return b.view(), nil
}

// Health reports the daemon's state.
func (d *Daemon) Health(ctx context.Context) api.Health {
	d.mu.Lock()
	n := len(d.boxes)
	d.mu.Unlock()
	h := api.Health{Version: d.opts.Version, API: api.Version, Arch: d.opts.Arch, KVM: d.opts.Launcher.Check() == nil,
		Unrecorded: d.opts.Unrecorded, Boxes: n, StateDir: d.opts.StateDir}
	if d.opts.Tracekit != nil {
		h.Signer = d.opts.Tracekit.Where()
		sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, err := d.opts.Tracekit.Status(sctx)
		cancel()
		h.SignerOK = err == nil
	}
	return h
}

// Shutdown stops every live box (reason "daemon shutdown") and waits for them.
func (d *Daemon) Shutdown(ctx context.Context) {
	d.mu.Lock()
	d.closed = true
	bs := make([]*box, 0, len(d.boxes))
	for _, b := range d.boxes {
		bs = append(bs, b)
	}
	d.mu.Unlock()
	var wg sync.WaitGroup
	for _, b := range bs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.stop(ctx, "daemon shutdown", false)
			// the run token dies with the daemon: close every open run so its bundle can still be exported. The close
			// has its own clock: a slow stop must not leave the run open
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := b.closeRun(cctx, "shutdown"); err != nil {
				b.event(api.EventSignerProblem, "lifecycle", "could not close the Tracekit run: "+err.Error(), nil)
				d.log.Printf("WARNING: box %s: could not close its Tracekit run: %v", b.id, err)
			}
		}()
	}
	wg.Wait()
	d.cancel()
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("tkbox: no randomness: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// errf builds an API error.
func errf(code, hint, format string, a ...any) *api.ErrorDetail {
	return &api.ErrorDetail{Code: code, Message: fmt.Sprintf(format, a...), Hint: hint}
}

// asAPIError turns any error into an API error (internal unless it already is one).
func asAPIError(err error) *api.ErrorDetail {
	var e *api.ErrorDetail
	if errors.As(err, &e) {
		return e
	}
	var u *tracekit.Unavailable
	if errors.As(err, &u) {
		return &api.ErrorDetail{Code: api.CodeUnavailable, Message: err.Error(),
			Hint: "check the signer (`tracekit status`); nothing runs without it"}
	}
	var pe *proto.Error
	if errors.As(err, &pe) {
		return &api.ErrorDetail{Code: pe.Code, Message: pe.Message}
	}
	return &api.ErrorDetail{Code: api.CodeInternal, Message: err.Error()}
}
