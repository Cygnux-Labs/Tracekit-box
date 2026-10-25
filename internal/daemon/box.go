package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
	"github.com/Cygnux-Labs/tracekit-box/internal/vmm"
)

const (
	proxyURL     = "http://127.0.0.1:3128"
	trustedObs   = "trusted"
	untrustedObs = "untrusted"
)

// box is one micro-VM, its proxy and its Tracekit run.
type box struct {
	d   *Daemon
	id  string
	dir string
	cid uint32

	mu            sync.Mutex
	info          api.Box
	machine       vmm.Machine
	guest         agentrpc.Guest
	proxy         Proxy
	listeners     []net.Listener
	run           tracekit.Run
	runClosed     bool   // close_run accepted
	runClosedBy   string // "export", "failed", "quarantine", "shutdown", "rm"
	runLost       bool   // a previous daemon left the run open and its token died with it
	closeReason   string // why the box stopped: the run's close reason
	calls         callTracker
	ctlMu         sync.Mutex // orders containment's pause/resume against stop's state change
	secrets       []egress.Secret
	approvedHosts map[string]bool // "host:port" approved for the rest of the box (scope "box")
	sessions      map[*execSession]struct{}
	timer         *time.Timer
	obs           *observer
	obsClosed     bool
	heldPaused    bool // paused because the signer holds the run
	bootCancel    context.CancelFunc
	stopReason    string // a stop asked for while creating
	signerTrouble bool
	failedClosed  bool // a must-record observe was lost: the box is being stopped
	tearingDown   bool
	persistMu     sync.Mutex // one box.json writer at a time

	scrubP   atomic.Pointer[scrubber]
	events   *eventLog
	stopCh   chan struct{} // closed when the box starts going down
	stopOnce sync.Once
	done     chan struct{} // closed once stopped or failed
	doneOnce sync.Once
	seq      atomic.Uint64
	pollNow  chan chan struct{} // tests: run one containment check now
	bootCfg  proto.BootConfig
}

func newBox(d *Daemon, info api.Box, dir string, cid uint32) *box {
	b := &box{d: d, id: info.ID, dir: dir, cid: cid, info: info, approvedHosts: map[string]bool{},
		sessions: map[*execSession]struct{}{}, events: openEventLog(dir), stopCh: make(chan struct{}),
		done: make(chan struct{}), pollNow: make(chan chan struct{})}
	b.scrubP.Store(&scrubber{})
	return b
}

func (b *box) scrub() *scrubber { return b.scrubP.Load() }

func (b *box) name() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.info.Name
}

func (b *box) state() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.info.State
}

func alive(state string) bool {
	switch state {
	case api.StateCreating, api.StateRunning, api.StatePaused, api.StateStopping:
		return true
	}
	return false
}

func (b *box) view() api.Box {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.info
	v.Allow = append([]string{}, b.info.Allow...)
	v.Secrets = append([]string(nil), b.info.Secrets...)
	v.Notices = append([]string(nil), b.info.Notices...)
	if b.info.SecretHeaders != nil {
		v.SecretHeaders = make(map[string]string, len(b.info.SecretHeaders))
		for k, x := range b.info.SecretHeaders {
			v.SecretHeaders[k] = x
		}
	}
	if b.info.Env != nil {
		v.Env = make(map[string]string, len(b.info.Env))
		for k, x := range b.info.Env {
			v.Env[k] = x
		}
	}
	return v
}

func (b *box) closeDone() { b.doneOnce.Do(func() { close(b.done) }) }

func (b *box) nextCallID(kind string) string { return fmt.Sprintf("%s-%d", kind, b.seq.Add(1)) }

// persist writes box.json atomically (0600). It holds no secret values: api.Box only names secrets.
func (b *box) persist() {
	b.persistMu.Lock()
	defer b.persistMu.Unlock()
	b.mu.Lock()
	p := persisted{Box: b.info, CID: b.cid, RunClosed: b.runClosed, RunClosedBy: b.runClosedBy, CloseReason: b.closeReason}
	b.mu.Unlock()
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		b.d.log.Printf("%s: box.json: %v", b.id, err)
		return
	}
	tmp := filepath.Join(b.dir, ".box.json.tmp")
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		b.d.log.Printf("%s: box.json: %v", b.id, err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(b.dir, "box.json")); err != nil {
		b.d.log.Printf("%s: box.json: %v", b.id, err)
	}
}

// Create validates req, boots a box and returns it running. On any failure everything is torn down, the run is
// closed with the reason, and the box stays listed as failed (its console.log kept for reading).
func (d *Daemon) Create(ctx context.Context, req api.CreateBoxRequest) (api.Box, error) {
	s, e := d.validate(req)
	if e != nil {
		return api.Box{}, e
	}
	prefixes, err := hostPrefixes()
	if err != nil {
		return api.Box{}, errf(api.CodeInternal, "check the host's network interfaces; a box can't start without knowing which addresses to keep it away from",
			"could not list this host's addresses: %v", err)
	}
	s.blockPrefixes = prefixes
	var notices []string
	if ws := s.req.Workspace; ws != "" && !gitWorkTree(ws) {
		notices = append(notices, ws+" is not a git work tree: copying every file except credential files")
	}
	if req.ValidateOnly {
		names := make([]string, 0, len(s.secrets))
		for _, sec := range s.secrets {
			names = append(names, sec.Name)
		}
		return api.Box{Name: req.Name, Image: s.req.Image, Allow: s.allow, Secrets: names, Env: s.req.Env,
			Workspace: s.req.Workspace, Limits: s.limits, Inspect: s.inspect, Unrecorded: d.opts.Unrecorded, Notices: notices}, nil
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return api.Box{}, errf(api.CodeUnavailable, "start the daemon again (`tkbox daemon`) and retry", "the daemon is shutting down")
	}
	live := 0
	used := map[uint32]bool{}
	for _, b := range d.boxes {
		b.mu.Lock()
		st, name := b.info.State, b.info.Name
		b.mu.Unlock()
		if req.Name != "" && name == req.Name {
			d.mu.Unlock()
			return api.Box{}, errf(api.CodeConflict, "pick another --name, or remove the old box with `tkbox rm "+req.Name+"`",
				"a box named %q already exists (%s)", req.Name, st)
		}
		if alive(st) {
			live++
			used[b.cid] = true
		}
	}
	if live >= d.opts.MaxBoxes {
		d.mu.Unlock()
		return api.Box{}, limitErr("%d boxes are alive and the daemon's limit is %d",
			"stop one with `tkbox stop <box>`, or restart the daemon with a higher --max-boxes", live, d.opts.MaxBoxes)
	}
	var id string
	for {
		id = "tkb-" + randHex(6)
		if _, taken := d.boxes[id]; !taken {
			break
		}
	}
	cid := uint32(3)
	for used[cid] {
		cid++
	}
	name := req.Name
	if name == "" {
		name = id
	}
	names := make([]string, 0, len(s.secrets))
	headers := map[string]string{}
	for _, sec := range s.secrets {
		names = append(names, sec.Name)
		headers[sec.Name] = sec.Header
	}
	if len(headers) == 0 {
		headers = nil
	}
	info := api.Box{ID: id, Name: name, State: api.StateCreating, Image: s.req.Image, Allow: s.allow, Secrets: names, SecretHeaders: headers,
		Env: s.req.Env, Workspace: s.req.Workspace, Limits: s.limits, Inspect: s.inspect,
		Unrecorded: d.opts.Unrecorded, CreatedAt: d.now().UTC(), Notices: notices}
	dir := d.boxDir(id)
	b := newBox(d, info, dir, cid)
	bctx, cancel := context.WithCancel(d.ctx)
	b.bootCancel = cancel
	d.boxes[id] = b
	d.wg.Add(1)
	d.mu.Unlock()
	defer d.wg.Done()
	defer cancel()

	if err := os.Mkdir(dir, 0o700); err != nil {
		d.mu.Lock()
		delete(d.boxes, id)
		d.mu.Unlock()
		return api.Box{}, asAPIError(err)
	}
	b.persist()
	b.event(api.EventBoxCreated, "lifecycle", fmt.Sprintf("box %s created from %s", name, s.req.Image), map[string]any{
		"image": s.req.Image, "allow": s.allow, "secrets": names, "unrecorded": d.opts.Unrecorded})
	for _, n := range notices {
		b.event(api.EventBoxCreated, "lifecycle", n, nil)
	}
	// a client that gives up (Ctrl-C on `tkbox run`) abandons the box rather than leaving one nobody knows about
	unwatch := context.AfterFunc(ctx, func() {
		b.mu.Lock()
		if b.stopReason == "" {
			b.stopReason = "the client went away"
		}
		b.mu.Unlock()
		cancel()
	})
	err = b.boot(bctx, s)
	unwatch()
	if err != nil {
		b.mu.Lock()
		if b.stopReason != "" {
			err = fmt.Errorf("stopped while creating (%s): %w", b.stopReason, err)
		}
		b.mu.Unlock()
		detail := ""
		var ge *guestError
		if errors.As(err, &ge) {
			detail = ge.detail
		}
		ae := asAPIError(err)
		ae.Message = b.scrub().str(ae.Message)
		b.teardown(context.Background(), ae.Message, detail, false, true)
		return b.view(), ae
	}
	return b.view(), nil
}

// guestError is a failure whose recorded reason is a fixed host-side phrase; detail (text the guest or the VM's
// console produced) goes only to events.ndjson, never into a trusted Tracekit record.
type guestError struct {
	msg, detail string
}

func (e *guestError) Error() string { return e.msg }

// gitWorkTree reports whether dir is inside a git work tree (git's own config and hooks stay out of it).
func gitWorkTree(dir string) bool {
	cmd := exec.Command("git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", dir, "rev-parse", "--is-inside-work-tree")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// boot does the work of Create after the box is registered.
func (b *box) boot(ctx context.Context, s *spec) error {
	d := b.d
	if d.opts.Tracekit != nil {
		run, err := d.opts.Tracekit.NewRun(ctx, tracekit.Agent{Name: s.agent})
		if err != nil {
			return fmt.Errorf("register the Tracekit run: %w", err)
		}
		b.mu.Lock()
		b.run = run
		b.info.RunID = run.ID()
		b.mu.Unlock()
		b.startObserver(run)
		if err := run.Observe(ctx, tracekit.SourceBox, trustedObs, map[string]any{
			"event": "created", "box_id": b.id, "name": b.info.Name, "image": s.req.Image, "allow": s.allow,
			"limits": s.limits, "secrets": b.info.Secrets, "workspace": s.req.Workspace, "inspect": s.inspect,
			"env": envValue(s.req.Env),
		}); err != nil {
			return fmt.Errorf("record the box in Tracekit: %w", err)
		}
		if s.req.Task != "" {
			if err := run.Observe(ctx, tracekit.SourceTask, trustedObs, map[string]any{"task": s.req.Task}); err != nil {
				return fmt.Errorf("record the task in Tracekit: %w", err)
			}
		}
		b.persist()
	}

	rootfs, err := d.opts.Builder.Rootfs(ctx, s.req.Image, d.opts.Arch)
	if err != nil {
		return fmt.Errorf("build the rootfs for %s: %w", s.req.Image, err)
	}
	b.mu.Lock()
	b.info.ImageDigest = rootfs.Digest
	b.mu.Unlock()

	wsSrc := s.req.Workspace
	if wsSrc == "" {
		wsSrc = filepath.Join(b.dir, "empty-workspace")
		if err := os.Mkdir(wsSrc, 0o700); err != nil {
			return err
		}
	}
	base := filepath.Join(b.dir, "workspace-base.ext4")
	if _, err := d.opts.Builder.Workspace(ctx, wsSrc, base); err != nil {
		return fmt.Errorf("build the workspace image: %w", err)
	}
	upper := filepath.Join(b.dir, "workspace-upper.ext4")
	if err := d.opts.Builder.Scratch(ctx, upper, int64(s.limits.DiskMiB)<<20); err != nil {
		return fmt.Errorf("create the %dMiB workspace disk: %w", s.limits.DiskMiB, err)
	}

	for i := range s.secrets {
		ph, err := d.eg.placeholder(s.secrets[i].Name)
		if err != nil {
			return fmt.Errorf("secret %s placeholder: %w", s.secrets[i].Name, err)
		}
		s.secrets[i].Placeholder = ph
	}
	b.mu.Lock()
	b.secrets = s.secrets
	b.mu.Unlock()
	b.scrubP.Store(newScrubber(s.secrets))

	var ca *egress.CA
	caPEM := ""
	if len(s.secrets) > 0 || s.inspect == egress.InspectAll {
		// the CA may impersonate only the hosts it must, and only while the box may live
		opts := egress.CAOptions{Lifetime: time.Duration(s.limits.Timeout) + time.Hour, Hosts: caHosts(s.secrets, s.allow, s.inspect)}
		if ca, caPEM, err = d.eg.newCA(b.id, opts); err != nil {
			return fmt.Errorf("create the box CA: %w", err)
		}
	}
	b.bootCfg = proto.BootConfig{
		Version: proto.Version, BoxID: b.id, Hostname: b.info.Name,
		Env:         buildEnv(rootfs.Config.Env, s.req.Env, s.secrets),
		ProxyListen: proto.DefaultProxyListen, CACertPEM: caPEM, CABundlePath: proto.DefaultCABundlePath,
		Workspace: &proto.WorkspaceMount{Path: proto.DefaultWorkspacePath, BaseDevice: "/dev/vdb", UpperDevice: "/dev/vdc"},
		Limits: proto.GuestLimits{ExecTimeoutMS: time.Duration(s.limits.ExecTimeout).Milliseconds(),
			MaxOutputBytes: proto.DefaultMaxOutputBytes, MaxProcs: proto.DefaultMaxProcs},
	}

	m, err := d.opts.Launcher.New(vmm.Spec{ID: b.id, KernelPath: d.opts.KernelPath, RootfsPath: rootfs.Path,
		Drives: []vmm.Drive{{ID: "workspace_base", Path: base, ReadOnly: true}, {ID: "workspace_upper", Path: upper}},
		VCPUs:  s.limits.CPUs, MemoryMiB: s.limits.MemoryMiB, StateDir: b.dir, GuestCID: b.cid})
	if err != nil {
		return fmt.Errorf("create the VM: %w", err)
	}
	b.mu.Lock()
	b.machine = m
	b.mu.Unlock()

	proxy, err := d.opts.NewProxy(egress.Config{BoxID: b.id, Allow: s.allow, ModelHosts: s.modelHosts,
		Secrets: s.secrets, Inspect: s.inspect, CA: ca, Decider: (*boxDecider)(b), Sink: (*boxSink)(b),
		BlockPrefixes: s.blockPrefixes, BlockFunc: d.hostAddrs.blocked, AllowPrivate: d.opts.EgressAllowPrivate, UpstreamRoots: d.opts.EgressUpstreamRoots,
		DecideTimeout: d.opts.ApprovalTimeout + 30*time.Second})
	if err != nil {
		return fmt.Errorf("start the egress proxy: %w", err)
	}
	b.mu.Lock()
	b.proxy = proxy
	b.mu.Unlock()

	lc, err := m.Listen(proto.PortConfig)
	if err != nil {
		return fmt.Errorf("listen for the boot config: %w", err)
	}
	b.addListener(lc)
	go b.serveBootConfig(lc)
	le, err := m.Listen(proto.PortEgress)
	if err != nil {
		return fmt.Errorf("listen for egress: %w", err)
	}
	b.addListener(le)
	go func() {
		if err := proxy.Serve(le); err != nil && !errors.Is(err, net.ErrClosed) && alive(b.state()) {
			b.event(api.EventBoxFailed, "egress", "egress proxy stopped: "+err.Error(), nil)
		}
	}()

	if err := m.Start(ctx); err != nil {
		return fmt.Errorf("start the VM: %w", err)
	}
	g := d.opts.GuestClient(m)
	b.mu.Lock()
	b.guest = g
	b.mu.Unlock()
	if err := b.waitReady(ctx, m, g); err != nil {
		return err
	}

	now := d.now().UTC()
	b.mu.Lock()
	b.info.State = api.StateRunning
	b.info.StartedAt = now
	b.info.ExpiresAt = now.Add(time.Duration(s.limits.Timeout))
	b.timer = time.AfterFunc(time.Duration(s.limits.Timeout), b.onTimeout)
	b.bootCancel = nil
	run := b.run
	b.mu.Unlock()
	if run != nil {
		octx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := run.Observe(octx, tracekit.SourceBox, trustedObs, map[string]any{"event": "started", "box_id": b.id,
			"image": s.req.Image, "image_digest": rootfs.Digest, "allow": s.allow, "limits": s.limits})
		cancel()
		if err != nil {
			b.mu.Lock()
			b.timer.Stop()
			b.info.State = api.StateCreating
			b.mu.Unlock()
			return fmt.Errorf("record the box start in Tracekit: %w", err)
		}
	}
	b.persist()
	b.event(api.EventBoxStarted, "lifecycle", fmt.Sprintf("box %s running (%s)", b.info.Name, rootfs.Digest),
		map[string]any{"image_digest": rootfs.Digest, "cpus": s.limits.CPUs, "memory_mib": s.limits.MemoryMiB})
	go b.watchMachine(m)
	if run != nil {
		go b.containmentLoop()
	}
	return nil
}

func (b *box) addListener(l net.Listener) {
	b.mu.Lock()
	b.listeners = append(b.listeners, l)
	b.mu.Unlock()
}

// buildEnv is the base env of every exec: image env, box env, placeholders, then the proxy and CA variables (later
// entries win). PATH and friends keep the image's order; the rest are sorted.
func buildEnv(imageEnv []string, boxEnv map[string]string, secrets []egress.Secret) []string {
	vals := map[string]string{}
	var order []string
	set := func(k, v string) {
		if _, ok := vals[k]; !ok {
			order = append(order, k)
		}
		vals[k] = v
	}
	for _, kv := range imageEnv {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			set(k, v)
		}
	}
	keys := make([]string, 0, len(boxEnv))
	for k := range boxEnv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		set(k, boxEnv[k])
	}
	for _, s := range secrets {
		set(s.Name, s.Placeholder)
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		set(k, proxyURL)
	}
	set("NO_PROXY", "")
	for _, k := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "CURL_CA_BUNDLE"} {
		set(k, proto.DefaultCABundlePath)
	}
	out := make([]string, len(order))
	for i, k := range order {
		out[i] = k + "=" + vals[k]
	}
	return out
}

// envValue is a box env as an observe value (map[string]any, which canonical JSON takes).
func envValue(env map[string]string) map[string]any {
	out := make(map[string]any, len(env))
	for k, v := range env {
		out[k] = v
	}
	return out
}

// serveBootConfig answers boot_config requests on the config port with the box's BootConfig until the guest has
// fetched it once; then the port is closed (the guest has no reason to ask twice).
func (b *box) serveBootConfig(l net.Listener) {
	var once sync.Once
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			f, err := proto.ReadFrame(c)
			if err != nil {
				return
			}
			var req proto.BootConfigRequest
			if f.Type != proto.TypeJSON || f.Decode(&req) != nil || req.Op != proto.OpBootConfig {
				proto.WriteJSON(c, proto.TypeError, proto.Error{Code: proto.CodeBadRequest, Message: "want {\"op\":\"boot_config\"}"})
				return
			}
			cfg := b.bootCfg
			cfg.UnixNano = time.Now().UnixNano()
			if proto.WriteJSON(c, proto.TypeJSON, cfg) == nil {
				once.Do(func() { l.Close() })
			}
		}()
	}
}

// waitReady pings the guest until it says Ready, the VM exits, or ReadyTimeout passes.
func (b *box) waitReady(ctx context.Context, m vmm.Machine, g agentrpc.Guest) error {
	deadline := time.NewTimer(b.d.opts.ReadyTimeout)
	defer deadline.Stop()
	console := m.ConsolePath()
	if console == "" {
		console = filepath.Join(b.dir, "console.log")
	}
	var last error
	for {
		pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		p, err := g.Ping(pctx)
		cancel()
		if err == nil && p.Ready {
			return nil
		}
		if err != nil {
			last = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.Done():
			return &guestError{msg: "the VM exited while booting: read " + console, detail: fmt.Sprint(m.Err())}
		case <-deadline.C:
			why := "it never said ready"
			if last != nil {
				why = last.Error()
			}
			return &guestError{msg: fmt.Sprintf("the guest did not come up within %s: read %s", b.d.opts.ReadyTimeout, console), detail: why}
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// watchMachine fails the box when its VM dies on its own.
func (b *box) watchMachine(m vmm.Machine) {
	select {
	case <-b.stopCh:
	case <-m.Done():
		st := b.state()
		if st == api.StateRunning || st == api.StatePaused {
			console := m.ConsolePath()
			if console == "" {
				console = filepath.Join(b.dir, "console.log")
			}
			b.teardown(context.Background(), "the VM exited on its own: read "+console, fmt.Sprint(m.Err()), false, true)
		}
	}
}

func (b *box) onTimeout() {
	b.mu.Lock()
	t := b.info.Limits.Timeout
	b.mu.Unlock()
	b.stop(context.Background(), fmt.Sprintf("timeout: the box reached its %s limit (raise it with --timeout)", time.Duration(t)), false)
}

// containmentLoop polls the signer's containment state: held pauses the VM, quarantined kills it.
func (b *box) containmentLoop() {
	t := time.NewTicker(b.d.opts.ContainmentPoll)
	defer t.Stop()
	for {
		select {
		case <-b.stopCh:
			return
		case <-t.C:
			b.checkContainment()
		case ack := <-b.pollNow:
			b.checkContainment()
			close(ack)
		}
	}
}

func (b *box) checkContainment() {
	b.mu.Lock()
	run, m, st := b.run, b.machine, b.info.State
	b.mu.Unlock()
	if run == nil || m == nil || (st != api.StateRunning && st != api.StatePaused) {
		return
	}
	ctx, cancel := context.WithTimeout(b.d.ctx, 10*time.Second)
	defer cancel()
	c, err := run.Contained(ctx)
	if err != nil {
		b.mu.Lock()
		first := !b.signerTrouble
		b.signerTrouble = true
		b.mu.Unlock()
		if first {
			b.event(api.EventSignerProblem, "lifecycle", "containment check failed: "+err.Error()+
				" (every decision fails closed until the signer answers)", nil)
		}
		return
	}
	b.mu.Lock()
	b.signerTrouble = false
	b.mu.Unlock()
	if c.Contained && c.State == "quarantined" {
		b.event(api.EventContained, "lifecycle", "Tracekit quarantined the run: killing the VM",
			map[string]any{"state": c.State, "incident_id": c.IncidentID, "reason": c.Reason})
		b.observe(tracekit.SourceContained, trustedObs, map[string]any{"state": c.State, "incident_id": c.IncidentID})
		b.stop(context.Background(), fmt.Sprintf("contained: Tracekit quarantined the run (incident %s)", c.IncidentID), true)
		// a quarantined job applies nothing: close its run now
		if err := b.closeRun(context.Background(), "quarantine"); err != nil {
			b.event(api.EventSignerProblem, "lifecycle", "could not close the Tracekit run: "+err.Error(), nil)
		}
		return
	}
	// pause and resume decide on the state as it is now, under ctlMu, so a box that started stopping meanwhile is
	// never paused under its stop or brought back to running
	b.ctlMu.Lock()
	b.mu.Lock()
	st, held := b.info.State, b.heldPaused
	b.mu.Unlock()
	switch {
	case c.Contained && st == api.StateRunning:
		if err := m.Pause(ctx); err != nil {
			b.ctlMu.Unlock()
			b.event(api.EventContained, "lifecycle", "Tracekit holds the run but pausing failed ("+err.Error()+"): killing the VM", nil)
			b.stop(context.Background(), "contained: held by Tracekit and the VM could not be paused", true)
			return
		}
		b.mu.Lock()
		b.info.State = api.StatePaused
		b.heldPaused = true
		b.mu.Unlock()
		b.ctlMu.Unlock()
		b.persist()
		b.event(api.EventContained, "lifecycle", "Tracekit holds the run: VM paused",
			map[string]any{"state": "held", "incident_id": c.IncidentID, "reason": c.Reason})
		b.observe(tracekit.SourceContained, trustedObs, map[string]any{"state": "held", "incident_id": c.IncidentID})
	case !c.Contained && st == api.StatePaused && held:
		if err := m.Resume(ctx); err != nil {
			b.ctlMu.Unlock()
			b.event(api.EventContained, "lifecycle", "the hold was released but resuming failed: "+err.Error(), nil)
			return
		}
		b.mu.Lock()
		b.info.State = api.StateRunning
		b.heldPaused = false
		b.mu.Unlock()
		b.ctlMu.Unlock()
		b.persist()
		b.event(api.EventContained, "lifecycle", "Tracekit released the hold: VM resumed", map[string]any{"state": ""})
		b.observe(tracekit.SourceContained, trustedObs, map[string]any{"state": "", "incident_id": c.IncidentID})
	default:
		b.ctlMu.Unlock()
	}
}

// How long stop gives running commands to end after SIGTERM (then SIGKILL) before it takes the diff.
var (
	execTermGrace = 3 * time.Second
	execKillGrace = 2 * time.Second
)

// stop brings a box down: running commands are signalled and the diff is saved first (unless kill or paused), then
// the guest and the VM are shut down, the proxy closed and the stop recorded. Idempotent; waits for the box to be
// down. Once started, a stop runs to the end even if ctx ends (its steps have their own timeouts).
func (b *box) stop(ctx context.Context, reason string, kill bool) {
	b.ctlMu.Lock()
	b.mu.Lock()
	st := b.info.State
	switch st {
	case api.StateCreating:
		if b.stopReason == "" {
			b.stopReason = reason
		}
		cancel := b.bootCancel
		b.mu.Unlock()
		b.ctlMu.Unlock()
		if cancel != nil {
			cancel()
		}
		b.waitDone(ctx)
		return
	case api.StateRunning, api.StatePaused:
		b.info.State = api.StateStopping
		b.mu.Unlock()
		b.ctlMu.Unlock()
	case api.StateStopping:
		b.mu.Unlock()
		b.ctlMu.Unlock()
		b.waitDone(ctx)
		return
	default:
		b.mu.Unlock()
		b.ctlMu.Unlock()
		return
	}
	b.persist()
	sctx := context.WithoutCancel(ctx)
	switch {
	case kill:
		b.diffNotSaved("the box was killed (--kill or containment), so its workspace diff was not saved")
	case st == api.StatePaused:
		b.diffNotSaved("the VM was paused (held by Tracekit) when it stopped, so its workspace diff was not saved")
	default:
		b.endExecs()
		b.saveDiff(sctx)
	}
	b.teardown(sctx, reason, "", kill, false)
}

// endExecs asks the box's running commands to end (SIGTERM, then SIGKILL) so the diff is not taken from files they
// are still writing.
func (b *box) endExecs() {
	b.mu.Lock()
	var running []*execSession
	for s := range b.sessions {
		if s.started.Load() && !isClosed(s.execDone) {
			running = append(running, s)
		}
	}
	b.mu.Unlock()
	if len(running) == 0 {
		return
	}
	b.event(api.EventBoxStopped, "lifecycle", fmt.Sprintf("stopping: sent SIGTERM to %d running commands", len(running)), nil)
	for _, sig := range []string{"SIGTERM", "SIGKILL"} {
		grace := execTermGrace
		if sig == "SIGKILL" {
			grace = execKillGrace
		}
		var left []*execSession
		for _, s := range running {
			if !isClosed(s.execDone) {
				select {
				case s.sigs <- sig:
				default:
				}
				left = append(left, s)
			}
		}
		if len(left) == 0 {
			return
		}
		t := time.NewTimer(grace)
		waited := true
		for _, s := range left {
			select {
			case <-s.execDone:
			case <-t.C:
				waited = false
			}
			if !waited {
				break
			}
		}
		t.Stop()
		if waited {
			return
		}
	}
	b.event(api.EventBoxStopped, "lifecycle", "stopping: some commands did not end after SIGKILL; the diff is taken anyway", nil)
}

func (b *box) waitDone(ctx context.Context) {
	select {
	case <-b.done:
	case <-ctx.Done():
	}
}

// diffNotSaved records why a box has no saved diff: in box.json (DiffError, shown by `tkbox diff` and `tkbox apply`),
// in events.ndjson and loudly in the daemon log.
func (b *box) diffNotSaved(why string) {
	b.mu.Lock()
	if b.info.DiffSaved || b.info.DiffError != "" {
		b.mu.Unlock()
		return
	}
	b.info.DiffError = why
	b.mu.Unlock()
	b.persist()
	b.event(api.EventBoxStopped, "lifecycle", "diff not saved: "+why, nil)
}

// diffExcludeDirs are dir names left out of every workspace diff: generated trees (dependencies, caches) that would
// blow the 64 MiB cap and that nobody applies by hand.
var diffExcludeDirs = []string{"node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
	".gradle", ".next", ".cache"}

// guestDiff asks the guest for the workspace patch without diffExcludeDirs. The guest's summary is not used: the
// host builds its own from the patch (summarize).
func guestDiff(ctx context.Context, g agentrpc.Guest, w io.Writer) error {
	_, err := g.DiffWith(ctx, proto.DiffRequest{Op: proto.OpDiff, MaxBytes: maxDiffBytes, ExcludeDirs: diffExcludeDirs}, w)
	return err
}

func isTooLarge(err error) bool {
	var pe *proto.Error
	return errors.Is(err, errDiffTooLarge) || (errors.As(err, &pe) && pe.Code == proto.CodeTooLarge)
}

// saveDiff writes the guest's workspace patch to diff.patch and the host's summary of it to diff.json. A failure is
// recorded (diffNotSaved) and the stop goes on.
func (b *box) saveDiff(ctx context.Context) {
	b.mu.Lock()
	g, name := b.guest, b.info.Name
	b.mu.Unlock()
	if g == nil {
		b.diffNotSaved("the guest never came up, so there is no workspace diff")
		return
	}
	dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	tmp := filepath.Join(b.dir, ".diff.patch.tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		b.diffNotSaved("the diff could not be written: " + err.Error())
		return
	}
	err = guestDiff(dctx, g, &limitWriter{w: f, n: maxDiffBytes})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		switch {
		case isTooLarge(err):
			b.diffNotSaved(fmt.Sprintf("the workspace patch was over %d MiB when box %s stopped, so no diff was saved; keep build output and generated files out of /workspace (write them under /tmp) or remove them before stopping", maxDiffBytes>>20, name))
		case errors.Is(dctx.Err(), context.DeadlineExceeded):
			b.diffNotSaved("the guest did not send the workspace diff within 60s, so no diff was saved")
		default:
			b.diffNotSaved("the guest did not send the workspace diff (" + err.Error() + "), so no diff was saved")
		}
		b.d.log.Printf("WARNING: box %s (%s): the workspace diff was NOT saved; nothing can be applied from it", name, b.id)
		return
	}
	if err := os.Rename(tmp, filepath.Join(b.dir, "diff.patch")); err != nil {
		b.diffNotSaved("the diff could not be saved: " + err.Error())
		return
	}
	if patch, err := os.ReadFile(filepath.Join(b.dir, "diff.patch")); err == nil {
		if js, err := json.Marshal(summarize(patch)); err == nil {
			os.WriteFile(filepath.Join(b.dir, "diff.json"), js, 0o600)
		}
	}
	b.mu.Lock()
	b.info.DiffSaved, b.info.DiffError = true, ""
	b.mu.Unlock()
	b.persist()
}

// teardown releases everything a box holds and records why. failed marks it failed instead of stopped. reason is a
// host-side phrase (it is recorded in Tracekit as trusted); detail, which may hold text from the guest or the VM's
// console, goes only to events.ndjson.
func (b *box) teardown(ctx context.Context, reason, detail string, kill, failed bool) {
	b.mu.Lock()
	if b.tearingDown {
		b.mu.Unlock()
		b.waitDone(ctx)
		return
	}
	b.tearingDown = true
	b.mu.Unlock()
	b.stopOnce.Do(func() { close(b.stopCh) })
	b.mu.Lock()
	if b.timer != nil {
		b.timer.Stop()
	}
	m, g, proxy, ls, run := b.machine, b.guest, b.proxy, b.listeners, b.run
	b.listeners = nil
	b.mu.Unlock()
	b.d.expireApprovals(b.id, reason)

	if m != nil {
		select {
		case <-m.Done():
		default:
			if kill {
				m.Kill()
			} else {
				if g != nil {
					gctx, cancel := context.WithTimeout(ctx, 5*time.Second)
					g.Shutdown(gctx)
					cancel()
				}
				sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
				if err := m.Shutdown(sctx); err != nil {
					m.Kill()
				}
				cancel()
			}
			select {
			case <-m.Done():
			case <-time.After(2 * time.Second):
				m.Kill()
			}
		}
	}
	if proxy != nil {
		proxy.Close()
	}
	for _, l := range ls {
		l.Close()
	}
	if failed {
		b.diffNotSaved("the box failed (" + reason + "), so its workspace diff was not saved")
	}
	if run != nil {
		fctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		b.flushObserver(fctx)
		cancel()
		// must-record observes that never reached the signer are recorded as a gap; if even that fails the run is
		// closed now with what was lost as its reason (no apply can then be recorded as if nothing was missing)
		fctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		lostReason := b.recordGaps(fctx, run)
		event := "stopped"
		if failed {
			event = "failed"
		}
		if err := run.Observe(fctx, tracekit.SourceBox, trustedObs, map[string]any{"event": event, "box_id": b.id, "reason": reason}); err != nil {
			b.event(api.EventSignerProblem, "lifecycle", "could not record the stop: "+err.Error(), nil)
			if lostReason != "" {
				lostReason += "; "
			}
			lostReason += "the stop could not be recorded"
		}
		cancel()
		b.mu.Lock()
		b.closeReason = reason
		if lostReason != "" {
			b.closeReason = reason + "; " + lostReason
		}
		b.mu.Unlock()
		if failed || lostReason != "" { // nothing (recordable) left to apply: close now; a stopped box keeps its run open for apply (see closeRun)
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			by := "failed"
			if !failed {
				by = "records lost"
			}
			if err := b.closeRun(cctx, by); err != nil {
				b.event(api.EventSignerProblem, "lifecycle", "could not close the Tracekit run: "+err.Error(), nil)
			}
			cancel()
		}
	}
	b.mu.Lock()
	b.info.StoppedAt = b.d.now().UTC()
	b.info.StopReason = reason
	if failed {
		b.info.State = api.StateFailed
		b.info.Error = reason
	} else {
		b.info.State = api.StateStopped
	}
	b.mu.Unlock()
	b.persist()
	data := map[string]any(nil)
	if detail != "" {
		data = map[string]any{"detail": detail}
	}
	if failed {
		b.event(api.EventBoxFailed, "lifecycle", reason, data)
	} else {
		b.event(api.EventBoxStopped, "lifecycle", "box stopped: "+reason, data)
	}
	b.events.release()
	b.closeDone()
}

// runCloseWait bounds how long closing a run waits for the box's in-flight gated calls to complete.
var runCloseWait = 15 * time.Second

// closeRun closes the box's Tracekit run once, with the reason the box stopped, after the box's in-flight gated
// calls (exec, egress, apply) completed (at most runCloseWait). A stopped box keeps its run open so `tkbox apply`
// records its Write decisions in the same run (one bundle per job); export, rm and daemon shutdown close it. by says
// who closed it ("export", "failed", "quarantine", "shutdown", "rm").
func (b *box) closeRun(ctx context.Context, by string) error {
	b.mu.Lock()
	run := b.run
	if run == nil || b.runClosed {
		b.mu.Unlock()
		return nil
	}
	b.mu.Unlock()
	if !b.calls.wait(runCloseWait) {
		b.event(api.EventSignerProblem, "lifecycle", fmt.Sprintf("closing the Tracekit run while gated calls are still in flight (they did not finish within %s)", runCloseWait), nil)
	}
	b.mu.Lock()
	if b.runClosed {
		b.mu.Unlock()
		return nil
	}
	b.runClosed = true
	reason := b.closeReason
	b.mu.Unlock()
	if reason == "" {
		reason = "box stopped"
	}
	if err := run.Close(ctx, reason); err != nil {
		b.mu.Lock()
		b.runClosed = false
		b.mu.Unlock()
		return err
	}
	b.mu.Lock()
	b.runClosedBy = by
	b.mu.Unlock()
	b.persist()
	return nil
}

// Stop stops a box (see box.stop) and returns it.
func (d *Daemon) Stop(ctx context.Context, ref string, req api.StopRequest) (api.Box, error) {
	b, err := d.lookup(ref)
	if err != nil {
		return api.Box{}, err
	}
	reason := req.Reason
	if reason == "" {
		reason = "stopped by the operator"
		if req.Kill {
			reason = "killed by the operator"
		}
	}
	b.stop(ctx, reason, req.Kill)
	return b.view(), nil
}

// Remove stops a box if it is alive and deletes its state dir.
func (d *Daemon) Remove(ctx context.Context, ref string) error {
	b, err := d.lookup(ref)
	if err != nil {
		return err
	}
	b.stop(ctx, "removed by the operator", false)
	if alive(b.state()) {
		return errf(api.CodeConflict, "try again, or `tkbox stop --kill "+ref+"`", "box %s is still going down", ref)
	}
	if err := b.closeRun(ctx, "rm"); err != nil {
		return errf(api.CodeUnavailable, "check the signer (`tracekit status`) and run `tkbox rm "+ref+"` again",
			"could not close the Tracekit run of box %s: %v", ref, err)
	}
	d.mu.Lock()
	delete(d.boxes, b.id)
	for id, a := range d.approvals {
		if a.box == b {
			delete(d.approvals, id)
		}
	}
	d.mu.Unlock()
	b.events.close()
	if err := os.RemoveAll(b.dir); err != nil {
		return asAPIError(err)
	}
	return nil
}

// caHosts are the hosts a box's CA may impersonate: the bound secrets' hosts and, with inspect all, the allowlist's
// (ports dropped: name constraints have none).
func caHosts(secrets []egress.Secret, allow []string, inspect string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, s := range secrets {
		for _, h := range s.Hosts {
			add(h)
		}
	}
	if inspect == egress.InspectAll {
		for _, a := range allow {
			if h, _, err := net.SplitHostPort(a); err == nil {
				a = h
			}
			add(strings.Trim(a, "[]"))
		}
	}
	return out
}

// hostAddrs is the live view of this host's own addresses the proxy consults on every dial (egress.Config.BlockFunc),
// so an address the host gains after a box started (a new interface, DHCP) is refused too. Re-read at most every 5s;
// a failed re-read keeps the last list.
type hostAddrs struct {
	mu  sync.Mutex
	at  time.Time
	set map[netip.Addr]bool
}

func (h *hostAddrs) blocked(a netip.Addr) (bool, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.set == nil || time.Since(h.at) > 5*time.Second {
		if ps, err := hostPrefixes(); err == nil {
			h.set = make(map[netip.Addr]bool, len(ps))
			for _, p := range ps {
				h.set[p.Addr()] = true
			}
			h.at = time.Now()
		}
	}
	if h.set[a.Unmap()] {
		return true, "an address of this host"
	}
	return false, ""
}

// hostPrefixes are this host's own non-loopback addresses: a guest must not reach host services on them, even on a
// public address. (Loopback is in the proxy's built-in block list, where the test-only --egress-allow-private may
// exempt it.) Without them a box is not started: an empty list would let a guest reach the host's own services.
var hostPrefixes = func() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok || ip.Unmap().IsLoopback() {
			continue
		}
		ip = ip.Unmap()
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out, nil
}
