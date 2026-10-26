package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/assets"
	"github.com/Cygnux-Labs/tracekit-box/internal/daemon"
	"github.com/Cygnux-Labs/tracekit-box/internal/image"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
	"github.com/Cygnux-Labs/tracekit-box/internal/vmm"
)

// cmdDaemon runs the box manager: it checks the host, connects to the signer (unless --unrecorded), and serves the
// API until SIGINT/SIGTERM, then stops every box.
func cmdDaemon(args []string, env *cliEnv) error {
	fs, sock := newFlags("daemon", env)
	stateDir := fs.String("state-dir", defaultStateDir(), "state dir (images, boxes, run/tkbox.sock)")
	signer := fs.String("signer", "", "Tracekit signer socket (default: $TRACEKIT_SIGNER, /etc/tracekit/client.json, or the dev signer)")
	unrecorded := fs.Bool("unrecorded", false, "run boxes that record NOTHING in Tracekit (no signer needed; boxes can't be exported)")
	tracekitBin := fs.String("tracekit-bin", "", "the tracekit CLI used by export (default: tracekit in PATH)")
	fcBin := fs.String("firecracker", "", "firecracker binary (default: the pinned release, downloaded and verified)")
	kernel := fs.String("kernel", "", "guest kernel vmlinux (default: the pinned kernel, downloaded and verified)")
	guestDir := fs.String("guest-dir", "", "dir holding tkbox-guest-linux-<arch> (default: next to this binary)")
	maxBoxes := fs.Int("max-boxes", daemon.DefaultMaxBoxes, "boxes alive at once")
	approvalTimeout := fs.Duration("approval-timeout", daemon.DefaultApprovalTimeout, "how long egress waits for a person to run tkbox approve (1s..4m)")
	var allowPrivate stringList
	allowPrivate.split = true
	fs.Var(&allowPrivate, "egress-allow-private", "TEST ONLY, DANGEROUS: a private CIDR boxes may reach (repeatable)")
	var egressBlock stringList
	egressBlock.split = true
	fs.Var(&egressBlock, "egress-block", "a CIDR no box may reach, e.g. this host's NAT'd public IP on a cloud VM (repeatable)")
	upstreamCA := fs.String("upstream-ca", "", "TEST ONLY, DANGEROUS: PEM file of roots trusted for upstream TLS instead of the system's")
	if pos, err := parseAll(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("unexpected argument %q", pos[0])
	}
	logger := log.New(env.stderr, "tkbox: ", log.LstdFlags)
	if !filepath.IsAbs(*stateDir) {
		abs, err := filepath.Abs(*stateDir)
		if err != nil {
			return err
		}
		*stateDir = abs
	}
	if *maxBoxes < 1 || *maxBoxes > 1024 {
		return usagef("--max-boxes %d: use 1..1024", *maxBoxes)
	}
	if *approvalTimeout < time.Second || *approvalTimeout > 4*time.Minute {
		return usagef("--approval-timeout %s: use 1s..4m (a connection waits for its approval at most that long plus 30s)", *approvalTimeout)
	}
	// what the flags say, taken once: daemonOptions builds the Options from it once the host is set up
	setup := daemonSetup{stateDir: *stateDir, unrecorded: *unrecorded, maxBoxes: *maxBoxes, approvalTimeout: *approvalTimeout,
		egressBlock: egressBlock.vals, allowPrivate: allowPrivate.vals, upstreamCA: *upstreamCA, logger: logger}
	// --egress-block is checked now, so a bad value fails before anything touches the host
	_, err := parseEgressBlock(setup.egressBlock)
	if err != nil {
		return err
	}
	if daemonFlagsHook != nil {
		if err := daemonFlagsHook(setup); err != nil {
			return err
		}
	}
	socketSet := false
	fs.Visit(func(f *flag.Flag) { socketSet = socketSet || f.Name == "socket" })
	if err = os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	// a host without KVM fails here, before anything is downloaded
	if err := checkKVM(); err != nil {
		return fmt.Errorf("this host can't run boxes: %w", err)
	}
	// claim the socket first: a second daemon fails here, before downloading anything
	sockPath := filepath.Join(*stateDir, "run", "tkbox.sock")
	if socketSet {
		if sockPath, err = filepath.Abs(*sock); err != nil {
			return err
		}
	}
	l, err := daemon.ListenSocket(sockPath)
	if err != nil {
		return err
	}
	defer l.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// the signer comes before any download: no signer means no box, and saying so must not wait on the network
	var tk tracekit.Client
	if *unrecorded {
		logger.Printf("WARNING: --unrecorded: boxes record NOTHING in Tracekit and cannot be exported; the allowlist and Box approvals still apply")
	} else {
		noSigner := func(err error) error {
			var u *tracekit.Unavailable
			if errors.As(err, &u) {
				err = u.Err // "no signer answering at …", without the wrapper's own words
			}
			return fmt.Errorf("the daemon needs a Tracekit signer: %v\nstart one with `tracekit up`, or pass --unrecorded to run boxes that record nothing", err)
		}
		dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		tk, err = tracekit.Dial(dctx, tracekit.Options{Signer: *signer, TracekitBin: *tracekitBin})
		cancel()
		if err != nil {
			return noSigner(err)
		}
		defer tk.Close()
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		st, err := tk.Status(sctx)
		cancel()
		if err != nil {
			return noSigner(err)
		}
		logger.Printf("signer %s %s at %s (rpc %d, identity %s)", st.SignerName, st.SignerVersion, st.Where, st.RPCVersion, st.Identity)
	}

	arch := runtime.GOARCH
	assetDir := filepath.Join(*stateDir, "images", "assets")
	if *fcBin == "" {
		if *fcBin, err = ensureAsset(ctx, assetDir, arch, assets.Firecracker, logger); err != nil {
			return err
		}
	}
	if *kernel == "" {
		if *kernel, err = ensureAsset(ctx, assetDir, arch, assets.Kernel, logger); err != nil {
			return err
		}
	}
	launcher := vmm.NewFirecracker(vmm.FirecrackerOptions{Binary: *fcBin})
	if err := launcher.Check(); err != nil {
		return fmt.Errorf("this host can't run boxes: %w", err)
	}
	if *guestDir == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if exe, err = filepath.EvalSymlinks(exe); err != nil {
			return err
		}
		*guestDir = filepath.Dir(exe)
	}
	guestBinary := func(a string) (string, error) {
		p := filepath.Join(*guestDir, "tkbox-guest-linux-"+a)
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("no guest agent at %s: build it with `make guest` or pass --guest-dir", p)
		}
		return p, nil
	}
	if _, err := guestBinary(arch); err != nil {
		return err
	}
	builder, err := image.NewBuilder(image.Options{CacheDir: filepath.Join(*stateDir, "images"), GuestBinary: guestBinary})
	if err != nil {
		return fmt.Errorf("image builder: %w", err)
	}

	setup.kernel, setup.launcher, setup.builder, setup.tk = *kernel, launcher, builder, tk
	opts, err := daemonOptions(setup)
	if err != nil {
		return err
	}
	d, err := daemon.New(opts)
	if err != nil {
		return err
	}
	logger.Printf("tkbox %s serving on %s (state %s, max %d boxes)", version, sockPath, *stateDir, *maxBoxes)
	serveErr := d.ServeListener(ctx, l)
	logger.Printf("stopping every box…")
	sctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d.Shutdown(sctx)
	return serveErr
}

// daemonSetup is what daemonOptions builds the daemon's Options from: flag values as cmdDaemon parsed them (the egress
// ones as given) and what it set up from them.
type daemonSetup struct {
	stateDir, kernel, upstreamCA string
	unrecorded                   bool
	maxBoxes                     int
	approvalTimeout              time.Duration
	egressBlock, allowPrivate    []string
	launcher                     vmm.Launcher
	builder                      image.Builder
	tk                           tracekit.Client
	logger                       *log.Logger
}

// daemonFlagsHook, when set (by tests), sees the setup cmdDaemon took from its flags, before anything touches the
// host; an error it returns ends the command.
var daemonFlagsHook func(daemonSetup) error

// daemonOptions builds the daemon's Options. It parses the egress flags: --egress-block, and the test-only
// --egress-allow-private and --upstream-ca, whose warnings it logs.
func daemonOptions(s daemonSetup) (daemon.Options, error) {
	blocked, err := parseEgressBlock(s.egressBlock)
	if err != nil {
		return daemon.Options{}, err
	}
	var prefixes []netip.Prefix
	for _, c := range s.allowPrivate {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return daemon.Options{}, usagef("--egress-allow-private %q: want a CIDR like 10.0.0.0/8", c)
		}
		prefixes = append(prefixes, p)
		s.logger.Printf("WARNING: --egress-allow-private %s: boxes may reach that private range (test only)", p)
	}
	var roots *x509.CertPool
	if s.upstreamCA != "" {
		pem, err := os.ReadFile(s.upstreamCA)
		if err != nil {
			return daemon.Options{}, err
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return daemon.Options{}, fmt.Errorf("--upstream-ca %s: no PEM certificates in it", s.upstreamCA)
		}
		s.logger.Printf("WARNING: --upstream-ca %s replaces the system roots for upstream TLS (test only)", s.upstreamCA)
	}
	return daemon.Options{
		StateDir: s.stateDir, Launcher: s.launcher, Builder: s.builder, Tracekit: s.tk, Unrecorded: s.unrecorded,
		KernelPath: s.kernel, Arch: runtime.GOARCH, Version: version, ApprovalTimeout: s.approvalTimeout, MaxBoxes: s.maxBoxes,
		EgressAllowPrivate: prefixes, EgressUpstreamRoots: roots, EgressBlock: blocked, Logger: s.logger,
		// GuestClient, NewProxy and Gate default to agentrpc.New, egress.New and tracekit.Gate
	}, nil
}

// parseEgressBlock parses --egress-block values: CIDRs (or single addresses) no box may reach.
func parseEgressBlock(vals []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, v := range vals {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			a, aerr := netip.ParseAddr(v)
			if aerr != nil || a.Zone() != "" {
				return nil, usagef("--egress-block %q: want a CIDR like 203.0.113.7/32 or an address", v)
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// checkKVM fails fast on a host that can't run Firecracker.
func checkKVM() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("tkbox daemon runs on Linux with /dev/kvm, not %s (use a Linux VM such as Lima)", runtime.GOOS)
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("/dev/kvm is not usable (%v): enable KVM (nested virtualization on a VM) and add this user to the kvm group", err)
	}
	return f.Close()
}

func ensureAsset(ctx context.Context, dir, arch string, pick func(string) (assets.Asset, error), logger *log.Logger) (string, error) {
	a, err := pick(arch)
	if err != nil {
		return "", fmt.Errorf("no pinned asset for %s: %w (pass --firecracker and --kernel)", arch, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p, err := assets.Ensure(ctx, dir, a)
	if err != nil {
		return "", fmt.Errorf("fetch %s %s: %w (pass --firecracker/--kernel to use local files)", a.Name, a.Version, err)
	}
	logger.Printf("%s %s: %s", a.Name, a.Version, p)
	return p, nil
}
