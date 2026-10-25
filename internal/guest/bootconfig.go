package guest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// bootConfigWait is how long the guest keeps asking the host for its boot config before failing closed.
const bootConfigWait = 10 * time.Second

// systemCABundles are the image CA bundles the guest knows, in order of preference.
var systemCABundles = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
	"/etc/ssl/cert.pem",                  // Alpine, macOS-style
}

// FetchBootConfig asks the host for the boot config on fresh connections from dial, retrying for up to wait.
func FetchBootConfig(ctx context.Context, dial func(ctx context.Context) (net.Conn, error), wait time.Duration) (*proto.BootConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var last error
	for {
		cfg, err := fetchOnce(ctx, dial)
		if err == nil {
			return cfg, nil
		}
		last = err
		var pe *proto.Error
		if errors.As(err, &pe) {
			return nil, err // the host answered and refused: retrying will not help
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("no boot config from the host after %v: %w", wait, last)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func fetchOnce(ctx context.Context, dial func(ctx context.Context) (net.Conn, error)) (*proto.BootConfig, error) {
	c, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if err := proto.WriteJSON(c, proto.TypeJSON, proto.BootConfigRequest{Op: proto.OpBootConfig}); err != nil {
		return nil, err
	}
	f, err := proto.ReadFrame(c)
	if err != nil {
		return nil, err
	}
	switch f.Type {
	case proto.TypeJSON:
		var cfg proto.BootConfig
		if err := f.Decode(&cfg); err != nil {
			return nil, err
		}
		return &cfg, nil
	case proto.TypeError:
		return nil, f.AsError()
	}
	return nil, fmt.Errorf("boot config: unexpected frame type %d", f.Type)
}

// CheckBootConfig validates cfg against the box id the kernel command line named and fills defaults.
func CheckBootConfig(cfg *proto.BootConfig, cmdlineID string) error {
	if cfg.Version != proto.Version {
		return fmt.Errorf("boot config version %d, this guest speaks %d", cfg.Version, proto.Version)
	}
	if cmdlineID != "" && cfg.BoxID != cmdlineID {
		return fmt.Errorf("boot config is for box %q, kernel command line says %q", cfg.BoxID, cmdlineID)
	}
	if cfg.ProxyListen == "" {
		cfg.ProxyListen = proto.DefaultProxyListen
	}
	if cfg.CABundlePath == "" {
		cfg.CABundlePath = proto.DefaultCABundlePath
	}
	if !filepath.IsAbs(cfg.CABundlePath) {
		return fmt.Errorf("ca_bundle_path %q is not absolute", cfg.CABundlePath)
	}
	if w := cfg.Workspace; w != nil {
		if w.Path == "" {
			w.Path = proto.DefaultWorkspacePath
		}
		if !filepath.IsAbs(w.Path) || filepath.Clean(w.Path) == "/" {
			return fmt.Errorf("workspace path %q must be an absolute directory below /", w.Path)
		}
		if w.BaseDevice == "" || w.UpperDevice == "" {
			return errors.New("workspace needs base_device and upper_device")
		}
	}
	return nil
}

// InstallCA writes bundlePath = the first existing system bundle + caPEM, and appends caPEM to every system bundle
// that exists (once per real file: bundles are often symlinks to each other).
func InstallCA(caPEM, bundlePath string, systemBundles []string) error {
	pem := strings.TrimSpace(caPEM)
	var bundle []byte
	for _, p := range systemBundles {
		if b, err := os.ReadFile(p); err == nil {
			bundle = b
			break
		}
	}
	out := append([]byte{}, bundle...)
	if pem != "" {
		if len(out) > 0 && !bytes.HasSuffix(out, []byte("\n")) {
			out = append(out, '\n')
		}
		out = append(out, pem+"\n"...)
	}
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(bundlePath, out, 0o644); err != nil {
		return err
	}
	if pem == "" {
		return nil
	}
	done := map[string]bool{}
	for _, p := range systemBundles {
		real, err := filepath.EvalSymlinks(p)
		if err != nil || done[real] {
			continue
		}
		done[real] = true
		b, err := os.ReadFile(real)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(pem)) {
			continue
		}
		if len(b) > 0 && !bytes.HasSuffix(b, []byte("\n")) {
			b = append(b, '\n')
		}
		b = append(b, pem+"\n"...)
		if err := writeFileAtomic(real, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// WriteHosts makes /etc/hosts resolve localhost and the box hostname to loopback, keeping other lines.
func WriteHosts(path, hostname string) error {
	old, _ := os.ReadFile(path)
	var b strings.Builder
	b.WriteString("127.0.0.1\tlocalhost " + hostname + "\n::1\tlocalhost ip6-localhost ip6-loopback\n")
	for _, line := range strings.Split(string(old), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "127.0.0.1" || f[0] == "::1" {
			continue
		}
		b.WriteString(line + "\n")
	}
	return writeFileAtomic(path, []byte(b.String()), 0o644)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tkbox-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// CmdlineValue returns key's value from a kernel command line.
func CmdlineValue(cmdline, key string) string {
	for _, f := range strings.Fields(cmdline) {
		if k, v, ok := strings.Cut(f, "="); ok && k == key {
			return v
		}
	}
	return ""
}
