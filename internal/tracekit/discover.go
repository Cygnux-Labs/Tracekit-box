package tracekit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// Signer discovery, as the 1.4.2 SDK finds its signer (sdk/client.py _default_signer, sdk/autospawn.py), without ever
// starting one: $TRACEKIT_SIGNER, else the signer the root-owned /etc/tracekit/client.json names (where a conflicting
// $TRACEKIT_SIGNER is refused), else the same-user dev signer's socket in its runtime dir.

var (
	systemConfigPath = "/etc/tracekit/client.json" // tracekit/client.py SYSTEM_CONFIG
	systemSignerYAML = "/etc/tracekit/signer.yaml" // tracekit/install.py V2_CONFIG: the system signer's config
)

const (
	devSock     = "signer.sock"
	devLock     = "signer.lock"
	devEndpoint = "endpoint.json"
)

// signerSource says how the signer was found; Export reads the store of the same signer.
type signerSource string

const (
	sourceOption signerSource = "option"
	sourceEnv    signerSource = "env"
	sourceSystem signerSource = "system"
	sourceDev    signerSource = "dev"
)

type discovered struct {
	path   string
	source signerSource
	alt    string // dev: the sibling runtime dir's socket, used when the first one serves another HOME's data dir
}

// systemConfig is the root-owned client config, nil when there is none; any doubt about it is an error (fail closed),
// as tracekit/client.py system_config.
func systemConfig() (map[string]any, error) {
	st, err := os.Stat(systemConfigPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read: %w", systemConfigPath, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 || st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s must be owned by root and not group- or world-writable", systemConfigPath)
	}
	data, err := os.ReadFile(systemConfigPath)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read: %w", systemConfigPath, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil || cfg == nil {
		return nil, fmt.Errorf("%s must hold a JSON object", systemConfigPath)
	}
	return cfg, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// discoverSigner finds the signer's socket for opts.
func discoverSigner(opts Options) (discovered, error) {
	sys, err := systemConfig()
	if err != nil {
		return discovered{}, &Unavailable{Err: err}
	}
	var sysSigner string
	if sys != nil {
		if v, ok := sys["signer"]; ok {
			s, isStr := v.(string)
			if !isStr || s == "" {
				return discovered{}, &Unavailable{Err: fmt.Errorf("%s: signer must be a socket path", systemConfigPath)}
			}
			sysSigner = s
		}
	}
	var d discovered
	env := os.Getenv("TRACEKIT_SIGNER")
	switch {
	case opts.Signer != "":
		// the operator named it; still never a signer other than the one the root-owned config pins
		if sysSigner != "" && opts.Signer != sysSigner {
			return d, &Unavailable{Err: fmt.Errorf("signer %s is not the system signer %s that %s names; refused",
				clip(opts.Signer, 256), sysSigner, systemConfigPath)}
		}
		d = discovered{path: opts.Signer, source: sourceOption}
		if sysSigner != "" {
			d.source = sourceSystem
		}
	case sysSigner != "":
		if env != "" && env != sysSigner {
			return d, &Unavailable{Err: fmt.Errorf("TRACEKIT_SIGNER=%s is not the system signer %s; refused",
				clip(env, 256), sysSigner)}
		}
		d = discovered{path: sysSigner, source: sourceSystem}
	case env != "":
		d = discovered{path: env, source: sourceEnv}
	case sys != nil:
		return d, &Unavailable{Err: fmt.Errorf("system mode (%s) names no signer and TRACEKIT_SIGNER is not set",
			systemConfigPath)}
	default:
		dir, alt, err := devSignerDir()
		if err != nil {
			return d, &Unavailable{Err: fmt.Errorf("no signer: TRACEKIT_SIGNER is not set, there is no system signer, "+
				"and no same-user dev signer (%v); start one with `tracekit up`", err)}
		}
		d = discovered{path: filepath.Join(dir, devSock), source: sourceDev}
		if alt != "" {
			d.alt = filepath.Join(alt, devSock)
		}
	}
	if strings.Contains(d.path, "://") {
		return d, &Unavailable{Err: fmt.Errorf("Tracekit Box reaches its signer over a Unix socket only; %s is not "+
			"one", clip(d.path, 256))}
	}
	return d, nil
}

// devRuntimeDir is autospawn.runtime_dir: $TRACEKIT_RUNTIME_DIR, else ~/Library/Application Support/tracekit/run on
// macOS (/tmp/tk-<uid> when the socket path would pass macOS's 104-byte cap), else $XDG_RUNTIME_DIR/tracekit, else
// /tmp/tracekit-<uid>.
func devRuntimeDir() (string, error) {
	if d := os.Getenv("TRACEKIT_RUNTIME_DIR"); d != "" {
		return d, nil
	}
	if runtime.GOOS == "darwin" {
		home, err := homeDir()
		if err != nil {
			return "", err
		}
		d := home + "/Library/Application Support/tracekit/run"
		if len(d+"/"+devSock) > 103 {
			d = fmt.Sprintf("/tmp/tk-%d", os.Getuid())
		}
		return d, nil
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		return strings.TrimRight(xdg, "/") + "/tracekit", nil
	}
	return fmt.Sprintf("/tmp/tracekit-%d", os.Getuid()), nil
}

// homeDir is Python's expanduser("~"): $HOME without its trailing slash.
func homeDir() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if t := strings.TrimRight(h, "/"); t != "" {
		return t, nil
	}
	return h, nil
}

// devDataDir is autospawn.data_dir: the dev signer's keys and store for this HOME.
func devDataDir() (string, error) {
	home, err := homeDir()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "darwin" {
		return home + "/Library/Application Support/tracekit/data", nil
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "tracekit"), nil
	}
	return home + "/.local/share/tracekit", nil
}

// privateDir checks a runtime dir is a directory owned by us with mode 0700 (autospawn._private, never creating it).
func privateDir(d string) error {
	st, err := os.Lstat(d)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || !ok || int(sys.Uid) != os.Getuid() || st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be a directory owned by you with mode 0700", d)
	}
	return nil
}

// devSignerDir is autospawn.signer_dir(create=False): the per-user runtime dir, or its sibling
// "<dir>-<12 hex of sha256(realpath(data dir))>" while this data dir's signer runs there or the per-user one's
// serves another data dir. alt is that sibling when the per-user dir was chosen.
func devSignerDir() (dir, alt string, err error) {
	d, err := devRuntimeDir()
	if err != nil {
		return "", "", err
	}
	if err := privateDir(d); err != nil {
		return "", "", err
	}
	data, err := devDataDir()
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(realPath(data)))
	side := d + "-" + hex.EncodeToString(sum[:])[:12]
	if lockHeld(filepath.Join(side, devLock)) || theirs(d, data) {
		if err := privateDir(side); err != nil {
			return "", "", err
		}
		return side, "", nil
	}
	return d, side, nil
}

// theirs is autospawn._theirs: whether the live dev signer of runtime dir d serves another data dir than ours.
func theirs(d, data string) bool {
	raw, err := os.ReadFile(filepath.Join(d, devEndpoint))
	if err != nil {
		return false
	}
	var ep map[string]any
	if json.Unmarshal(raw, &ep) != nil || ep == nil || !lockHeld(filepath.Join(d, devLock)) {
		return false
	}
	if v, ok := ep["data_dir"]; ok {
		s, _ := v.(string)
		return realPath(s) != realPath(data)
	}
	return !lockHeld(filepath.Join(data, "store", "lock"))
}

// lockHeld is autospawn._held: whether some process holds the flock on path. Any doubt reads as held, as there.
func lockHeld(path string) bool {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}

// realPath is Python's os.path.realpath (non-strict): symlinks resolved as far as the path exists.
func realPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	rest := ""
	cur := abs
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			if rest == "" {
				return r
			}
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs
		}
		if rest == "" {
			rest = filepath.Base(cur)
		} else {
			rest = filepath.Join(filepath.Base(cur), rest)
		}
		cur = parent
	}
}
