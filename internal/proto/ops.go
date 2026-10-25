package proto

import "fmt"

// Operations on PortAgent. The first frame of every connection is a TypeJSON request whose "op" names one of these.
const (
	OpPing      = "ping"
	OpExec      = "exec"
	OpReadFile  = "read_file"
	OpWriteFile = "write_file"
	OpStat      = "stat"
	OpDiff      = "diff"
	OpShutdown  = "shutdown"
)

// OpBootConfig is the only operation on PortConfig: guest → host, answered with one TypeJSON BootConfig frame.
const OpBootConfig = "boot_config"

// Version is the protocol version both sides report in ping and boot_config.
const Version = 1

// Header is decoded first to route a request; the full frame is then decoded into the op's request type.
type Header struct {
	Op string `json:"op"`
}

// Exchanges (→ host to guest, ← guest to host):
//
//	ping:       → PingRequest                                  ← TypeJSON PingResponse
//	exec:       → ExecRequest, [TypeStdin…, TypeStdinEOF], [TypeSignal…]
//	            ← TypeStdout/TypeStderr…, then TypeExit ExitStatus | TypeError
//	read_file:  → ReadFileRequest                              ← TypeJSON FileInfo, TypeStdout…, TypeExit | TypeError
//	write_file: → WriteFileRequest, TypeStdin…, TypeStdinEOF    ← TypeExit | TypeError
//	stat:       → StatRequest                                  ← TypeJSON FileInfo | TypeError
//	diff:       → DiffRequest                                  ← TypeJSON DiffSummary, TypeStdout… (patch), TypeExit | TypeError
//	shutdown:   → ShutdownRequest                              ← TypeExit, then the guest syncs, unmounts and powers off
//	boot_config (PortConfig, guest → host): → BootConfigRequest ← TypeJSON BootConfig | TypeError

type PingRequest struct {
	Op string `json:"op"`
}

type PingResponse struct {
	Version  int    `json:"version"`
	BoxID    string `json:"box_id"`
	UptimeMS int64  `json:"uptime_ms"`
	Ready    bool   `json:"ready"` // boot config applied, workspace mounted, forwarder listening
}

type ExecRequest struct {
	Op        string   `json:"op"`
	Argv      []string `json:"argv"`                 // argv[0] is looked up in PATH of the merged env
	Env       []string `json:"env,omitempty"`        // KEY=VALUE; overrides BootConfig.Env for this process
	Cwd       string   `json:"cwd,omitempty"`        // default BootConfig.Workspace.Path, else "/"
	UID       uint32   `json:"uid,omitempty"`        // default 0 (root inside the VM; the VM is the boundary)
	GID       uint32   `json:"gid,omitempty"`        // default 0
	TimeoutMS int64    `json:"timeout_ms,omitempty"` // 0: BootConfig.Limits.ExecTimeoutMS; on expiry the process group gets SIGKILL
	Stdin     bool     `json:"stdin,omitempty"`      // the host sends TypeStdin frames ending with TypeStdinEOF; else stdin is /dev/null
}

// ExitStatus ends a successful exchange. For exec, Code is the process's exit code (-1 when killed by a signal).
type ExitStatus struct {
	Code       int    `json:"code"`
	Signal     string `json:"signal,omitempty"`      // e.g. "SIGKILL" when killed by a signal
	TimedOut   bool   `json:"timed_out,omitempty"`   // killed because TimeoutMS passed
	DurationMS int64  `json:"duration_ms,omitempty"` // wall time of the process
	Truncated  bool   `json:"truncated,omitempty"`   // output beyond BootConfig.Limits.MaxOutputBytes was dropped
}

// Signal asks the guest to deliver a signal to a running exec's process group.
type Signal struct {
	Signal string `json:"signal"` // "SIGINT", "SIGTERM", "SIGKILL", "SIGHUP", "SIGQUIT"
}

type ReadFileRequest struct {
	Op       string `json:"op"`
	Path     string `json:"path"`                // absolute path in the guest
	MaxBytes int64  `json:"max_bytes,omitempty"` // 0: 64 MiB; a larger file is an error with CodeTooLarge
}

type WriteFileRequest struct {
	Op   string `json:"op"`
	Path string `json:"path"`           // absolute path in the guest; parent dirs are created (0755)
	Mode uint32 `json:"mode,omitempty"` // permission bits; 0: 0644
}

type StatRequest struct {
	Op   string `json:"op"`
	Path string `json:"path"`
}

type FileInfo struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"` // Go fs.FileMode bits
	IsDir   bool   `json:"is_dir"`
	ModTime int64  `json:"mod_time"` // unix seconds
}

type DiffRequest struct {
	Op       string `json:"op"`
	MaxBytes int64  `json:"max_bytes,omitempty"` // 0: 64 MiB; a larger patch is an error with CodeTooLarge
}

// DiffSummary lists what changed in the workspace relative to the image it booted with.
type DiffSummary struct {
	Files []DiffFile `json:"files"`
	Bytes int64      `json:"bytes"` // size of the patch that follows
}

type DiffFile struct {
	Path    string `json:"path"`              // relative to the workspace root, slash-separated, never ".." or absolute
	Status  string `json:"status"`            // "added", "modified", "deleted", "mode", "type" (file↔symlink↔dir)
	Binary  bool   `json:"binary,omitempty"`  // the patch carries a GIT binary patch for this file
	Symlink bool   `json:"symlink,omitempty"` // the new (or deleted) entry is a symlink
	OldMode uint32 `json:"old_mode,omitempty"`
	NewMode uint32 `json:"new_mode,omitempty"`
}

type ShutdownRequest struct {
	Op string `json:"op"`
}

type BootConfigRequest struct {
	Op string `json:"op"`
}

// BootConfig is everything box-specific the guest needs; it is never baked into the image so images stay cacheable by
// digest. Secret values never appear here, only their placeholders.
type BootConfig struct {
	Version  int    `json:"version"`
	BoxID    string `json:"box_id"`
	Hostname string `json:"hostname"`
	// Env is the base environment of every exec: the image's env, the box's env, secret placeholders, the proxy
	// variables (HTTP_PROXY, HTTPS_PROXY, http_proxy, https_proxy, NO_PROXY=""), and the CA variables (SSL_CERT_FILE,
	// NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, GIT_SSL_CAINFO, CURL_CA_BUNDLE) all pointing at CABundlePath.
	Env []string `json:"env"`
	// ProxyListen is where the guest's egress forwarder listens ("127.0.0.1:3128"); each accepted TCP connection is
	// piped unchanged to the host on vsock PortEgress.
	ProxyListen string `json:"proxy_listen"`
	// CACertPEM is the box's MITM CA certificate. The guest writes CABundlePath = the image's system CA bundle (if
	// any) followed by this cert, and also appends it to the well-known system bundle paths that exist in the image.
	CACertPEM    string          `json:"ca_cert_pem"`
	CABundlePath string          `json:"ca_bundle_path"` // "/etc/tkbox/ca-bundle.pem"
	Workspace    *WorkspaceMount `json:"workspace,omitempty"`
	Limits       GuestLimits     `json:"limits"`
	// UnixNano is the host's wall clock when the config was sent; the guest sets its clock from it (TLS needs it).
	UnixNano int64 `json:"unix_nano"`
}

// WorkspaceMount describes the workspace disks. The guest mounts BaseDevice read-only, UpperDevice read-write, and an
// overlay of the two at Path (upper/work dirs live on UpperDevice). The diff op compares the overlay's upper layer
// with the base.
type WorkspaceMount struct {
	Path        string `json:"path"`         // "/workspace"
	BaseDevice  string `json:"base_device"`  // "/dev/vdb": ext4 built from the host checkout, read-only
	UpperDevice string `json:"upper_device"` // "/dev/vdc": empty ext4 sized by limits.disk, read-write
}

type GuestLimits struct {
	ExecTimeoutMS  int64 `json:"exec_timeout_ms"`  // default per-exec timeout
	MaxOutputBytes int64 `json:"max_output_bytes"` // per exec, stdout+stderr; beyond it output is dropped and Truncated set
	MaxProcs       int   `json:"max_procs"`        // concurrent execs; more are refused with CodeBusy
}

// Error ends a failed exchange.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error codes.
const (
	CodeBadRequest = "bad_request"
	CodeNotFound   = "not_found"
	CodeTooLarge   = "too_large"
	CodeBusy       = "busy"
	CodeNotReady   = "not_ready"
	CodeInternal   = "internal"
)

func (e *Error) Error() string { return fmt.Sprintf("guest: %s: %s", e.Code, e.Message) }

// Defaults the guest applies when a request leaves a field zero.
const (
	DefaultMaxReadBytes   int64 = 64 << 20
	DefaultMaxDiffBytes   int64 = 64 << 20
	DefaultProxyListen          = "127.0.0.1:3128"
	DefaultCABundlePath         = "/etc/tkbox/ca-bundle.pem"
	DefaultWorkspacePath        = "/workspace"
	DefaultExecTimeoutMS  int64 = 30 * 60 * 1000
	DefaultMaxOutputBytes int64 = 256 << 20
	DefaultMaxProcs             = 64
)

// Kernel command line keys the host passes and the guest reads from /proc/cmdline.
const (
	CmdlineBoxID = "tkbox.id" // tkbox.id=<box id>
)
