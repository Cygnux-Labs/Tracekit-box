// Package api is the contract of the tkbox daemon's HTTP API, served on a Unix socket (run/tkbox.sock, mode 0600 in
// a 0700 dir). The daemon accepts a connection only from its own uid or root (SO_PEERCRED); the CLI, the MCP server,
// the Python SDK and the GitHub Action all speak this API.
//
// Routes (JSON bodies unless noted; errors are an ErrorBody with a non-2xx status):
//
//	GET    /v1/health                     → Health
//	POST   /v1/boxes                      CreateBoxRequest → Box (201)
//	GET    /v1/boxes                      → []Box
//	GET    /v1/boxes/{box}                → Box            ({box} is an id or a name)
//	POST   /v1/boxes/{box}/exec           ExecRequest, Upgrade: tkbox-exec/1 → 101, then frames (see below)
//	POST   /v1/boxes/{box}/stop           StopRequest → Box
//	DELETE /v1/boxes/{box}                → 204            (a running box is stopped first)
//	GET    /v1/boxes/{box}/diff           → text/x-diff patch body; header X-Tkbox-Diff-Summary: DiffSummary JSON
//	                                        (only when at most 8 KiB; else X-Tkbox-Diff-Summary-Omitted: 1)
//	GET    /v1/boxes/{box}/diff/summary   → DiffSummary
//	POST   /v1/boxes/{box}/apply          ApplyRequest → ApplyResult
//	POST   /v1/boxes/{box}/export         ExportRequest → ExportResult
//	GET    /v1/boxes/{box}/events         → application/x-ndjson stream of Event (?follow=1 keeps it open)
//	GET    /v1/approvals                  → []Approval     (pending Box approvals of every box)
//	POST   /v1/approvals/{id}             ApprovalDecision → Approval
//	POST   /v1/images                     ImageBuildRequest → Image
//
// Exec stream: after 101 Switching Protocols the connection carries internal/proto frames in both directions.
// Daemon → client: TypeJSON ExecEvent (state changes: deciding, waiting_approval, running), TypeStdout, TypeStderr,
// then TypeExit (proto.ExitStatus) or TypeError (proto.Error; Code is one of the Code* values below or a proto code).
// Client → daemon: TypeStdin…, TypeStdinEOF, TypeSignal. The command is decided by the signer before it starts; a
// refusal is a TypeError with CodeDenied before any output.
package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// Version of this API; reported by /v1/health.
const Version = "v1"

// Upgrade protocol token for the exec stream.
const ExecUpgrade = "tkbox-exec/1"

// DiffSummaryHeader carries the proto.DiffSummary of a diff response, JSON-encoded, when that JSON is at most
// MaxDiffSummaryHeader bytes; a larger summary is left out (DiffSummaryOmittedHeader is "1" instead) and read from
// GET /v1/boxes/{box}/diff/summary. A guest decides how many files and how long their paths are, so the summary is
// never an unbounded header.
const DiffSummaryHeader = "X-Tkbox-Diff-Summary"

// DiffSummaryOmittedHeader is "1" on a diff response whose summary was too large for DiffSummaryHeader.
const DiffSummaryOmittedHeader = "X-Tkbox-Diff-Summary-Omitted"

// MaxDiffSummaryHeader caps the DiffSummaryHeader value.
const MaxDiffSummaryHeader = 8 << 10

// Box states.
const (
	StateCreating = "creating"
	StateRunning  = "running"
	StatePaused   = "paused"
	StateStopping = "stopping"
	StateStopped  = "stopped"
	StateFailed   = "failed"
)

// Error codes of ErrorBody and of exec TypeError frames.
const (
	CodeBadRequest   = "bad_request"
	CodeNotFound     = "not_found"
	CodeConflict     = "conflict"    // name taken, box in the wrong state
	CodeDenied       = "denied"      // the signer or an approver refused the action
	CodeUnavailable  = "unavailable" // the signer can't be reached: fail closed
	CodeLimit        = "limit"       // a limit was hit; Message says which and what to do
	CodeForbidden    = "forbidden"   // the API caller's uid may not use this daemon
	CodeInternal     = "internal"
	CodeTimeout      = "timeout"       // a box timeout or approval timeout
	CodeNotSupported = "not_supported" // e.g. this host has no /dev/kvm
	CodeCancelled    = "cancelled"     // the caller cancelled (Ctrl-C, a closed connection) before the command started
)

type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	RuleIDs []string `json:"rule_ids,omitempty"` // signer rules behind a denial
	Hint    string   `json:"hint,omitempty"`     // what to do next (owner rule: every limit says what to do)
}

func (e *ErrorDetail) Error() string {
	s := e.Code + ": " + e.Message
	if len(e.RuleIDs) > 0 {
		s += " [" + strings.Join(e.RuleIDs, ", ") + "]"
	}
	if e.Hint != "" {
		s += " (" + e.Hint + ")"
	}
	return s
}

type Health struct {
	Version    string `json:"version"`    // tkbox build version
	API        string `json:"api"`        // Version
	Arch       string `json:"arch"`       // "arm64" or "amd64"
	KVM        bool   `json:"kvm"`        // /dev/kvm is usable
	Signer     string `json:"signer"`     // where the signer is ("" when unrecorded)
	SignerOK   bool   `json:"signer_ok"`  // the signer answered status just now
	Unrecorded bool   `json:"unrecorded"` // the daemon was started with --unrecorded: nothing is recorded
	Boxes      int    `json:"boxes"`      // boxes known (any state)
	StateDir   string `json:"state_dir"`
}

// Duration is a time.Duration that encodes as a Go duration string ("30m") and decodes from one or from seconds.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("duration %q: %w", s, err)
		}
		*d = Duration(v)
		return nil
	}
	var n float64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration: want a string like \"30m\" or seconds")
	}
	*d = Duration(time.Duration(n * float64(time.Second)))
	return nil
}

// Limits of one box. Zero values mean the daemon's defaults (see docs/limits.md).
type Limits struct {
	CPUs        int      `json:"cpus,omitempty"`         // vCPUs, 1..32 (default 2)
	MemoryMiB   int      `json:"memory_mib,omitempty"`   // 128..65536 (default 2048)
	DiskMiB     int      `json:"disk_mib,omitempty"`     // workspace upper disk, 64..1048576 (default 4096)
	Timeout     Duration `json:"timeout,omitempty"`      // box lifetime; at expiry it is stopped (default 1h)
	ExecTimeout Duration `json:"exec_timeout,omitempty"` // per exec (default 30m)
}

// SecretSpec is one secret as the CLI resolved it. Value never leaves the daemon: the VM sees a placeholder and the
// egress proxy swaps the value into Header only on requests to Hosts.
type SecretSpec struct {
	Value  string   `json:"value"`
	Hosts  []string `json:"hosts"`            // exact host names or IP literals, lower case; wildcards are refused
	Header string   `json:"header,omitempty"` // header the placeholder is swapped in; "" = Authorization
}

type CreateBoxRequest struct {
	Name      string                `json:"name,omitempty"`      // unique among boxes; default the id
	Image     string                `json:"image"`               // OCI reference, e.g. "python:3.12-slim"
	Allow     []string              `json:"allow,omitempty"`     // presets ("pypi") and hosts ("api.example.com", "h:8443")
	Secrets   map[string]SecretSpec `json:"secrets,omitempty"`   // env var name → secret
	Env       map[string]string     `json:"env,omitempty"`       // plain env for every exec
	Workspace string                `json:"workspace,omitempty"` // absolute host dir copied into /workspace; "" = none
	Limits    Limits                `json:"limits,omitempty"`
	Inspect   string                `json:"inspect,omitempty"` // "bound" (default: MITM only hosts with a bound secret) or "all"
	Agent     string                `json:"agent,omitempty"`   // agent name recorded in the Tracekit run (default "tkbox")
	Task      string                `json:"task,omitempty"`    // the task, recorded as trusted observe content
	// ValidateOnly checks the request (limits, allowlist, secrets, workspace) and answers 200 with the box it would
	// create, without creating anything.
	ValidateOnly bool `json:"validate_only,omitempty"`
}

type Box struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	State       string   `json:"state"`
	Image       string   `json:"image"`
	ImageDigest string   `json:"image_digest,omitempty"`
	Allow       []string `json:"allow"`             // after preset expansion
	Secrets     []string `json:"secrets,omitempty"` // names only, never values
	// SecretHeaders is the header each secret is swapped into (an empty SecretSpec.Header means Authorization).
	SecretHeaders map[string]string `json:"secret_headers,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	Workspace     string            `json:"workspace,omitempty"`
	Limits        Limits            `json:"limits"`
	Inspect       string            `json:"inspect"`
	RunID         string            `json:"run_id,omitempty"` // the Tracekit run; "" when unrecorded
	Unrecorded    bool              `json:"unrecorded,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	StartedAt     time.Time         `json:"started_at,omitzero"`
	StoppedAt     time.Time         `json:"stopped_at,omitzero"`
	ExpiresAt     time.Time         `json:"expires_at,omitzero"`
	StopReason    string            `json:"stop_reason,omitempty"`
	Error         string            `json:"error,omitempty"` // why it failed
	Execs         int               `json:"execs"`           // execs started so far
	// DiffSaved is set once the workspace patch was saved at stop (apply and diff read it); DiffError says why it
	// was not (killed, paused, too large, the guest did not answer, …).
	DiffSaved bool     `json:"diff_saved,omitempty"`
	DiffError string   `json:"diff_error,omitempty"`
	Notices   []string `json:"notices,omitempty"` // what the person should know (e.g. the workspace is not a git work tree)
}

type ExecRequest struct {
	Argv    []string          `json:"argv"`
	Env     map[string]string `json:"env,omitempty"`
	Cwd     string            `json:"cwd,omitempty"`
	Timeout Duration          `json:"timeout,omitempty"` // 0: the box's exec timeout
	// Stdin streams stdin over the exec connection (TypeStdin frames); the complete records its sha256 and size.
	Stdin bool `json:"stdin,omitempty"`
	// StdinData is the whole stdin when it is known before the command starts (base64 in JSON, at most MaxStdinData):
	// the signer decides it with the command (stdin_sha256 and stdin_bytes, and stdin_text when it is UTF-8 of at most
	// MaxStdinText bytes), then it is the process's stdin. Use StdinData or Stdin, not both.
	StdinData []byte `json:"stdin_data,omitempty"`
}

// MaxStdinData caps ExecRequest.StdinData; stream larger input (ExecRequest.Stdin) or put it in a file.
const MaxStdinData = 1 << 20

// MaxStdinText is the largest StdinData whose text goes into the decision as stdin_text (when it is valid UTF-8).
const MaxStdinText = 4 << 10

// Exec states sent as TypeJSON ExecEvent frames.
const (
	ExecDeciding        = "deciding"
	ExecWaitingApproval = "waiting_approval"
	ExecRunning         = "running"
	ExecNotice          = "notice" // something the person should see on stderr (an egress refusal, an approval to give)
)

type ExecEvent struct {
	State      string   `json:"state"`
	Decision   string   `json:"decision,omitempty"` // allow, deny, ask
	RuleIDs    []string `json:"rule_ids,omitempty"`
	ApprovalID string   `json:"approval_id,omitempty"` // with waiting_approval
	Approver   string   `json:"approver,omitempty"`    // "tracekit" (approve with `tracekit approvals approve <id>`) or "tkbox"
	Message    string   `json:"message,omitempty"`
}

type StopRequest struct {
	Kill   bool   `json:"kill,omitempty"`   // SIGKILL the VM now instead of a clean shutdown
	Reason string `json:"reason,omitempty"` // recorded as the run's close reason
}

type ApplyRequest struct {
	Dir   string `json:"dir,omitempty"`   // host checkout to apply to; default the box's workspace
	Check bool   `json:"check,omitempty"` // validate and decide only, write nothing
	// AllowSensitive lets the patch change files that steer the next run or host automation (.gitignore,
	// .gitattributes, .gitmodules, tkbox.yaml, .husky/, .github/workflows/, …); without it such a patch is refused.
	AllowSensitive bool `json:"allow_sensitive,omitempty"`
}

type ApplyResult struct {
	Applied   []string `json:"applied"`             // paths written (relative to Dir)
	Denied    []string `json:"denied,omitempty"`    // paths the signer refused; nothing is applied if any is denied
	Patch     string   `json:"patch,omitempty"`     // path of the saved patch file under the box's state dir
	Checked   bool     `json:"checked,omitempty"`   // Check was set: nothing was written
	Sensitive []string `json:"sensitive,omitempty"` // paths of Applied that steer the next run or host automation
	Ignored   []string `json:"ignored,omitempty"`   // new files the checkout's .gitignore ignores: left out of the apply
	SHA256    string   `json:"sha256,omitempty"`    // sha256 of the patch that was decided (and applied)
}

type ExportRequest struct {
	Out string `json:"out"` // absolute path for the .tkb; the trust file goes next to it: demo.tkb → demo.trust.json
}

type ExportResult struct {
	RunID  string `json:"run_id"`
	Bundle string `json:"bundle"`
	Trust  string `json:"trust"`
	Verify string `json:"verify"` // the command that verifies it offline
}

// Approval is a Box approval: a request Box itself holds for a person (an egress host off the allowlist). Approvals
// the signer's policy asks for are answered with `tracekit approvals approve <id>` instead.
type Approval struct {
	ID        string    `json:"id"`
	BoxID     string    `json:"box_id"`
	BoxName   string    `json:"box_name"`
	Kind      string    `json:"kind"`   // "egress"
	Target    string    `json:"target"` // e.g. "https://example.com:443"
	State     string    `json:"state"`  // "pending", "approved", "rejected", "expired", "withdrawn"
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	DecidedBy string    `json:"decided_by,omitempty"` // "uid:<n>" of the API caller who answered
	Waiters   int       `json:"waiters"`              // connections waiting on it now; at 0 it is withdrawn
}

type ApprovalDecision struct {
	Decision string `json:"decision"`        // "approve" or "reject"
	Scope    string `json:"scope,omitempty"` // "once" (default) or "box": approve the host for the rest of the box
}

type ImageBuildRequest struct {
	Ref string `json:"ref"`
}

type Image struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
	Arch   string `json:"arch"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
}

// DiffSummary is the proto summary, re-exported for API clients.
type DiffSummary = proto.DiffSummary

// Event is one line of a box's events.ndjson: what happened at each door. Never a secret value.
type Event struct {
	Time    time.Time      `json:"time"`
	BoxID   string         `json:"box_id"`
	Kind    string         `json:"kind"`              // see the Event* kinds
	Door    string         `json:"door,omitempty"`    // "exec", "egress", "secret", "model", "apply", "lifecycle"
	Summary string         `json:"summary,omitempty"` // one human line
	Data    map[string]any `json:"data,omitempty"`
}

// Event kinds.
const (
	EventBoxCreated    = "box.created"
	EventBoxStarted    = "box.started"
	EventBoxStopped    = "box.stopped"
	EventBoxFailed     = "box.failed"
	EventExecDecided   = "exec.decided"
	EventExecExited    = "exec.exited"
	EventEgressAllowed = "egress.allowed"
	EventEgressDenied  = "egress.denied"
	EventEgressClosed  = "egress.closed"
	EventSecretUse     = "secret.use"
	EventSecretLeak    = "secret.leak"
	EventModelCall     = "model.call"
	EventApproval      = "approval"
	EventApplyDecided  = "apply.decided"
	EventContained     = "contained"
	EventSignerProblem = "signer.problem"
)
