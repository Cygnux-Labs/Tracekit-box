// Package tracekit is a Go client of the Tracekit 1.4.2 signer RPC (protocol 19, served RPC_MIN 15..19): newline-
// delimited JSON frames over the signer's Unix socket, `hello` first, identity from the socket's peer credentials.
// One Tracekit run per box. The interfaces and helpers in this file are the contract (lead); client.go and friends
// implement them (agent E). Tests above this package use tracekitfake.
package tracekit

import (
	"context"
	"strings"
	"time"
)

// Tool names and args shapes Box sends, so the signer's existing packs apply (coding pack: Bash → shell,
// WebFetch → http, Write → fs).
const (
	ToolBash     = "Bash"
	ToolWebFetch = "WebFetch"
	ToolWrite    = "Write"
)

// Observe sources Box records (value is a small JSON object; never a secret value).
const (
	SourceTask       = "tkbox.task"        // trusted: the task the operator gave the box
	SourceBox        = "tkbox.box"         // trusted: box lifecycle {box_id, image, image_digest, allow, limits}
	SourceSecretUse  = "tkbox.secret.use"  // {name, host}
	SourceSecretLeak = "tkbox.secret.leak" // {name, host, reason}
	SourceModelCall  = "tkbox.model.call"  // {host, path, status, bytes}
	SourceEgress     = "tkbox.egress"      // {host, port, decision, reason} for refusals Box made itself
	SourceApproval   = "tkbox.approval"    // trusted: a Box approval {approval_id, target, decision, approver}
	SourceContained  = "tkbox.contained"   // {state, incident_id}
)

// BashArgs is the args of a Bash decision for argv: {"command": <argv as one POSIX shell-quoted line>}.
func BashArgs(argv []string) map[string]any { return map[string]any{"command": ShellQuote(argv)} }

// WebFetchArgs is the args of a WebFetch decision: {"url": url}.
func WebFetchArgs(url string) map[string]any { return map[string]any{"url": url} }

// WriteArgs is the args of a Write decision for a file Box is about to write on the host: {"file_path": path}.
func WriteArgs(path string) map[string]any { return map[string]any{"file_path": path} }

// ShellQuote joins argv into one line a POSIX shell parses back into argv: words made only of safe characters stay
// bare, every other word is single-quoted with each embedded single quote written as '\”. The first word is also
// quoted when a shell would not read it as the program name (an assignment such as X=1, or a reserved word such as
// then), so the signer's parser sees the program the guest actually runs.
func ShellQuote(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if i == 0 && a != "" && (strings.Contains(a, "=") || shellReserved[a]) {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
			continue
		}
		out[i] = quoteWord(a)
	}
	return strings.Join(out, " ")
}

// shellReserved are the words a POSIX shell or bash reads as syntax, not a command, in command position.
var shellReserved = map[string]bool{"case": true, "coproc": true, "do": true, "done": true, "elif": true,
	"else": true, "esac": true, "fi": true, "for": true, "function": true, "if": true, "in": true, "select": true,
	"then": true, "time": true, "until": true, "while": true}

func quoteWord(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./-_", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Options configures a Client.
type Options struct {
	// Signer is the signer's Unix socket. "" discovers it as the Python SDK does, without auto-spawning one:
	// $TRACEKIT_SIGNER, else the root-owned /etc/tracekit/client.json "signer", else the same-user dev signer's
	// socket in its runtime dir.
	Signer      string
	Timeout     time.Duration // per call (default 30s); long polls add their own wait
	TracekitBin string        // the `tracekit` CLI used by Export (default "tracekit" in PATH)
}

// Status is the signer's status answer.
type Status struct {
	RPCVersion    int
	SignerName    string
	SignerVersion string
	Identity      string // "uid:1000"
	Where         string // the socket path
}

// Agent is the agent recorded in register_run.
type Agent struct {
	Name    string
	Version string
}

// Client is a connection to one signer.
type Client interface {
	Where() string
	// Status calls `status`; an error means the signer is not usable (fail closed).
	Status(ctx context.Context) (Status, error)
	// NewRun registers a run.
	NewRun(ctx context.Context, agent Agent) (Run, error)
	// Export writes the run's bundle (tracekit export --v2) and the signer's trust config (tracekit signer trust),
	// waiting until the run is final (the signer finalises a run a few seconds after close_run).
	Export(ctx context.Context, runID, bundleOut, trustOut string) error
	Close() error
}

// Call is one tool call. ID is unique within the run; Attempt is 0 unless a call is retried.
type Call struct {
	ID      string
	Tool    string
	Args    map[string]any
	Attempt int
}

// Decision is the signer's answer to decide.
type Decision struct {
	Decision   string // "allow", "deny", "ask"
	DecisionID string
	RuleIDs    []string
	Reason     string
	RunSeq     uint64
	IncidentID string
	SendResult bool
}

// Approval states (approval_wait).
const (
	ApprovalRequested = "requested"
	ApprovalApproved  = "approved"
	ApprovalRejected  = "rejected"
	ApprovalExpired   = "expired"
	ApprovalConsumed  = "consumed"
)

// Consume is the answer to approval_consume.
type Consume struct {
	OK         bool
	RuleIDs    []string
	ApprovalID string
	Reason     string
}

// Containment is the run's containment state as the signer sees it.
type Containment struct {
	Contained  bool
	State      string // "held", "quarantined" or ""
	IncidentID string
	Reason     string
}

// Run is one registered run. Event calls (decide, complete, observe) are sent in client_seq order. All methods are
// safe for concurrent use. Errors are *RPCError for signer refusals, *Unavailable when the signer can't be reached.
type Run interface {
	ID() string
	Decide(ctx context.Context, call Call) (Decision, error)
	RequestApproval(ctx context.Context, call Call, reason string) (approvalID string, err error)
	// WaitApproval does one approval_wait of up to timeout (capped at the signer's 300s) and returns the state.
	WaitApproval(ctx context.Context, approvalID string, timeout time.Duration) (string, error)
	Consume(ctx context.Context, call Call, approvalHint string) (Consume, error)
	// Abandon withdraws an approval whose call will never run.
	Abandon(ctx context.Context, approvalID, reason string) error
	// Complete records the outcome of a call that ran: status "ok" or "error"; args_digest is computed from
	// call.Tool and call.Args (sha256 of their RFC 8785 canonical JSON). result is sent as-is when the decision asked
	// for it (SendResult) and fits, else as its digest.
	Complete(ctx context.Context, call Call, d Decision, status string, result any) error
	Observe(ctx context.Context, source, trust string, value any) error
	// Contained reports whether the signer's containment holds or quarantined this run.
	Contained(ctx context.Context) (Containment, error)
	Close(ctx context.Context, reason string) error
}

// RPCError is a signer refusal ({"error": {code, message}}).
type RPCError struct {
	Code         string
	Message      string
	RetryAfterMS int64
}

func (e *RPCError) Error() string { return "tracekit signer: " + e.Code + ": " + e.Message }

// Unavailable means the signer could not be reached or did not answer in time. Box fails closed on it.
type Unavailable struct{ Err error }

func (e *Unavailable) Error() string { return "tracekit signer unavailable: " + e.Err.Error() }
func (e *Unavailable) Unwrap() error { return e.Err }

// Outcome is what Gate decided.
type Outcome struct {
	Allowed    bool
	Decision   Decision
	ApprovalID string   // set when the call went through approval
	Reason     string   // why it may not run, for the person and the agent
	RuleIDs    []string // rules behind a refusal
}

// GateHooks lets the caller follow a gate (e.g. to tell the CLI an approval is pending).
type GateHooks struct {
	OnAsk func(approvalID string) // called once approval_request returns
}
