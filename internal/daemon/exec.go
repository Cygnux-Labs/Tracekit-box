package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/Cygnux-Labs/tracekit-box/internal/agentrpc"
	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/config"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

const (
	// maxStdinBuffer is how much stdin the daemon holds for a process that has not read it yet. The frame reader
	// never blocks on stdin (signals and a closed connection must get through); past this the rest is dropped and the
	// process killed (never handed a false EOF): its exit status says so (StdinTruncated).
	maxStdinBuffer = 4 << 20
	// clientWriteGrace is how long a client may take to read the last frames once the exec is cancelled or the box
	// stops; a client that stalls longer is cut off so the exec can finish and be completed.
	clientWriteGrace = 2 * time.Second
)

// execSession is one exec stream; it receives notices (egress refusals, approvals to give) for the person.
type execSession struct {
	notices  chan string
	sigs     chan string   // signals for the process once it runs
	started  atomic.Bool   // the command was handed to the guest (set under box.mu)
	execDone chan struct{} // closed once the guest exec returned (or it never started)
	doneOnce sync.Once
}

func (s *execSession) finish() { s.doneOnce.Do(func() { close(s.execDone) }) }

// notice tells every exec stream of the box something the person should see on stderr.
func (b *box) notice(msg string) {
	msg = b.scrub().str(msg)
	b.mu.Lock()
	defer b.mu.Unlock()
	for s := range b.sessions {
		select {
		case s.notices <- msg:
		default: // a stuck client never blocks the proxy
		}
	}
}

var signalNames = map[string]bool{"SIGINT": true, "SIGTERM": true, "SIGKILL": true, "SIGHUP": true, "SIGQUIT": true}

// loaderEnv are env names that change what a decided command runs without changing its argv (shell startup and
// tracing, which program a name resolves to, where config and modules are read from, build-tool wrappers, editors
// and pagers); a per-exec env may not set them, nor any name under loaderEnvPrefixes (an operator's box env may).
// The env a command does get is also in its decided command line (`env K=V … cmd`, see commandLine), so the signer's
// own env rules see it; these lists refuse up front what no command needs per exec.
var loaderEnv = map[string]bool{"ENV": true, "PROMPT_COMMAND": true, "PATH": true, "GCONV_PATH": true,
	"SHELLOPTS": true, "BASHOPTS": true, "PS4": true, "IFS": true, "CDPATH": true, "GLOBIGNORE": true, "ZDOTDIR": true,
	"FPATH": true, "HOME": true, "GLIBC_TUNABLES": true, "CLASSPATH": true, "GEM_PATH": true, "GEM_HOME": true,
	"BUNDLE_GEMFILE": true, "MAKEFILES": true, "MAKEFLAGS": true, "GOFLAGS": true, "GOENV": true, "GOTOOLCHAIN": true,
	"RUSTC": true, "RUSTC_WRAPPER": true, "RUSTC_WORKSPACE_WRAPPER": true, "RUSTFLAGS": true, "CARGO_HOME": true,
	"CARGO_BUILD_RUSTC": true, "CARGO_BUILD_RUSTC_WRAPPER": true, "CC": true, "CXX": true, "CPP": true, "LD": true,
	"PHPRC": true, "PHP_INI_SCAN_DIR": true, "LESSOPEN": true, "LESSCLOSE": true, "EDITOR": true, "VISUAL": true,
	"PAGER": true, "MANPAGER": true, "SSH_ASKPASS": true, "PIP_CONFIG_FILE": true}

// loaderEnvPrefixes are name prefixes a per-exec env may not set: the dynamic loader (LD_, and DYLD_), GIT_ (config,
// hooks, ssh, exec path, editor, pager, …), XDG_ base dirs (config is read there), interpreters' options and module
// paths (PYTHON, PERL, RUBY, NODE_, JAVA_, JDK_, _JAVA_, LUA_) and BASH_ (BASH_ENV, …). npm reads its config from
// NPM_CONFIG_ names in any case, so that prefix is matched in any case too.
var loaderEnvPrefixes = []string{"LD_", "DYLD_", "GIT_", "XDG_", "PYTHON", "PERL", "RUBY", "NODE_", "JAVA_", "JDK_",
	"_JAVA_", "LUA_", "BASH_"}

// loaderEnvAllowed are names under a loaderEnvPrefixes prefix that change no program and may be set per exec.
var loaderEnvAllowed = map[string]bool{"GIT_AUTHOR_NAME": true, "GIT_AUTHOR_EMAIL": true, "GIT_AUTHOR_DATE": true,
	"GIT_COMMITTER_NAME": true, "GIT_COMMITTER_EMAIL": true, "GIT_COMMITTER_DATE": true, "NODE_ENV": true,
	"PYTHONUNBUFFERED": true, "PYTHONDONTWRITEBYTECODE": true, "PYTHONIOENCODING": true, "PYTHONUTF8": true,
	"PYTHONHASHSEED": true, "PYTHONFAULTHANDLER": true}

// isLoaderEnv reports whether a per-exec env may not set k.
func isLoaderEnv(k string) bool {
	if loaderEnv[k] || strings.HasPrefix(strings.ToUpper(k), "NPM_CONFIG_") {
		return true
	}
	if loaderEnvAllowed[k] {
		return false
	}
	for _, p := range loaderEnvPrefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// prepareExec checks an exec request before the connection is upgraded, so a refusal is a plain JSON error.
func (d *Daemon) prepareExec(ref string, req api.ExecRequest) (*box, *api.ErrorDetail) {
	b, err := d.lookup(ref)
	if err != nil {
		return nil, asAPIError(err)
	}
	switch st := b.state(); st {
	case api.StateRunning:
	case api.StatePaused:
		return nil, errf(api.CodeConflict, "the signer holds this run; ask whoever owns the incident in Tracekit", "box %s is paused", ref)
	default:
		return nil, errf(api.CodeConflict, "start a new box with `tkbox run`", "box %s is %s", ref, st)
	}
	if len(req.Argv) == 0 || req.Argv[0] == "" {
		return nil, errf(api.CodeBadRequest, "pass the command after --, e.g. `tkbox exec box -- ls -la`", "no command")
	}
	if strings.HasPrefix(req.Argv[0], "%") {
		// bash and zsh run a first word %… as a job spec (fg), quoted or not: no decided command line could name it
		return nil, errf(api.CodeBadRequest, "rename it or run it by path (./"+req.Argv[0]+")",
			"a program name may not start with %%: a shell reads it as a job spec, so the record could not name the program")
	}
	for _, a := range req.Argv {
		if strings.ContainsRune(a, 0) {
			return nil, errf(api.CodeBadRequest, "remove the NUL byte from the command", "an argument has a NUL byte")
		}
	}
	b.mu.Lock()
	secrets := b.secrets
	b.mu.Unlock()
	// a secret's value never enters the box, nor the decision (which holds the command and cwd as they are): the
	// command, cwd and stdin_data are checked together. A secret value has no NUL, so joining them with NUL can't make a
	// match across two of them.
	if name := secretIn(strings.Join(append([]string{req.Cwd, string(req.StdinData)}, req.Argv...), "\x00"), secrets); name != "" {
		return nil, errf(api.CodeBadRequest, "use the secret's placeholder ($"+name+" in the box) instead; its value never enters the box",
			"the command, its cwd or its stdin holds the value of secret %s", name)
	}
	for k, v := range req.Env {
		if !envNameRE.MatchString(k) || strings.ContainsRune(v, 0) {
			return nil, errf(api.CodeBadRequest, "env names are letters, digits and _; values can't hold NUL", "env %q is not a valid KEY=VALUE", k)
		}
		if name := secretIn(v, secrets); name != "" {
			return nil, errf(api.CodeBadRequest, "use the secret's placeholder ($"+name+" in the box) instead; its value never enters the box",
				"env %s holds the value of secret %s", k, name)
		}
		if reservedEnv[k] {
			return nil, errf(api.CodeBadRequest, "every connection goes through the box's proxy", "env %s is set by the box and can't be overridden", k)
		}
		if isLoaderEnv(k) {
			return nil, errf(api.CodeBadRequest, "it changes what the command runs without showing in the command the signer decides; put it in the command itself (e.g. sh -c '"+k+"=… cmd') so it is decided",
				"env %s can't be set per command", k)
		}
	}
	if len(req.Env) > 0 && strings.Contains(req.Argv[0], "=") {
		// the decided line is `env K=V … argv`: env would read a first word with = as one more variable, not the program
		return nil, errf(api.CodeBadRequest, "run it through a shell instead, e.g. sh -c '…'",
			"a program name with = can't take a per-command env")
	}
	// the decided command line joins argv with spaces and names each env variable, so a value split over bare words
	// (`echo correct horse battery`) or used as an env name is in it as it is
	if name := secretIn(b.commandLine(req), secrets); name != "" {
		return nil, errf(api.CodeBadRequest, "use the secret's placeholder ($"+name+" in the box) instead; its value never enters the box",
			"the command line the signer decides holds the value of secret %s", name)
	}
	if req.Stdin && req.StdinData != nil {
		return nil, errf(api.CodeBadRequest, "send the input as stdin_data (known up front) or stream it (stdin: true), not both",
			"stdin and stdin_data are both set")
	}
	if len(req.StdinData) > api.MaxStdinData {
		return nil, limitErr("stdin_data is %d bytes, over the %d MiB limit", "stream larger input instead (`tkbox exec -i`, or a file object in the SDK), or write it to a file in /workspace and read it from there",
			len(req.StdinData), api.MaxStdinData>>20)
	}
	if req.Cwd != "" && !strings.HasPrefix(req.Cwd, "/") {
		return nil, errf(api.CodeBadRequest, "pass --cwd /workspace/... (absolute)", "cwd %q must be an absolute path in the box", req.Cwd)
	}
	if t := time.Duration(req.Timeout); t < 0 || (t > 0 && t < config.MinExecTimeout) || t > config.MaxExecTimeout {
		return nil, limitErr("exec timeout %s is outside 1s..24h", "pass --timeout up to 24h", t)
	}
	return b, nil
}

// frameWriter serialises frames from several goroutines; each Write is one whole frame (proto.WriteFrame).
type frameWriter struct {
	mu  sync.Mutex
	w   io.Writer
	err error
}

func (f *frameWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	n, err := f.w.Write(p)
	if err != nil {
		f.err = err
	}
	return n, err
}

func (f *frameWriter) event(e api.ExecEvent) error { return proto.WriteJSON(f, proto.TypeJSON, e) }

// stdinQueue holds stdin frames until the process reads them. Writes never block.
type stdinQueue struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      bytes.Buffer
	max      int
	closed   bool
	err      error
	overflow bool  // more than max waited: the rest is dropped, and Read never reports EOF (the process is killed)
	dropped  int64 // bytes dropped since the overflow
	ended    bool  // the exec is over
	sum      hash.Hash
	given    int64 // bytes handed to the process (hashed in sum)
}

func newStdinQueue(max int) *stdinQueue {
	q := &stdinQueue{max: max, sum: sha256.New()}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// digest is the sha256 and size of the stdin handed to the process so far.
func (q *stdinQueue) digest() (string, int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return hex.EncodeToString(q.sum.Sum(nil)), q.given
}

// write queues p; it reports false the first time the queue overflows. From then on every byte is dropped (counted)
// and no EOF is ever delivered: the caller kills the process instead.
func (q *stdinQueue) write(p []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.overflow {
		q.dropped += int64(len(p))
		return true
	}
	if q.closed {
		return true
	}
	if q.buf.Len()+len(p) > q.max {
		q.overflow = true
		q.dropped += int64(len(p))
		q.cond.Broadcast()
		return false
	}
	q.buf.Write(p)
	q.cond.Broadcast()
	return true
}

// truncated reports whether stdin overflowed and how many bytes were dropped.
func (q *stdinQueue) truncated() (bool, int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.overflow, q.dropped
}

func (q *stdinQueue) closeWith(err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed, q.err = true, err
	}
	q.cond.Broadcast()
}

// end is called once the exec is over: a Read still waiting returns.
func (q *stdinQueue) end() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.ended, q.closed = true, true
	q.cond.Broadcast()
}

func (q *stdinQueue) Read(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	// after an overflow no EOF is delivered while the exec runs: the process is being killed
	for q.buf.Len() == 0 && (!q.closed || q.overflow) && !q.ended {
		q.cond.Wait()
	}
	if q.buf.Len() == 0 {
		if q.err != nil {
			return 0, q.err
		}
		return 0, io.EOF
	}
	n, err := q.buf.Read(p)
	q.sum.Write(p[:n])
	q.given += int64(n)
	return n, err
}

// redactor returns what the decision shows of a value: a secret's placeholder as tkbox_NAME_…, its value as
// [secret NAME], and a value those complete with the text around it as a run of filler (see unrebuild).
func (b *box) redactor() func(string) string {
	b.mu.Lock()
	secrets := b.secrets
	b.mu.Unlock()
	left := unrebuild(secrets)
	return func(v string) string {
		for _, s := range secrets {
			if s.Placeholder != "" {
				v = strings.ReplaceAll(v, s.Placeholder, "tkbox_"+s.Name+"_…")
			}
			if s.Value != "" {
				v = strings.ReplaceAll(v, s.Value, "[secret "+s.Name+"]")
			}
		}
		if left != nil {
			v = left.Replace(v)
		}
		return v
	}
}

// commandLine is the command line the signer decides for an exec: argv shell-quoted, led by `env K=V …` with the
// exec's own env (sorted, placeholders redacted) when it has any, so the signer's shell parser and its env rules see
// the variables the command runs with, as they would in a command typed with them.
func (b *box) commandLine(req api.ExecRequest) string {
	if len(req.Env) == 0 {
		return tracekit.ShellQuote(req.Argv)
	}
	redact := b.redactor()
	keys := make([]string, 0, len(req.Env))
	for k := range req.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	argv := make([]string, 0, 1+len(keys)+len(req.Argv))
	argv = append(argv, "env")
	for _, k := range keys {
		argv = append(argv, k+"="+redact(req.Env[k]))
	}
	return tracekit.ShellQuote(append(argv, req.Argv...))
}

// bashArgs is what the signer decides for an exec: the command line (commandLine) and everything else that changes
// what runs.
func (b *box) bashArgs(req api.ExecRequest, line string) map[string]any {
	cwd := req.Cwd
	if cwd == "" {
		cwd = proto.DefaultWorkspacePath
	}
	env := map[string]any{}
	redact := b.redactor()
	for k, v := range req.Env {
		env[k] = redact(v)
	}
	args := map[string]any{"command": line, "cwd": cwd, "env": env, "stdin": req.Stdin || req.StdinData != nil}
	if req.StdinData != nil {
		// stdin known up front is decided with the command: a script piped into an interpreter is not run unseen
		sum := sha256.Sum256(req.StdinData)
		args["stdin_sha256"] = hex.EncodeToString(sum[:])
		args["stdin_bytes"] = len(req.StdinData)
		if len(req.StdinData) <= api.MaxStdinText && utf8.Valid(req.StdinData) {
			args["stdin_text"] = redact(string(req.StdinData))
		}
	}
	return args
}

// tooLongToRecord reports whether err is the signer's (or the client's) refusal of a frame over 1 MiB.
func tooLongToRecord(err error) bool {
	var rpc *tracekit.RPCError
	return errors.As(err, &rpc) && rpc.Code == "quota_exceeded"
}

var errTooLong = errf(api.CodeLimit, "put it in a script in /workspace and run that",
	"the command is too long to record (over 1 MiB)")

// runExec runs one exec on an upgraded connection: decide (Bash) → maybe wait for a Tracekit approval → run in the
// guest, streaming stdio both ways → complete with the exit status. conn may be nil in tests (no write deadlines).
func (b *box) runExec(parent context.Context, conn net.Conn, r io.Reader, w io.Writer, req api.ExecRequest) {
	b.calls.begin()
	defer b.calls.end()
	fw := &frameWriter{w: w}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	go func() {
		select {
		case <-b.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	if conn != nil {
		// once the exec is cancelled (the box stops, the client goes away) a client that does not read can't hold
		// the exec, its goroutines or the run's complete hostage
		stopDeadline := context.AfterFunc(ctx, func() { conn.SetWriteDeadline(time.Now().Add(clientWriteGrace)) })
		defer stopDeadline()
	}
	// dctx is the decision's context: a signal or a closed connection before the command starts cancels it (and
	// withdraws a pending approval) instead of being delivered later
	dctx, dcancel := context.WithCancel(ctx)
	defer dcancel()

	sess := &execSession{notices: make(chan string, 64), sigs: make(chan string, 8), execDone: make(chan struct{})}
	defer sess.finish()
	b.mu.Lock()
	b.sessions[sess] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.sessions, sess)
		b.mu.Unlock()
	}()
	pumpCtx, stopPump := context.WithCancel(ctx)
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		for {
			select {
			case m := <-sess.notices:
				fw.event(api.ExecEvent{State: api.ExecNotice, Message: m})
			case <-pumpCtx.Done():
				return
			}
		}
	}()
	// final frames go out after the pump stops, so nothing follows TypeExit/TypeError
	final := func(typ byte, v any) {
		stopPump()
		<-pumpDone
		proto.WriteJSON(fw, typ, v)
	}

	// client → daemon: stdin, stdin EOF, signals. This loop never blocks, so a signal or a closed connection is
	// seen at once whatever the process does with its stdin.
	stdin := newStdinQueue(maxStdinBuffer)
	defer stdin.end()
	go func() {
		for {
			f, err := proto.ReadFrame(r)
			if err != nil {
				stdin.closeWith(io.ErrUnexpectedEOF)
				cancel()
				return
			}
			switch f.Type {
			case proto.TypeStdin:
				if req.Stdin && !stdin.write(f.Payload) {
					// the process can't get its whole input; a false EOF would let it finish as if it had: it is
					// stopped instead (not started at all if it has not started yet)
					if !sess.started.Load() {
						dcancel()
						if !sess.started.Load() {
							continue
						}
					}
					select {
					case sess.notices <- fmt.Sprintf("stdin: more than %d MiB waited for the process to read it; the rest is dropped and the command is being stopped", maxStdinBuffer>>20):
					default:
					}
					go func() {
						select {
						case sess.sigs <- "SIGKILL":
						case <-sess.execDone:
						}
					}()
				}
			case proto.TypeStdinEOF:
				stdin.closeWith(nil)
			case proto.TypeSignal:
				var s proto.Signal
				if f.Decode(&s) != nil || !signalNames[s.Signal] {
					continue
				}
				if !sess.started.Load() {
					dcancel() // not started yet: don't start it
					continue
				}
				select {
				case sess.sigs <- s.Signal:
				default:
				}
			}
		}
	}()

	b.mu.Lock()
	run, g, m := b.run, b.guest, b.machine
	timeout := time.Duration(b.info.Limits.ExecTimeout)
	b.mu.Unlock()
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout)
	}
	line := b.commandLine(req)
	cancelled := func() {
		if over, n := stdin.truncated(); over {
			b.event(api.EventExecDecided, "exec", "exec not started, stdin overflowed before it started: "+line,
				map[string]any{"command": line, "decision": "cancelled", "stdin_dropped_bytes": n})
			final(proto.TypeError, api.ErrorDetail{Code: api.CodeLimit,
				Message: fmt.Sprintf("more than %d MiB of stdin arrived before the command started, so it was not started (nothing ran)", maxStdinBuffer>>20),
				Hint:    "write large input to a file in /workspace and read it from there"})
			return
		}
		b.event(api.EventExecDecided, "exec", "exec cancelled before it started: "+line, map[string]any{"command": line, "decision": "cancelled"})
		if isClosed(b.stopCh) {
			final(proto.TypeError, api.ErrorDetail{Code: api.CodeConflict, Message: "the box stopped before the command started",
				Hint: "see why with `tkbox ls`; start a new box with `tkbox run`"})
			return
		}
		final(proto.TypeError, api.ErrorDetail{Code: api.CodeCancelled, Message: "cancelled before the command started (nothing ran)"})
	}
	fw.event(api.ExecEvent{State: api.ExecDeciding})
	var call tracekit.Call
	var dec tracekit.Decision
	decided := false
	complete := func(status string, result any) {
		if !decided {
			return
		}
		cctx, cancel := context.WithTimeout(b.d.ctx, 30*time.Second)
		defer cancel()
		if err := run.Complete(cctx, call, dec, status, result); err != nil {
			b.completeFailed("exec", err)
		}
	}
	if run != nil {
		call = tracekit.Call{ID: b.nextCallID("exec"), Tool: tracekit.ToolBash, Args: b.bashArgs(req, line)}
		out, err := b.d.opts.Gate(dctx, run, call, tracekit.GateHooks{OnAsk: func(id string) {
			fw.event(api.ExecEvent{State: api.ExecWaitingApproval, Decision: "ask", ApprovalID: id, Approver: "tracekit",
				Message: "approve with: tracekit approvals approve " + id})
		}})
		if err != nil {
			switch {
			case dctx.Err() != nil:
				cancelled()
			case tooLongToRecord(err):
				b.event(api.EventExecDecided, "exec", "exec refused, too long to record: "+trunc(line),
					map[string]any{"decision": "deny", "reason": err.Error()})
				final(proto.TypeError, *errTooLong)
			default:
				b.event(api.EventExecDecided, "exec", "exec refused, the signer did not answer: "+line,
					map[string]any{"command": line, "decision": "deny", "reason": err.Error()})
				final(proto.TypeError, api.ErrorDetail{Code: api.CodeUnavailable,
					Message: "the Tracekit signer did not answer, so nothing runs (fail closed): " + err.Error(),
					Hint:    "check the signer with `tracekit status` (start it with `tracekit up`), then run the command again"})
			}
			return
		}
		b.pokeContainment(out.Decision)
		if !out.Allowed {
			if dctx.Err() != nil {
				cancelled() // Gate withdrew the approval
				return
			}
			msg, hint := denial(out)
			b.event(api.EventExecDecided, "exec", "exec denied: "+line,
				map[string]any{"command": line, "decision": "deny", "rule_ids": out.RuleIDs, "reason": out.Reason})
			fw.event(api.ExecEvent{State: api.ExecDeciding, Decision: "deny", RuleIDs: out.RuleIDs, Message: msg})
			final(proto.TypeError, api.ErrorDetail{Code: api.CodeDenied, Message: msg, RuleIDs: out.RuleIDs, Hint: hint})
			return
		}
		dec, decided = out.Decision, true
	}
	b.event(api.EventExecDecided, "exec", "exec allowed: "+line,
		map[string]any{"command": line, "decision": "allow", "rule_ids": dec.RuleIDs, "decision_id": nonEmpty(dec.DecisionID)})
	b.mu.Lock()
	st := b.info.State
	if st != api.StateRunning || g == nil {
		b.mu.Unlock()
		complete("error", "not run: the box is "+st)
		final(proto.TypeError, api.ErrorDetail{Code: api.CodeConflict, Message: "the box is " + st + ", so the command did not start",
			Hint: "start a new box with `tkbox run`"})
		return
	}
	sess.started.Store(true) // from here on stop() waits for it (and signals it) before saving the diff
	b.info.Execs++
	b.mu.Unlock()
	if dctx.Err() != nil {
		sess.finish()
		complete("error", "not run: cancelled before it started")
		cancelled()
		return
	}
	b.persist()
	msg := ""
	if run == nil {
		msg = "unrecorded: this command is not recorded in Tracekit"
	}
	fw.event(api.ExecEvent{State: api.ExecRunning, Decision: "allow", RuleIDs: dec.RuleIDs, Message: msg})

	env := make([]string, 0, len(req.Env))
	for k, v := range req.Env {
		env = append(env, k+"="+v)
	}
	sort.Strings(env)
	preq := proto.ExecRequest{Op: proto.OpExec, Argv: req.Argv, Env: env, Cwd: req.Cwd,
		TimeoutMS: timeout.Milliseconds(), Stdin: req.Stdin || req.StdinData != nil}
	stdio := agentrpc.ExecIO{Stdout: proto.ChunkWriter{W: fw, Type: proto.TypeStdout},
		Stderr: proto.ChunkWriter{W: fw, Type: proto.TypeStderr}, Signals: sess.sigs}
	switch {
	case req.StdinData != nil:
		stdio.Stdin = bytes.NewReader(req.StdinData) // exactly what was decided
	case req.Stdin:
		stdio.Stdin = stdin
	}
	ectx, ecancel := context.WithTimeout(ctx, timeout+30*time.Second) // host backstop; the guest enforces timeout
	es, err := g.Exec(ectx, preq, stdio)
	deadline := errors.Is(ectx.Err(), context.DeadlineExceeded)
	ecancel()
	sess.finish()
	if err != nil {
		code, m2, hint := api.CodeInternal, err.Error(), "read the box's console.log and events (`tkbox events <box>`)"
		var pe *proto.Error
		switch {
		case m != nil && isClosed(m.Done()):
			code, m2, hint = api.CodeConflict, "the VM exited while the command ran", "see why with `tkbox ls` and `tkbox events <box>`; start a new box with `tkbox run`"
		case isClosed(b.stopCh):
			code, m2, hint = api.CodeConflict, "the box stopped while the command ran", "see why with `tkbox ls`; start a new box with `tkbox run`"
		case deadline:
			code, m2, hint = api.CodeTimeout, fmt.Sprintf("the command did not finish within %s", timeout), "pass a longer --timeout (up to 24h) or set limits.exec_timeout"
		case ctx.Err() != nil:
			code, m2, hint = api.CodeCancelled, "the client went away, so the command was stopped", ""
		case errors.As(err, &pe):
			code, m2 = pe.Code, pe.Message
			switch {
			case pe.Code == proto.CodeBusy:
				hint = fmt.Sprintf("at most %d commands run at once in a box; wait for one to finish", proto.DefaultMaxProcs)
			case pe.Code == proto.CodeNotFound && strings.HasPrefix(pe.Message, "start "):
				hint = "install it in the box or use an image that has it"
			}
		}
		res := map[string]any{"error": m2}
		data := map[string]any{"command": line, "error": m2}
		if req.Stdin {
			// the process may have read (and run) streamed stdin before it failed, was stopped or lost its client:
			// the run keeps the digest of what it was given on every path, not only a clean exit
			sum, n := stdin.digest()
			res["stdin_sha256"], res["stdin_bytes"] = sum, n
			data["stdin_sha256"], data["stdin_bytes"] = sum, n
		}
		complete("error", res)
		b.event(api.EventExecExited, "exec", "exec failed: "+m2, data)
		final(proto.TypeError, api.ErrorDetail{Code: code, Message: m2, Hint: hint})
		return
	}
	if over, n := stdin.truncated(); over {
		es.StdinTruncated = true
		es.StdinDroppedBytes += n
	}
	status := "ok"
	if es.Code != 0 || es.StdinTruncated {
		status = "error"
	}
	result := map[string]any{"exit_code": es.Code, "signal": es.Signal, "timed_out": es.TimedOut, "duration_ms": es.DurationMS}
	data := map[string]any{"command": line, "exit_code": es.Code, "signal": es.Signal, "timed_out": es.TimedOut, "duration_ms": es.DurationMS}
	summary := fmt.Sprintf("exec exited %d: %s", es.Code, line)
	if req.Stdin {
		// streamed stdin was not known when the command was decided: its digest is recorded with the outcome
		sum, n := stdin.digest()
		result["stdin_sha256"], result["stdin_bytes"] = sum, n
		data["stdin_sha256"], data["stdin_bytes"] = sum, n
	}
	if es.StdinTruncated {
		result["stdin_truncated"], result["stdin_dropped_bytes"] = true, es.StdinDroppedBytes
		data["stdin_truncated"], data["stdin_dropped_bytes"] = true, es.StdinDroppedBytes
		summary = fmt.Sprintf("exec stopped, its stdin was not consumed fast enough (%d bytes dropped): %s", es.StdinDroppedBytes, line)
	}
	complete(status, result)
	b.event(api.EventExecExited, "exec", summary, data)
	final(proto.TypeExit, es)
}

// denial is the message and hint of a refusal: the signer's own reason with the rule ids once, and a hint only when
// the signer gave no reason.
func denial(out tracekit.Outcome) (string, string) {
	rules := ""
	if len(out.RuleIDs) > 0 {
		rules = " [" + strings.Join(out.RuleIDs, ", ") + "]"
	}
	reason := ""
	if out.Decision.Decision == "deny" {
		reason = out.Decision.Reason
	}
	switch {
	case out.ApprovalID != "":
		return "denied by Tracekit policy" + rules + ": the approval " + out.ApprovalID + " was not given",
			"ask again and approve with `tracekit approvals approve <id>`"
	case reason != "":
		return "denied by Tracekit policy" + rules + ": " + reason, ""
	case out.Reason != "" && rules == "":
		return out.Reason, ""
	}
	return "denied by Tracekit policy" + rules, "run something the policy allows, or change the policy in Tracekit"
}

func nonEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// callTracker counts a box's in-flight gated calls (exec, egress decisions, apply) so the run is not closed under
// them.
type callTracker struct {
	mu   sync.Mutex
	n    int
	idle chan struct{} // closed while n == 0
}

func (c *callTracker) begin() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == 0 {
		c.idle = make(chan struct{})
	}
	c.n++
}

func (c *callTracker) end() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n--
	if c.n == 0 {
		close(c.idle)
	}
}

// inFlight is how many calls are in flight now.
func (c *callTracker) inFlight() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// wait waits until no call is in flight, at most d. It reports whether they all finished.
func (c *callTracker) wait(d time.Duration) bool {
	c.mu.Lock()
	if c.n == 0 {
		c.mu.Unlock()
		return true
	}
	idle := c.idle
	c.mu.Unlock()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-idle:
		return true
	case <-t.C:
		return false
	}
}
