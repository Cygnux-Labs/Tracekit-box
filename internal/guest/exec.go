//go:build unix

package guest

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// drainGrace is how long exec keeps reading stdout/stderr after the process exits: background children that still
// hold the pipes get this long to finish, then the pipes are closed (their next write gets EPIPE).
const drainGrace = 2 * time.Second

// signals the host may forward to an exec's process group.
var allowedSignals = map[string]syscall.Signal{
	"SIGINT":  syscall.SIGINT,
	"SIGTERM": syscall.SIGTERM,
	"SIGKILL": syscall.SIGKILL,
	"SIGHUP":  syscall.SIGHUP,
	"SIGQUIT": syscall.SIGQUIT,
}

func (s *Server) handleExec(c net.Conn, f proto.Frame, st *state) {
	var req proto.ExecRequest
	if err := f.Decode(&req); err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	if len(req.Argv) == 0 || req.Argv[0] == "" {
		sendError(c, proto.CodeBadRequest, "argv is empty")
		return
	}
	lim := effectiveLimits(st.cfg.Limits)
	if n := s.execs.Add(1); n > int64(lim.MaxProcs) {
		s.execs.Add(-1)
		sendError(c, proto.CodeBusy, fmt.Sprintf("%d execs already running (limits.max_procs)", lim.MaxProcs))
		return
	}
	defer s.execs.Add(-1)

	env, err := mergeEnv(st.cfg.Env, req.Env)
	if err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	cwd := req.Cwd
	if cwd == "" {
		cwd = "/"
		if st.ws != nil {
			cwd = st.ws.Path
		}
	}
	if !filepath.IsAbs(cwd) {
		sendError(c, proto.CodeBadRequest, "cwd must be absolute")
		return
	}
	if fi, err := os.Stat(cwd); err != nil || !fi.IsDir() {
		sendError(c, proto.CodeNotFound, fmt.Sprintf("cwd %s is not a directory", cwd))
		return
	}
	path, err := lookPath(req.Argv[0], envValue(env, "PATH"), cwd)
	if err != nil {
		sendError(c, proto.CodeNotFound, err.Error())
		return
	}
	for _, a := range req.Argv {
		if strings.IndexByte(a, 0) >= 0 {
			sendError(c, proto.CodeBadRequest, "argv contains a NUL byte")
			return
		}
	}

	ex, err := newExecPipes(req.Stdin)
	if err != nil {
		sendError(c, proto.CodeInternal, err.Error())
		return
	}
	defer ex.closeAll()
	start := time.Now()
	p, err := s.Spawner.Spawn(ProcSpec{
		Path: path, Argv: req.Argv, Env: env, Dir: cwd, UID: req.UID, GID: req.GID,
		Files: []uintptr{ex.childIn.Fd(), ex.outW.Fd(), ex.errW.Fd()},
	})
	ex.closeChildEnds()
	if err != nil {
		code := proto.CodeInternal
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) {
			code = proto.CodeNotFound
		} else if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) {
			code = proto.CodeBadRequest
		}
		sendError(c, code, fmt.Sprintf("start %s: %v", req.Argv[0], err))
		return
	}

	run := &execRun{conn: c, proc: p, maxOut: lim.MaxOutputBytes}
	var pumps sync.WaitGroup
	pumps.Add(2)
	go run.pump(ex.outR, proto.TypeStdout, &pumps)
	go run.pump(ex.errR, proto.TypeStderr, &pumps)

	hostGone := make(chan struct{})
	finished := make(chan struct{})
	defer close(finished)
	stdin := newStdinFeeder(ex.stdinW, finished)
	go run.readHost(stdin, hostGone, finished, s.logf)

	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if req.TimeoutMS <= 0 {
		timeout = time.Duration(lim.ExecTimeoutMS) * time.Millisecond
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var timedOut, gone bool
	select {
	case <-p.Done():
	case <-timer.C:
		timedOut = true
		p.Signal(syscall.SIGKILL)
		<-p.Done()
	case <-hostGone:
		gone = true
		p.Signal(syscall.SIGKILL)
		<-p.Done()
	}
	dur := time.Since(start)
	stdin.close()
	if timedOut || gone {
		// the group was killed; whatever is still in the pipes is the last output
		p.Signal(syscall.SIGKILL)
	}
	drained := make(chan struct{})
	go func() { pumps.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(drainGrace):
		ex.outR.Close()
		ex.errR.Close()
		<-drained
	}
	if gone {
		return
	}
	es := proto.ExitStatus{TimedOut: timedOut, DurationMS: dur.Milliseconds(), Truncated: run.truncated()}
	ws := p.Status()
	switch {
	case ws.Signaled():
		es.Code = -1
		es.Signal = unix.SignalName(ws.Signal())
		if es.Signal == "" {
			es.Signal = fmt.Sprintf("SIG%d", int(ws.Signal()))
		}
	default:
		es.Code = ws.ExitStatus()
	}
	run.wmu.Lock()
	defer run.wmu.Unlock()
	proto.WriteJSON(c, proto.TypeExit, es)
}

// execRun is the frame side of one running exec.
type execRun struct {
	conn   net.Conn
	proc   *Proc
	maxOut int64

	wmu    sync.Mutex // frame writes
	outN   int64
	trunc  bool
	broken bool
}

func (r *execRun) truncated() bool {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	return r.trunc
}

// pump forwards one output pipe as frames, counting against maxOut; it keeps draining past the cap so the process
// never blocks on a full pipe.
func (r *execRun) pump(f *os.File, typ byte, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 64<<10)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			r.write(typ, buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func (r *execRun) write(typ byte, b []byte) {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if r.broken {
		return
	}
	if room := r.maxOut - r.outN; int64(len(b)) > room {
		r.trunc = true
		b = b[:max(room, 0)]
	}
	if len(b) == 0 {
		return
	}
	r.outN += int64(len(b))
	if err := proto.WriteFrame(r.conn, typ, b); err != nil {
		// the host is gone: kill the group rather than run unobserved
		r.broken = true
		r.proc.Signal(syscall.SIGKILL)
	}
}

// readHost reads stdin and signal frames until the connection closes; a close before the exec finished means the
// host is gone.
func (r *execRun) readHost(stdin *stdinFeeder, hostGone, finished chan struct{}, logf func(string, ...any)) {
	for {
		f, err := proto.ReadFrame(r.conn)
		if err != nil {
			stdin.close()
			select {
			case <-finished:
			default:
				close(hostGone)
			}
			return
		}
		switch f.Type {
		case proto.TypeStdin:
			stdin.send(f.Payload)
		case proto.TypeStdinEOF:
			stdin.close()
		case proto.TypeSignal:
			var sig proto.Signal
			if err := f.Decode(&sig); err != nil {
				logf("exec: bad signal frame: %v", err)
				continue
			}
			if n, ok := allowedSignals[sig.Signal]; ok {
				r.proc.Signal(n)
			} else {
				logf("exec: signal %q not allowed", sig.Signal)
			}
		default:
			logf("exec: ignoring frame type %d", f.Type)
		}
	}
}

// stdinFeeder writes TypeStdin payloads to the child's stdin pipe on its own goroutine so a child that does not read
// stdin never blocks the frame reader (and with it signals and host-gone detection) for long.
type stdinFeeder struct {
	w        *os.File // nil when the exec has no stdin
	ch       chan []byte
	once     sync.Once
	finished <-chan struct{}
}

func newStdinFeeder(w *os.File, finished <-chan struct{}) *stdinFeeder {
	sf := &stdinFeeder{w: w, ch: make(chan []byte, 4), finished: finished}
	if w != nil {
		go func() {
			ok := true
			for b := range sf.ch {
				if ok {
					if _, err := w.Write(b); err != nil {
						ok = false // the child closed stdin: drop the rest
					}
				}
			}
			w.Close()
		}()
	}
	return sf
}

func (sf *stdinFeeder) send(b []byte) {
	if sf.w == nil {
		return
	}
	select {
	case sf.ch <- b:
	case <-sf.finished:
	}
}

func (sf *stdinFeeder) close() {
	sf.once.Do(func() {
		close(sf.ch)
	})
}

// execPipes are the child's stdio. The parent keeps stdinW (nil without stdin), outR and errR.
type execPipes struct {
	childIn, stdinW, outR, outW, errR, errW *os.File
}

func newExecPipes(withStdin bool) (*execPipes, error) {
	ex := &execPipes{}
	var err error
	if withStdin {
		if ex.childIn, ex.stdinW, err = os.Pipe(); err != nil {
			return nil, err
		}
	} else if ex.childIn, err = os.Open(os.DevNull); err != nil {
		return nil, err
	}
	if ex.outR, ex.outW, err = os.Pipe(); err != nil {
		ex.closeAll()
		return nil, err
	}
	if ex.errR, ex.errW, err = os.Pipe(); err != nil {
		ex.closeAll()
		return nil, err
	}
	return ex, nil
}

func (ex *execPipes) closeChildEnds() {
	for _, f := range []*os.File{ex.childIn, ex.outW, ex.errW} {
		if f != nil {
			f.Close()
		}
	}
}

func (ex *execPipes) closeAll() {
	for _, f := range []*os.File{ex.childIn, ex.stdinW, ex.outR, ex.outW, ex.errR, ex.errW} {
		if f != nil {
			f.Close()
		}
	}
}

// effectiveLimits fills zero limits with the protocol defaults.
func effectiveLimits(l proto.GuestLimits) proto.GuestLimits {
	if l.ExecTimeoutMS <= 0 {
		l.ExecTimeoutMS = proto.DefaultExecTimeoutMS
	}
	if l.MaxOutputBytes <= 0 {
		l.MaxOutputBytes = proto.DefaultMaxOutputBytes
	}
	if l.MaxProcs <= 0 {
		l.MaxProcs = proto.DefaultMaxProcs
	}
	return l
}

// mergeEnv returns base with every KEY=VALUE of over replacing the same key (in place) or appended.
func mergeEnv(base, over []string) ([]string, error) {
	out := make([]string, 0, len(base)+len(over))
	idx := map[string]int{}
	add := func(kv string, strict bool) error {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" || strings.IndexByte(kv, 0) >= 0 {
			if strict {
				return fmt.Errorf("env entry %q is not KEY=VALUE", kv)
			}
			return nil
		}
		if i, seen := idx[k]; seen {
			out[i] = kv
			return nil
		}
		idx[k] = len(out)
		out = append(out, kv)
		return nil
	}
	for _, kv := range base {
		add(kv, false)
	}
	for _, kv := range over {
		if err := add(kv, true); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func envValue(env []string, key string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// lookPath resolves name like execvp against pathEnv (the merged env's PATH, not the agent's own); relative entries
// and names with a slash resolve against dir.
func lookPath(name, pathEnv, dir string) (string, error) {
	if strings.Contains(name, "/") {
		p := name
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		if err := checkExecutable(p); err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		return p, nil
	}
	if pathEnv == "" {
		pathEnv = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	for _, d := range filepath.SplitList(pathEnv) {
		if d == "" {
			d = "."
		}
		p := filepath.Join(d, name)
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		if checkExecutable(p) == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: executable not found in PATH", name)
}

func checkExecutable(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if fi.IsDir() || fi.Mode()&0o111 == 0 {
		return fs.ErrPermission
	}
	return nil
}
