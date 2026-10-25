//go:build unix

package guest

import (
	"syscall"
)

// ProcSpec is one process to start in its own process group.
type ProcSpec struct {
	Path  string   // resolved executable
	Argv  []string // argv[0] included
	Env   []string
	Dir   string
	UID   uint32
	GID   uint32
	Files []uintptr // fds 0, 1, 2 of the child
}

// Spawner starts processes and reports their exit. In the VM it is the Reaper (PID 1 must own every wait4); in tests
// and on macOS it is WaitSpawner.
type Spawner interface {
	Spawn(spec ProcSpec) (*Proc, error)
}

// Proc is a started process; its pid is also its process group id.
type Proc struct {
	Pid    int
	done   chan struct{}
	status syscall.WaitStatus
}

func newProc(pid int) *Proc { return &Proc{Pid: pid, done: make(chan struct{})} }

func (p *Proc) finish(ws syscall.WaitStatus) {
	p.status = ws
	close(p.done)
}

// Done is closed when the process has been reaped.
func (p *Proc) Done() <-chan struct{} { return p.done }

// Status is the wait status, valid after Done.
func (p *Proc) Status() syscall.WaitStatus { return p.status }

// Signal delivers sig to the whole process group.
func (p *Proc) Signal(sig syscall.Signal) error { return syscall.Kill(-p.Pid, sig) }

// forkExec starts spec in a new process group. It never waits for the child.
func forkExec(spec ProcSpec) (int, error) {
	sys := &syscall.SysProcAttr{Setpgid: true}
	if spec.UID != 0 || spec.GID != 0 {
		sys.Credential = &syscall.Credential{Uid: spec.UID, Gid: spec.GID}
	}
	return syscall.ForkExec(spec.Path, spec.Argv, &syscall.ProcAttr{
		Dir:   spec.Dir,
		Env:   spec.Env,
		Files: spec.Files,
		Sys:   sys,
	})
}

// WaitSpawner waits for each child by pid on its own goroutine. Use it only where nothing else reaps children
// (not as PID 1, where orphans must be reaped too: use Reaper).
type WaitSpawner struct{}

func (WaitSpawner) Spawn(spec ProcSpec) (*Proc, error) {
	pid, err := forkExec(spec)
	if err != nil {
		return nil, err
	}
	p := newProc(pid)
	go func() {
		var ws syscall.WaitStatus
		for {
			_, err := syscall.Wait4(pid, &ws, 0, nil)
			if err == syscall.EINTR {
				continue
			}
			if err != nil {
				ws = syscall.WaitStatus(0xff << 8) // unknown: report exit 255 rather than hang
			}
			break
		}
		p.finish(ws)
	}()
	return p, nil
}
