//go:build linux

package guest

import (
	"sync"
	"syscall"
	"time"
)

// Reaper is the Spawner for PID 1: one wait4(-1) loop reaps every child, including orphans reparented to init, and
// hands exec children their status by pid. Nothing else in the process may call wait (os/exec's Wait would race it).
type Reaper struct {
	mu    sync.Mutex
	procs map[int]*Proc
	kick  chan struct{}
}

// NewReaper starts the reap loop.
func NewReaper() *Reaper {
	r := &Reaper{procs: map[int]*Proc{}, kick: make(chan struct{}, 1)}
	go r.loop()
	return r
}

// Spawn forks under the lock so the loop cannot look up a pid before it is registered.
func (r *Reaper) Spawn(spec ProcSpec) (*Proc, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pid, err := forkExec(spec)
	if err != nil {
		return nil, err
	}
	p := newProc(pid)
	r.procs[pid] = p
	select {
	case r.kick <- struct{}{}:
	default:
	}
	return p, nil
}

func (r *Reaper) loop() {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		switch {
		case err == syscall.EINTR:
			continue
		case err == syscall.ECHILD:
			<-r.kick // no children until the next Spawn
			continue
		case err != nil:
			time.Sleep(10 * time.Millisecond)
			continue
		}
		r.mu.Lock()
		p := r.procs[pid]
		delete(r.procs, pid)
		r.mu.Unlock()
		if p != nil {
			p.finish(ws)
		}
	}
}
