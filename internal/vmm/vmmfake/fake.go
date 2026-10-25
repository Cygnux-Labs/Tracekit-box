// Package vmmfake is an in-memory vmm.Launcher for tests without KVM. A fake Machine serves Dial(port) by handing one
// end of a net.Pipe to the handler registered for that port, and Listen(port) returns a listener the test can
// connect to with GuestDial (as the guest would).
package vmmfake

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/Cygnux-Labs/tracekit-box/internal/vmm"
)

// Handler serves one host→guest connection (the guest side of the pipe).
type Handler func(conn net.Conn)

type Launcher struct {
	mu       sync.Mutex
	Machines []*Machine
	// Handlers are copied into every new Machine: port → guest-side handler.
	Handlers map[uint32]Handler
	CheckErr error
	NewErr   error
	// OnStart runs in its own goroutine when a machine starts (e.g. a fake guest dialling the config port).
	OnStart func(m *Machine)
}

func (l *Launcher) New(spec vmm.Spec) (vmm.Machine, error) {
	if l.NewErr != nil {
		return nil, l.NewErr
	}
	m := &Machine{Spec: spec, handlers: map[uint32]Handler{}, listeners: map[uint32]*pipeListener{},
		done: make(chan struct{}), onStart: l.OnStart}
	for p, h := range l.Handlers {
		m.handlers[p] = h
	}
	l.mu.Lock()
	l.Machines = append(l.Machines, m)
	l.mu.Unlock()
	return m, nil
}

func (l *Launcher) Check() error { return l.CheckErr }

type Machine struct {
	Spec      vmm.Spec
	mu        sync.Mutex
	handlers  map[uint32]Handler
	listeners map[uint32]*pipeListener
	State     string // "new", "running", "paused", "stopped"
	done      chan struct{}
	once      sync.Once
	err       error
	onStart   func(m *Machine)
}

func (m *Machine) ID() string { return m.Spec.ID }

func (m *Machine) Listen(port uint32) (net.Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.listeners[port]; ok {
		return nil, errors.New("vmmfake: port already listening")
	}
	l := &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
	m.listeners[port] = l
	return l, nil
}

// GuestDial connects to a host listener as the guest would.
func (m *Machine) GuestDial(ctx context.Context, port uint32) (net.Conn, error) {
	m.mu.Lock()
	l := m.listeners[port]
	m.mu.Unlock()
	if l == nil {
		return nil, errors.New("vmmfake: nothing listening on that port")
	}
	host, guest := net.Pipe()
	select {
	case l.conns <- host:
		return guest, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *Machine) Start(ctx context.Context) error {
	m.mu.Lock()
	m.State = "running"
	m.mu.Unlock()
	if m.onStart != nil {
		go m.onStart(m)
	}
	return nil
}

func (m *Machine) Dial(ctx context.Context, port uint32) (net.Conn, error) {
	m.mu.Lock()
	h, state := m.handlers[port], m.State
	m.mu.Unlock()
	if state != "running" {
		return nil, errors.New("vmmfake: machine not running")
	}
	if h == nil {
		return nil, errors.New("vmmfake: connection refused")
	}
	host, guest := net.Pipe()
	go h(guest)
	return host, nil
}

func (m *Machine) set(s string) { m.mu.Lock(); m.State = s; m.mu.Unlock() }

func (m *Machine) Pause(context.Context) error  { m.set("paused"); return nil }
func (m *Machine) Resume(context.Context) error { m.set("running"); return nil }

func (m *Machine) Shutdown(context.Context) error { return m.stop(nil) }
func (m *Machine) Kill() error                    { return m.stop(errors.New("killed")) }

func (m *Machine) stop(err error) error {
	m.once.Do(func() {
		m.set("stopped")
		m.err = err
		m.mu.Lock()
		for _, l := range m.listeners {
			l.Close()
		}
		m.mu.Unlock()
		close(m.done)
	})
	return nil
}

func (m *Machine) Done() <-chan struct{} { return m.done }
func (m *Machine) Err() error            { return m.err }
func (m *Machine) PID() int              { return 4242 }
func (m *Machine) ConsolePath() string   { return "" }

type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "vmmfake" }
