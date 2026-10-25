package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/egress"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// eventLog is a box's events.ndjson (0600, append only). Every line goes through the box's scrubber, so a secret value
// or placeholder never lands on disk even if a caller slips one into a summary.
type eventLog struct {
	path   string
	mu     sync.Mutex
	f      *os.File
	notify chan struct{} // closed and replaced on every write (followers wait on it)
}

func openEventLog(dir string) *eventLog {
	return &eventLog{path: filepath.Join(dir, "events.ndjson"), notify: make(chan struct{})}
}

func (l *eventLog) write(e api.Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		l.f = f
	}
	_, err = l.f.Write(b)
	close(l.notify)
	l.notify = make(chan struct{})
	return err
}

func (l *eventLog) wait() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.notify
}

func (l *eventLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
	close(l.notify)
	l.notify = make(chan struct{})
}

// stream copies events.ndjson to w; with follow it keeps going until the box is no longer alive or ctx ends.
func (l *eventLog) stream(ctx context.Context, w io.Writer, flush func(), follow bool, alive func() bool) error {
	var off int64
	for {
		wait := l.wait()
		live := alive()
		f, err := os.Open(l.path)
		if err == nil {
			if _, err = f.Seek(off, io.SeekStart); err == nil {
				var n int64
				n, err = io.Copy(w, f)
				off += n
			}
			f.Close()
			if err != nil {
				return err
			}
			if flush != nil {
				flush()
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if !follow || !live {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-wait:
		case <-time.After(2 * time.Second):
		}
	}
}

// scrubber replaces every secret value and placeholder of a box with "[secret NAME]".
type scrubber struct {
	pairs []string // old, new, … for strings.NewReplacer
	r     *strings.Replacer
}

func newScrubber(secrets []egress.Secret) *scrubber {
	s := &scrubber{}
	for _, sec := range secrets {
		tag := "[secret " + sec.Name + "]"
		if sec.Value != "" {
			s.pairs = append(s.pairs, sec.Value, tag)
		}
		if sec.Placeholder != "" {
			s.pairs = append(s.pairs, sec.Placeholder, tag)
		}
	}
	if len(s.pairs) > 0 {
		s.r = strings.NewReplacer(s.pairs...)
	}
	return s
}

func (s *scrubber) str(v string) string {
	if s == nil || s.r == nil {
		return v
	}
	return s.r.Replace(v)
}

// value scrubs strings inside maps and slices built from JSON-ish values.
func (s *scrubber) value(v any) any {
	if s == nil || s.r == nil {
		return v
	}
	switch t := v.(type) {
	case string:
		return s.str(t)
	case []string:
		out := make([]string, len(t))
		for i, x := range t {
			out[i] = s.str(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = s.value(x)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[s.str(k)] = s.value(x)
		}
		return out
	default:
		return v
	}
}

// event records one line in events.ndjson.
func (b *box) event(kind, door, summary string, data map[string]any) {
	sc := b.scrub()
	e := api.Event{Time: b.d.now().UTC(), BoxID: b.id, Kind: kind, Door: door, Summary: sc.str(summary)}
	if len(data) > 0 {
		e.Data = sc.value(data).(map[string]any)
	}
	if err := b.events.write(e); err != nil {
		b.d.log.Printf("%s: events.ndjson: %v", b.id, err)
	}
}

// observer queues observe calls in order so the proxy's goroutines never wait on the signer.
type observer struct {
	ch   chan observation
	done chan struct{}
}

type observation struct {
	source string
	trust  string
	value  any
}

const observeQueue = 4096

func (b *box) startObserver(run tracekit.Run) {
	o := &observer{ch: make(chan observation, observeQueue), done: make(chan struct{})}
	b.obs = o
	go func() {
		defer close(o.done)
		for ob := range o.ch {
			ctx, cancel := context.WithTimeout(b.d.ctx, 30*time.Second)
			err := run.Observe(ctx, ob.source, ob.trust, ob.value)
			cancel()
			if err != nil {
				b.event(api.EventSignerProblem, "lifecycle", fmt.Sprintf("observe %s failed: %v", ob.source, err), nil)
			}
		}
	}()
}

// observe queues one observe (no-op when unrecorded). It never blocks: a full queue drops the record and says so.
func (b *box) observe(source, trust string, value any) {
	value = b.scrub().value(value)
	dropped := false
	b.mu.Lock()
	if b.obs != nil && !b.obsClosed {
		select {
		case b.obs.ch <- observation{source, trust, value}:
		default:
			dropped = true
		}
	}
	b.mu.Unlock()
	if dropped {
		b.event(api.EventSignerProblem, "lifecycle", "observe queue full: a "+source+" record was dropped", nil)
	}
}

// flushObserver stops taking observes and waits until the queued ones reached the signer (or ctx ends).
func (b *box) flushObserver(ctx context.Context) {
	b.mu.Lock()
	o := b.obs
	already := b.obsClosed
	b.obsClosed = true
	if o != nil && !already {
		close(o.ch)
	}
	b.mu.Unlock()
	if o == nil {
		return
	}
	select {
	case <-o.done:
	case <-ctx.Done():
	}
}
