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

// maxEventLog caps events.ndjson: past it bulk lines (egress connections and refusals, signer problems) are dropped
// after one line saying so; must-record lines (lifecycle, execs, secrets, approvals, containment, apply) are kept.
const maxEventLog = 64 << 20

// EventLogCapped is the kind of the one line written when events.ndjson reaches maxEventLog.
const eventLogCapped = "events.capped"

// bulkEventKinds are the event kinds a guest can produce at will; they are the first to go when a cap is reached.
var bulkEventKinds = map[string]bool{api.EventEgressAllowed: true, api.EventEgressDenied: true,
	api.EventEgressClosed: true, api.EventSignerProblem: true}

// eventLog is a box's events.ndjson (0600, append only). Every line goes through the box's scrubber, so a secret value
// or placeholder never lands on disk even if a caller slips one into a summary.
type eventLog struct {
	path      string
	mu        sync.Mutex
	f         *os.File
	size      int64
	sized     bool
	capped    bool
	transient bool          // the box is down: open the file per write instead of holding it
	notify    chan struct{} // closed and replaced on every write (followers wait on it)
	max       int64
}

func openEventLog(dir string) *eventLog {
	return &eventLog{path: filepath.Join(dir, "events.ndjson"), notify: make(chan struct{}), max: maxEventLog}
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
		if !l.sized {
			if fi, err := f.Stat(); err == nil {
				l.size = fi.Size()
			}
			l.sized = true
		}
	}
	if l.transient {
		defer func() { l.f.Close(); l.f = nil }()
	}
	if l.size+int64(len(b)) > l.max && bulkEventKinds[e.Kind] {
		if l.capped {
			return nil
		}
		l.capped = true
		capLine, _ := json.Marshal(api.Event{Time: e.Time, BoxID: e.BoxID, Kind: eventLogCapped, Door: "lifecycle",
			Summary: fmt.Sprintf("events.ndjson reached %d MiB: egress and signer-problem lines are no longer written (lifecycle, exec, secret, approval, containment and apply lines still are)", l.max>>20)})
		b = append(capLine, '\n')
	}
	n, err := l.f.Write(b)
	l.size += int64(n)
	close(l.notify)
	l.notify = make(chan struct{})
	return err
}

// release closes the file once the box is down; later lines (apply decisions) open it per write.
func (l *eventLog) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.transient = true
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
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
	l.transient = true
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

// Observes go to the signer in two lanes. Must-record observes (secret use and leaks, model calls, approvals,
// containment) are never dropped: when one can't be queued or the signer refuses it, the box is stopped (fail
// closed). Bulk observes (the refusals Box makes itself, which a guest can produce at will) are rate-limited to
// bulkRate a second per box; the rest are counted in a summary observe once a second.
const (
	mustQueue = 4096
	bulkQueue = 256
	bulkRate  = 20
)

type observer struct {
	must   chan observation
	bulk   chan observation
	ctx    context.Context // cancelled when a flush gives up: the rest is dropped instead of waiting on a hung signer
	cancel context.CancelFunc
	done   chan struct{}

	// guarded by box.mu
	tokens     float64
	last       time.Time
	suppressed int
}

type observation struct {
	source string
	trust  string
	value  any
}

func (b *box) startObserver(run tracekit.Run) {
	ctx, cancel := context.WithCancel(b.d.ctx)
	o := &observer{must: make(chan observation, mustQueue), bulk: make(chan observation, bulkQueue), ctx: ctx,
		cancel: cancel, done: make(chan struct{}), tokens: bulkRate, last: time.Now()}
	b.mu.Lock()
	b.obs = o
	b.mu.Unlock()
	send := func(ob observation, must bool) {
		if o.ctx.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(o.ctx, 30*time.Second)
		err := run.Observe(ctx, ob.source, ob.trust, ob.value)
		cancel()
		if err == nil || o.ctx.Err() != nil {
			return
		}
		b.event(api.EventSignerProblem, "lifecycle", fmt.Sprintf("observe %s failed: %v", ob.source, err), nil)
		if must {
			b.failClosed(ob.source, err)
		}
	}
	summary := func() {
		b.mu.Lock()
		n := o.suppressed
		o.suppressed = 0
		b.mu.Unlock()
		if n > 0 {
			send(observation{tracekit.SourceEgress, untrustedObs, map[string]any{"decision": "deny", "summary": true,
				"suppressed": n, "reason": fmt.Sprintf("%d more refusals Box made itself were not recorded one by one (at most %d a second)", n, bulkRate)}}, false)
		}
	}
	drain := func() { // the run is closing: send what is queued, then the last summary
		for {
			select {
			case ob := <-o.bulk:
				send(ob, false)
			default:
				summary()
				return
			}
		}
	}
	go func() {
		defer close(o.done)
		defer cancel()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select { // must-record observes first
			case ob, ok := <-o.must:
				if !ok {
					drain()
					return
				}
				send(ob, true)
				continue
			default:
			}
			select {
			case ob, ok := <-o.must:
				if !ok {
					drain()
					return
				}
				send(ob, true)
			case ob := <-o.bulk:
				send(ob, false)
			case <-tick.C:
				summary()
			}
		}
	}()
}

// failClosed stops a box whose must-record observe could not be recorded.
func (b *box) failClosed(source string, err error) {
	reason := "could not record " + source + " in Tracekit, so the box was stopped (fail closed)"
	b.event(api.EventSignerProblem, "lifecycle", reason+": "+err.Error(), nil)
	b.d.log.Printf("%s: %s: %v", b.id, reason, err)
	go b.stop(context.Background(), reason, false)
}

// observe queues one observe (no-op when unrecorded). It never blocks.
func (b *box) observe(source, trust string, value any) {
	value = b.scrub().value(value)
	ob := observation{source, trust, value}
	bulk := source == tracekit.SourceEgress
	b.mu.Lock()
	o := b.obs
	if o == nil || b.obsClosed {
		b.mu.Unlock()
		if o != nil {
			b.event(api.EventSignerProblem, "lifecycle", "not recorded, the run is closing: a "+source+" record", nil)
		}
		return
	}
	if bulk {
		now := time.Now()
		o.tokens = min(bulkRate, o.tokens+now.Sub(o.last).Seconds()*bulkRate)
		o.last = now
		queued := false
		if o.tokens >= 1 {
			select {
			case o.bulk <- ob:
				o.tokens--
				queued = true
			default:
			}
		}
		if !queued {
			o.suppressed++
		}
		b.mu.Unlock()
		return
	}
	select {
	case o.must <- ob:
		b.mu.Unlock()
	default:
		b.mu.Unlock()
		b.failClosed(source, fmt.Errorf("%d records are already waiting for the signer", mustQueue))
	}
}

// flushObserver stops taking observes and waits until the queued ones reached the signer, or ctx ends (then the rest
// is dropped and the observer stops at once).
func (b *box) flushObserver(ctx context.Context) {
	b.mu.Lock()
	o := b.obs
	already := b.obsClosed
	b.obsClosed = true
	if o != nil && !already {
		close(o.must)
	}
	b.mu.Unlock()
	if o == nil {
		return
	}
	select {
	case <-o.done:
	case <-ctx.Done():
		o.cancel()
		b.event(api.EventSignerProblem, "lifecycle", "the signer did not take the last records in time; they were dropped", nil)
	}
}
