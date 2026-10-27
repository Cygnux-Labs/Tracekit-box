package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
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

// maxEventLogHard caps events.ndjson as a whole: past it no line is written except what stopping the box writes
// (at most eventLogReserve more), and the box is stopped ("events log over its hard cap"). A var for tests.
var maxEventLogHard int64 = 256 << 20

const eventLogReserve = 1 << 20

// eventLogHardCapReason is the stop reason of a box whose events.ndjson reached maxEventLogHard.
const eventLogHardCapReason = "events log over its hard cap"

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
	hardMax   int64
	hardHit   bool   // hardMax reached: only the reserve is left
	onHardCap func() // called once (on its own goroutine) when hardMax is reached
}

func openEventLog(dir string) *eventLog {
	return &eventLog{path: filepath.Join(dir, "events.ndjson"), notify: make(chan struct{}), max: maxEventLog, hardMax: maxEventLogHard}
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
	if l.hardMax > 0 && l.size+int64(len(b)) > l.hardMax {
		if l.hardHit {
			if bulkEventKinds[e.Kind] || l.size+int64(len(b)) > l.hardMax+eventLogReserve {
				return nil // the reserve is for the box's stop lines
			}
		} else {
			l.hardHit = true
			capLine, _ := json.Marshal(api.Event{Time: e.Time, BoxID: e.BoxID, Kind: eventLogCapped, Door: "lifecycle",
				Summary: fmt.Sprintf("events.ndjson reached its hard cap of %d MiB: no more lines are written and the box is stopped", l.hardMax>>20)})
			b = append(capLine, '\n')
			if l.onHardCap != nil {
				go l.onHardCap()
			}
		}
	} else if l.size+int64(len(b)) > l.max && bulkEventKinds[e.Kind] {
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
	left  *strings.Replacer // see unrebuild
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
		s.left = unrebuild(secrets)
	}
	return s
}

// unrebuild returns a replacer that turns each secret value into a run of a filler no value holds a byte of, for
// after the tags go in: a tag (or a placeholder's mark) can complete a value with the text around it ("]abc…" before
// its own tail, or a value inside "secret NAME"). No value can take in a byte of such a run, so after the one leftmost
// pass none is left. nil when no secret has a value.
func unrebuild(secrets []egress.Secret) *strings.Replacer {
	free := func(fill string) bool { // byte by byte: no value may hold any byte of the filler
		for i := 0; i < len(fill); i++ {
			if slices.ContainsFunc(secrets, func(s egress.Secret) bool { return strings.IndexByte(s.Value, fill[i]) >= 0 }) {
				return false
			}
		}
		return true
	}
	// records are JSON, so a filler JSON writes as it is: "*#~", then other printable ASCII, then a non-ASCII
	// character (values that together hold every printable character, as several strong random passwords can, hold
	// none of these as a rule); any other byte only after that, and no value holds a NUL (the daemon refuses one)
	var cands []string
	for _, c := range "*#~" {
		cands = append(cands, string(c))
	}
	for c := byte('!'); c <= '~'; c++ {
		if !strings.ContainsRune(`"\<>&*#~`, rune(c)) {
			cands = append(cands, string(rune(c)))
		}
	}
	cands = append(cands, "·", "•", "░", "█")
	for c := 1; c < 256; c++ {
		cands = append(cands, string([]byte{byte(c)}))
	}
	fill := "\x00"
	for _, c := range cands {
		if free(c) {
			fill = c
			break
		}
	}
	var pairs []string
	for _, s := range secrets {
		if s.Value != "" {
			pairs = append(pairs, s.Value, strings.Repeat(fill, len(s.Value)))
		}
	}
	if len(pairs) == 0 {
		return nil
	}
	return strings.NewReplacer(pairs...)
}

func (s *scrubber) str(v string) string {
	if s == nil || s.r == nil {
		return v
	}
	v = s.r.Replace(v)
	if s.left != nil {
		v = s.left.Replace(v)
	}
	return v
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
// bulkRate a second per box; the rest are counted in a summary observe once a second. Refusals that never reach the
// signer (a summary stands for the ones it counts) are counted in the tkbox.gap record, without stopping the box.
const (
	bulkQueue = 256
	bulkRate  = 20
)

// mustQueue is how many must-record observes may wait for the signer (a var for tests).
var mustQueue = 4096

// sourceGap is the observe that records observes that never reached the signer:
// {kind: their source, dropped: how many, reason}.
const sourceGap = "tkbox.gap"

// gap counts the observes of one source that were lost.
type gap struct {
	dropped int
	reason  string
}

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
	gaps       map[string]*gap // observes lost, by source
	gapsTaken  bool            // recordGaps took gaps: a later loss is recorded on its own (recordLoss)
}

// gapComplete is the tkbox.gap kind of completes that never reached the signer.
const gapComplete = "complete"

// completeFailed handles a complete the signer refused or never answered: the decided call then has no recorded
// outcome, so it is counted into the box's tkbox.gap record (kind "complete") like a lost observe.
func (b *box) completeFailed(door string, err error) {
	b.event(api.EventSignerProblem, door, "complete failed: "+err.Error(), nil)
	b.recordLoss(gapComplete, door, "the signer refused it or did not answer: "+err.Error())
}

// recordLoss counts one must-record record of kind that never reached the signer. While the box is up it joins the
// gaps teardown records; afterwards (an apply of a stopped box, or a record that failed after teardown recorded the
// gaps) a tkbox.gap record is sent for it at once.
func (b *box) recordLoss(kind, door, reason string) {
	b.mu.Lock()
	o, run := b.obs, b.run
	if o != nil && !o.gapsTaken {
		o.lost(kind, reason, 1)
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()
	if run == nil {
		return
	}
	ctx, cancel := context.WithTimeout(b.d.ctx, 30*time.Second)
	defer cancel()
	if gerr := run.Observe(ctx, sourceGap, trustedObs, map[string]any{"kind": kind, "dropped": 1, "reason": reason}); gerr != nil {
		b.event(api.EventSignerProblem, door, "a "+kind+" record was lost and the loss could not be recorded: "+gerr.Error(), nil)
		b.d.log.Printf("WARNING: box %s: a %s record was lost and the loss could not be recorded in Tracekit: %v", b.id, kind, gerr)
	}
}

// lost counts n records of source that will never reach the signer (caller holds box.mu).
func (o *observer) lost(source, reason string, n int) {
	if o.gaps == nil {
		o.gaps = map[string]*gap{}
	}
	g := o.gaps[source]
	if g == nil {
		g = &gap{reason: reason}
		o.gaps[source] = g
	}
	g.dropped += n
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
	// send sends ob, which stands for n records; if they never reach the signer they are counted for the tkbox.gap
	// record, and a must-record one the signer refused stops the box
	send := func(ob observation, must bool, n int) {
		if o.ctx.Err() != nil {
			b.mu.Lock()
			o.lost(ob.source, "the signer did not take it before the box stopped", n)
			b.mu.Unlock()
			return
		}
		ctx, cancel := context.WithTimeout(o.ctx, 30*time.Second)
		err := run.Observe(ctx, ob.source, ob.trust, ob.value)
		cancel()
		if err == nil {
			return
		}
		if o.ctx.Err() != nil {
			b.mu.Lock()
			o.lost(ob.source, "the signer did not take it before the box stopped", n)
			b.mu.Unlock()
			return
		}
		b.event(api.EventSignerProblem, "lifecycle", fmt.Sprintf("observe %s failed: %v", ob.source, err), nil)
		b.mu.Lock()
		o.lost(ob.source, "the signer refused it or did not answer: "+err.Error(), n)
		b.mu.Unlock()
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
				"suppressed": n, "reason": fmt.Sprintf("%d more refusals Box made itself were not recorded one by one (at most %d a second)", n, bulkRate)}}, false, n)
		}
	}
	drain := func() { // the run is closing: send what is queued, then the last summary
		for {
			select {
			case ob := <-o.bulk:
				send(ob, false, 1)
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
				send(ob, true, 1)
				continue
			default:
			}
			select {
			case ob, ok := <-o.must:
				if !ok {
					drain()
					return
				}
				send(ob, true, 1)
			case ob := <-o.bulk:
				send(ob, false, 1)
			case <-tick.C:
				summary()
			}
		}
	}()
}

// failClosed stops a box whose must-record observe could not be recorded.
func (b *box) failClosed(source string, err error) {
	b.mu.Lock()
	already := b.failedClosed
	b.failedClosed = true
	b.mu.Unlock()
	if already {
		return // the box is already going down; the loss is counted for its tkbox.gap record
	}
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
		if o != nil {
			o.lost(source, "it came after the box started closing its run", 1)
		}
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
		o.lost(source, fmt.Sprintf("%d records were already waiting for the signer", mustQueue), 1)
		b.mu.Unlock()
		b.failClosed(source, fmt.Errorf("%d records are already waiting for the signer", mustQueue))
	}
}

// recordGaps records, once the observer has drained, every observe that never reached the signer
// (observe tkbox.gap). It returns a close reason naming what was lost when even that could not be recorded.
func (b *box) recordGaps(ctx context.Context, run tracekit.Run) string {
	b.mu.Lock()
	var gaps map[string]*gap
	if b.obs != nil {
		gaps, b.obs.gaps = b.obs.gaps, nil
		b.obs.gapsTaken = true
	}
	b.mu.Unlock()
	if len(gaps) == 0 {
		return ""
	}
	sources := make([]string, 0, len(gaps))
	for s := range gaps {
		sources = append(sources, s)
	}
	sort.Strings(sources)
	var unrecorded []string
	for _, s := range sources {
		g := gaps[s]
		b.event(api.EventSignerProblem, "lifecycle", fmt.Sprintf("%d %s records never reached the signer: %s", g.dropped, s, g.reason),
			map[string]any{"kind": s, "dropped": g.dropped})
		if err := run.Observe(ctx, sourceGap, trustedObs, map[string]any{"kind": s, "dropped": g.dropped, "reason": g.reason}); err != nil {
			unrecorded = append(unrecorded, fmt.Sprintf("%d %s records lost (%s)", g.dropped, s, g.reason))
		}
	}
	if len(unrecorded) == 0 {
		return ""
	}
	return "records lost and the loss could not be recorded: " + strings.Join(unrecorded, "; ")
}

// observerFlushWait bounds how long a stopping box waits for the signer to take the observes still queued.
var observerFlushWait = 30 * time.Second

// observerStopWait bounds how long a flush that gave up waits for the observer to stop counting what it drops.
var observerStopWait = 5 * time.Second

// flushObserver stops taking observes and waits until the queued ones reached the signer, or ctx ends: then the rest
// is dropped (each one counted for the tkbox.gap record) and it waits, at most observerStopWait, for the observer to
// stop. It reports whether the observer stopped: only then is every loss counted.
func (b *box) flushObserver(ctx context.Context) bool {
	b.mu.Lock()
	o := b.obs
	already := b.obsClosed
	b.obsClosed = true
	if o != nil && !already {
		close(o.must)
	}
	b.mu.Unlock()
	if o == nil {
		return true
	}
	select {
	case <-o.done:
		return true
	case <-ctx.Done():
	}
	o.cancel()
	b.event(api.EventSignerProblem, "lifecycle", "the signer did not take the last records in time; they were dropped", nil)
	t := time.NewTimer(observerStopWait)
	defer t.Stop()
	select {
	case <-o.done:
		return true
	case <-t.C:
		b.event(api.EventSignerProblem, "lifecycle", fmt.Sprintf("the observer did not stop within %s of giving up on the signer: how many records were lost is not known", observerStopWait), nil)
		return false
	}
}

// lostSince counts the observes lost since recordGaps took the gaps (the observer was still running).
func (b *box) lostSince() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	if b.obs != nil {
		for _, g := range b.obs.gaps {
			n += g.dropped
		}
	}
	return n
}
