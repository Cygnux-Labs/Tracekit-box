package egress

import (
	"fmt"
	"slices"
	"sync"
	"time"
)

// eventLimiter bounds what a guest can make the proxy record, since every refusal is cheap to provoke and the Sink
// writes to disk and to the signer. Per window, egress.denied events beyond deniedPerWindow are counted and recorded
// as one summary; secret.leak events are never dropped, but an identical one repeated back to back within a window
// is recorded once and then as a count. Summaries are written when the window ends, or at Close.
type eventLimiter struct {
	mu     sync.Mutex
	closed bool

	winStart time.Time
	denied   int // recorded one by one in this window
	dropped  int // counted only
	dTimer   *time.Timer

	leak    Event // the last secret.leak recorded
	leakAt  time.Time
	repeats int
	lTimer  *time.Timer
}

// emit records an egress.denied or secret.leak event through the limits. The Sink is called with mu held so a
// summary always precedes the event that ends its window.
func (l *eventLimiter) emit(p *Proxy, e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch e.Kind {
	case EventDenied:
		if e.Time.Sub(l.winStart) >= eventWindow {
			l.flushDenied(p)
			l.winStart, l.denied = e.Time, 0
		}
		if l.denied < deniedPerWindow {
			l.denied++
			p.cfg.Sink.Emit(e)
			return
		}
		l.dropped++
		if l.dTimer == nil && !l.closed {
			l.dTimer = time.AfterFunc(time.Until(l.winStart.Add(eventWindow)), func() {
				l.mu.Lock()
				defer l.mu.Unlock()
				l.flushDenied(p)
			})
		}
	case EventSecretLeak:
		if !l.leakAt.IsZero() && sameLeak(l.leak, e) && e.Time.Sub(l.leakAt) < eventWindow {
			l.repeats++
			if l.lTimer == nil && !l.closed {
				l.lTimer = time.AfterFunc(time.Until(l.leakAt.Add(eventWindow)), func() {
					l.mu.Lock()
					defer l.mu.Unlock()
					l.flushLeak(p)
				})
			}
			return
		}
		l.flushLeak(p)
		l.leak, l.leakAt = e, e.Time
		p.cfg.Sink.Emit(e)
	}
}

func sameLeak(a, b Event) bool {
	return a.Host == b.Host && a.Port == b.Port && a.Method == b.Method && a.Path == b.Path && a.Secret == b.Secret &&
		a.Reason == b.Reason && slices.Equal(a.RuleIDs, b.RuleIDs)
}

func (l *eventLimiter) flushDenied(p *Proxy) {
	if l.dTimer != nil {
		l.dTimer.Stop()
		l.dTimer = nil
	}
	if l.dropped == 0 {
		return
	}
	n := l.dropped
	l.dropped = 0
	p.cfg.Sink.Emit(Event{Time: time.Now(), Kind: EventDenied,
		Reason: fmt.Sprintf("%d more refusals in the last second (Box records at most %d a second one by one)", n, deniedPerWindow)})
}

func (l *eventLimiter) flushLeak(p *Proxy) {
	if l.lTimer != nil {
		l.lTimer.Stop()
		l.lTimer = nil
	}
	if l.repeats == 0 {
		return
	}
	e := l.leak
	e.Time = time.Now()
	e.Reason = fmt.Sprintf("%s (repeated %d more times in the last second)", e.Reason, l.repeats)
	l.repeats = 0
	p.cfg.Sink.Emit(e)
}

// close writes the pending summaries and stops the timers.
func (l *eventLimiter) close(p *Proxy) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	l.flushDenied(p)
	l.flushLeak(p)
}
