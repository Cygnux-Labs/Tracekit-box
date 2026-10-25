package vmm

import (
	"fmt"
	"io"
	"sync"
)

// DefaultMaxConsoleBytes caps console.log when Spec.MaxConsoleBytes is 0.
const DefaultMaxConsoleBytes = 8 << 20

const consoleTailBytes = 2 << 10

// capWriter writes up to max bytes to w and drops the rest, noting the cut once. It never fails a write: a VMM
// blocked on a full stdout pipe would stall the guest. It keeps the last consoleTailBytes (dropped or not) for
// error messages.
type capWriter struct {
	mu      sync.Mutex
	w       io.Writer
	max     int64
	n       int64
	dropped bool
	failed  bool
	tail    []byte
}

func newCapWriter(w io.Writer, max int64) *capWriter {
	if max <= 0 {
		max = DefaultMaxConsoleBytes
	}
	return &capWriter{w: w, max: max}
}

func (c *capWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keepTail(p)
	if c.failed {
		return len(p), nil
	}
	keep := p
	if room := c.max - c.n; int64(len(keep)) > room {
		keep = keep[:max(room, 0)]
	}
	if len(keep) > 0 {
		n, err := c.w.Write(keep)
		c.n += int64(n)
		if err != nil {
			c.failed = true
			return len(p), nil
		}
	}
	if len(keep) < len(p) && !c.dropped {
		c.dropped = true
		fmt.Fprintf(c.w, "\n[tkbox: console output reached the %d byte cap; the rest is dropped]\n", c.max)
	}
	return len(p), nil
}

func (c *capWriter) keepTail(p []byte) {
	if len(p) >= consoleTailBytes {
		c.tail = append(c.tail[:0], p[len(p)-consoleTailBytes:]...)
		return
	}
	if over := len(c.tail) + len(p) - consoleTailBytes; over > 0 {
		c.tail = append(c.tail[:0], c.tail[over:]...)
	}
	c.tail = append(c.tail, p...)
}

// Tail returns the last bytes written.
func (c *capWriter) Tail() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.tail)
}

// Dropped reports whether output was cut.
func (c *capWriter) Dropped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}
