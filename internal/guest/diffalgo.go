package guest

import (
	"bytes"
	"fmt"
	"io"
)

// Line diff (Myers' O(ND) greedy algorithm) and unified hunks.

// myersMaxD bounds the edit distance the line diff searches (memory grows with its square: 2000 ≈ 16 MB). Past it
// the changed region becomes one replacement hunk, which is still a correct patch, only larger.
var myersMaxD = 2000

// hunkContext is the number of unchanged lines around each change, as git diff -U3.
const hunkContext = 3

type editOp uint8

const (
	opEq editOp = iota
	opDel
	opIns
)

// edit is one line of the script; a and b are the old and new line indexes at that point.
type edit struct {
	op   editOp
	a, b int
}

// splitLines splits data into lines that keep their "\n"; the last one may lack it.
func splitLines(data []byte) [][]byte {
	var out [][]byte
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			out = append(out, data)
			break
		}
		out = append(out, data[:i+1])
		data = data[i+1:]
	}
	return out
}

// lineDiff returns the edit script turning a into b.
func lineDiff(a, b [][]byte) []edit {
	pre := 0
	for pre < len(a) && pre < len(b) && bytes.Equal(a[pre], b[pre]) {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && bytes.Equal(a[len(a)-1-suf], b[len(b)-1-suf]) {
		suf++
	}
	ids := map[string]int32{}
	intern := func(lines [][]byte) []int32 {
		out := make([]int32, len(lines))
		for i, l := range lines {
			id, ok := ids[string(l)]
			if !ok {
				id = int32(len(ids))
				ids[string(l)] = id
			}
			out[i] = id
		}
		return out
	}
	ma, mb := intern(a[pre:len(a)-suf]), intern(b[pre:len(b)-suf])
	mid, ok := myers(ma, mb, myersMaxD)
	if !ok {
		mid = mid[:0]
		for i := range ma {
			mid = append(mid, edit{op: opDel, a: i})
		}
		for j := range mb {
			mid = append(mid, edit{op: opIns, a: len(ma), b: j})
		}
	}
	out := make([]edit, 0, pre+len(mid)+suf)
	for i := 0; i < pre; i++ {
		out = append(out, edit{opEq, i, i})
	}
	for _, e := range mid {
		out = append(out, edit{e.op, e.a + pre, e.b + pre})
	}
	for i := 0; i < suf; i++ {
		out = append(out, edit{opEq, len(a) - suf + i, len(b) - suf + i})
	}
	return out
}

// myers computes a shortest edit script, or reports false when it needs more than maxD edits.
func myers(a, b []int32, maxD int) ([]edit, bool) {
	n, m := len(a), len(b)
	if n == 0 && m == 0 {
		return nil, true
	}
	limit := min(maxD, n+m)
	off := limit + 1
	v := make([]int32, 2*limit+3)
	var trace [][]int32 // trace[d] = v[k] for k in [-d-1, d+1] before step d
	for d := 0; d <= limit; d++ {
		snap := make([]int32, 2*d+3)
		copy(snap, v[off-d-1:off+d+2])
		trace = append(trace, snap)
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = int(v[off+k+1])
			} else {
				x = int(v[off+k-1]) + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = int32(x)
			if x >= n && y >= m {
				return backtrack(trace, n, m), true
			}
		}
	}
	return nil, false
}

func backtrack(trace [][]int32, n, m int) []edit {
	var rev []edit
	x, y := n, m
	for d := len(trace) - 1; d >= 0; d-- {
		vd := trace[d]
		at := func(k int) int { return int(vd[k+d+1]) }
		k := x - y
		var pk int
		if k == -d || (k != d && at(k-1) < at(k+1)) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := 0
		if d > 0 {
			px = at(pk)
		}
		py := px - pk
		if d == 0 {
			px, py = 0, 0
		}
		for x > px && y > py {
			x--
			y--
			rev = append(rev, edit{opEq, x, y})
		}
		if d > 0 {
			if x == px {
				rev = append(rev, edit{opIns, px, py})
			} else {
				rev = append(rev, edit{opDel, px, py})
			}
		}
		x, y = px, py
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// writeHunks writes unified hunks for edits over a and b.
func writeHunks(w io.Writer, a, b [][]byte, edits []edit) error {
	var changes []int
	for i, e := range edits {
		if e.op != opEq {
			changes = append(changes, i)
		}
	}
	for ci := 0; ci < len(changes); {
		first, last := changes[ci], changes[ci]
		cj := ci + 1
		for cj < len(changes) && changes[cj]-last-1 <= 2*hunkContext {
			last = changes[cj]
			cj++
		}
		ci = cj
		s := max(first-hunkContext, 0)
		end := min(last+hunkContext, len(edits)-1)
		oldN, newN := 0, 0
		for _, e := range edits[s : end+1] {
			if e.op != opIns {
				oldN++
			}
			if e.op != opDel {
				newN++
			}
		}
		if _, err := fmt.Fprintf(w, "@@ -%s +%s @@\n", hunkRange(edits[s].a, oldN), hunkRange(edits[s].b, newN)); err != nil {
			return err
		}
		for _, e := range edits[s : end+1] {
			var prefix byte
			var line []byte
			switch e.op {
			case opEq:
				prefix, line = ' ', a[e.a]
			case opDel:
				prefix, line = '-', a[e.a]
			case opIns:
				prefix, line = '+', b[e.b]
			}
			if err := writeLine(w, prefix, line); err != nil {
				return err
			}
		}
	}
	return nil
}

// hunkRange formats one side of a hunk header: start is 0-based; an empty range names the line before it.
func hunkRange(start, n int) string {
	switch n {
	case 0:
		return fmt.Sprintf("%d,0", start)
	case 1:
		return fmt.Sprintf("%d", start+1)
	}
	return fmt.Sprintf("%d,%d", start+1, n)
}

func writeLine(w io.Writer, prefix byte, line []byte) error {
	buf := make([]byte, 0, len(line)+32)
	buf = append(buf, prefix)
	buf = append(buf, line...)
	if len(line) == 0 || line[len(line)-1] != '\n' {
		buf = append(buf, "\n\\ No newline at end of file\n"...)
	}
	_, err := w.Write(buf)
	return err
}
