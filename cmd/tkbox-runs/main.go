// Command tkbox-runs checks the signed runs under runs/ (Verified Runs) or recipes/ (Job Recipes): every run.tkb must
// pass `tracekit verify` against the run.trust.json next to it, and the table in the folder's README.md is written
// from the verified records, never from what a contributor wrote.
//
//	go run ./cmd/tkbox-runs runs          # verify every run and rewrite the table (make runs)
//	go run ./cmd/tkbox-runs -check runs   # verify every run and fail when the table is out of date (CI)
//
// It needs the Tracekit 1.4.2 CLI (pip install tracekit-ai==1.4.2).
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Cygnux-Labs/tracekit-box/internal/config"
)

func main() {
	check := flag.Bool("check", false, "fail when the table is out of date instead of rewriting it")
	bin := flag.String("tracekit", "tracekit", "the Tracekit 1.4.2 CLI")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "usage: tkbox-runs [-check] [-tracekit BIN] runs|recipes")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(context.Background(), os.Stdout, flag.Arg(0), *bin, *check); err != nil {
		fmt.Fprintln(os.Stderr, "tkbox-runs:", err)
		os.Exit(1)
	}
}

// layout is a folder of entries: each one run's run.tkb and run.trust.json, and the files that describe it.
type layout struct {
	where string   // where an entry goes, for messages
	depth int      // folder levels from the root to an entry
	files []string // what an entry holds, and nothing else
	head  []string // the table's columns before the counts
	// describe reads and checks an entry's own files and returns its cells before the counts
	describe func(dir, rel string) ([]string, error)
}

var layouts = map[string]layout{
	"runs": {where: "runs/<agent>/<short-name>/", depth: 2, files: []string{"run.tkb", "run.trust.json", "run.yaml"},
		head: []string{"Agent", "Task"}, describe: describeRun},
	"recipes": {where: "recipes/<job>/", depth: 1,
		files: []string{"README.md", "run.tkb", "run.trust.json", "tkbox.yaml"}, head: []string{"Job"},
		describe: describeRecipe},
}

// The table in the folder's README.md goes between these lines.
const (
	beginMark = "<!-- BEGIN table: written by `make runs` from the verified records; do not edit by hand -->"
	endMark   = "<!-- END table -->"
)

// slug is a folder name in a layout.
var slug = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func run(ctx context.Context, w io.Writer, root, bin string, check bool) error {
	l, ok := layouts[filepath.Base(filepath.Clean(root))]
	if !ok {
		return fmt.Errorf("%s: give the runs or the recipes folder", root)
	}
	entries, err := find(root, l)
	if err != nil {
		return err
	}
	var rows, failed []string
	for _, e := range entries {
		integrity, err := verify(ctx, bin, e.dir)
		var t tally
		if err == nil {
			t, err = count(filepath.Join(e.dir, "run.tkb"))
		}
		if err != nil {
			failed = append(failed, e.rel+": "+err.Error())
			continue
		}
		fmt.Fprintf(w, "%s: %s; %d commands, %d connections, %d held, %d refused\n", e.rel, integrity, t.Commands,
			t.Connections, t.Held, t.Refused)
		cells := append(e.cells, strconv.Itoa(t.Commands), strconv.Itoa(t.Connections), strconv.Itoa(t.Held),
			strconv.Itoa(t.Refused), integrity)
		rows = append(rows, "| "+strings.Join(cells, " | ")+" |")
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d run(s) did not verify, so none is listed until they do:\n  %s", len(failed),
			len(entries), strings.Join(failed, "\n  "))
	}
	readme := filepath.Join(root, "README.md")
	old, err := os.ReadFile(readme)
	if err != nil {
		return err
	}
	updated, err := replaceTable(old, table(l, rows))
	if err != nil {
		return fmt.Errorf("%s: %w", readme, err)
	}
	switch {
	case bytes.Equal(old, updated):
		fmt.Fprintf(w, "%s: the table is up to date (%d run(s))\n", readme, len(rows))
		return nil
	case check:
		return fmt.Errorf("%s: the table is out of date: run `make runs` and commit the README", readme)
	}
	if err := os.WriteFile(readme, updated, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s: table written (%d run(s))\n", readme, len(rows))
	return nil
}

// entry is one run folder.
type entry struct {
	rel   string   // its path under the root, with forward slashes ("claude-code/fix-test")
	dir   string   // its path on disk
	cells []string // the table cells its own files give
}

// find lists the entries under root, in path order. Anything outside the layout is an error, so nothing lands in the
// folder unchecked.
func find(root string, l layout) ([]entry, error) {
	var out []entry
	var problems []string
	var walk func(dir, rel string, level int)
	walk = func(dir, rel string, level int) {
		des, err := os.ReadDir(dir)
		if err != nil {
			problems = append(problems, err.Error())
			return
		}
		if level == l.depth {
			have := map[string]bool{}
			for _, de := range des {
				switch name := de.Name(); {
				case !slices.Contains(l.files, name):
					problems = append(problems, fmt.Sprintf("%s/%s: a run folder holds only %s", rel, name,
						strings.Join(l.files, ", ")))
				case !de.Type().IsRegular():
					problems = append(problems, fmt.Sprintf("%s/%s: not a regular file", rel, name))
				default:
					have[name] = true
				}
			}
			for _, name := range l.files {
				if !have[name] && !slices.ContainsFunc(des, func(de os.DirEntry) bool { return de.Name() == name }) {
					problems = append(problems, fmt.Sprintf("%s: no %s", rel, name))
				}
			}
			if len(have) != len(l.files) {
				return
			}
			cells, err := l.describe(dir, rel)
			if err != nil {
				problems = append(problems, rel+": "+err.Error())
				return
			}
			out = append(out, entry{rel: rel, dir: dir, cells: cells})
			return
		}
		for _, de := range des {
			name, at := de.Name(), path.Join(rel, de.Name())
			switch {
			case level == 0 && name == "README.md" && de.Type().IsRegular():
			case !de.IsDir():
				problems = append(problems, fmt.Sprintf("%s: put each run in %s", at, l.where))
			case !slug.MatchString(name):
				problems = append(problems, fmt.Sprintf("%s: a folder name is lowercase letters, digits, '.', '_' and "+
					"'-' (at most 64)", at))
			default:
				walk(filepath.Join(dir, name), at, level+1)
			}
		}
	}
	walk(root, "", 0)
	if len(problems) > 0 {
		return nil, fmt.Errorf("%s does not match its layout (%s):\n  %s", root, l.where,
			strings.Join(problems, "\n  "))
	}
	return out, nil
}

func describeRun(dir, rel string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "run.yaml"))
	if err != nil {
		return nil, err
	}
	r, err := parseRunYAML(b)
	if err != nil {
		return nil, err
	}
	return []string{"[" + cell(r.Agent) + "](" + rel + "/)", cell(r.Task)}, nil
}

func describeRecipe(dir, rel string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "tkbox.yaml"))
	if err != nil {
		return nil, err
	}
	if _, err := config.Parse(b, "tkbox.yaml"); err != nil {
		return nil, err
	}
	return []string{"[" + cell(path.Base(rel)) + "](" + rel + "/)"}, nil
}

func table(l layout, rows []string) string {
	head := append(slices.Clone(l.head), "Commands", "Connections", "Held", "Refused", "Integrity")
	align := slices.Repeat([]string{"---"}, len(l.head))
	align = append(align, "--:", "--:", "--:", "--:", "---")
	return "| " + strings.Join(head, " | ") + " |\n|" + strings.Join(align, "|") + "|\n" +
		strings.Join(append(rows, ""), "\n")
}

// cell is text for a Markdown table cell: one line, with every character Markdown or HTML could read escaped.
func cell(s string) string {
	var b strings.Builder
	for _, r := range strings.Join(strings.Fields(s), " ") {
		if strings.ContainsRune("\\`*_{}[]()<>#+!|~&", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// replaceTable puts table between the begin and end lines of doc.
func replaceTable(doc []byte, table string) ([]byte, error) {
	s := string(doc)
	i, j := strings.Index(s, beginMark), strings.Index(s, endMark)
	if strings.Count(s, beginMark) != 1 || strings.Count(s, endMark) != 1 || j < i {
		return nil, errors.New("it needs one line " + beginMark + " and, after it, one line " + endMark)
	}
	return []byte(s[:i+len(beginMark)] + "\n" + table + s[j:]), nil
}
