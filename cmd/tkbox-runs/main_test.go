package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type zfile struct {
	name string
	body []byte
}

// writeBundle writes a .tkb holding files and a manifest of their SHA-256s, as tracekit export does, then extra
// entries the manifest does not list.
func writeBundle(t *testing.T, path string, files []zfile, extra ...zfile) {
	t.Helper()
	sums := map[string]string{}
	for _, f := range files {
		sum := sha256.Sum256(f.body)
		sums[f.name] = hex.EncodeToString(sum[:])
	}
	manifest, _ := json.Marshal(map[string]any{"format": "tracekit.bundle.v2", "files": sums})
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range append(append([]zfile{{"manifest.json", manifest}}, files...), extra...) {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(f.body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rec(typ, data string) string {
	return `{"v":2,"event":{"type":"` + typ + `","data":` + data + `}}`
}

func decision(id, tool, dec string) string {
	return rec("policy.decision", `{"tool_use_id":"`+id+`","tool":"`+tool+`","decision":"`+dec+`"}`)
}

func observed(source string) string {
	return rec("input.observed", `{"source":"`+source+`","trust":"trusted","output":{"hash":"hmac-sha256:00","size":1}}`)
}

func lines(recs ...string) []byte { return []byte(strings.Join(recs, "\n") + "\n") }

// boxRun is a small Box run: one command that reached one host on the allowlist.
var boxRun = lines(rec("run.registered", `{"agent":{"name":"tkbox"}}`), observed("tkbox.box"),
	decision("exec-1", "Bash", "flag"), decision("egress-2", "WebFetch", "flag"),
	rec("tool.result", `{"tool_use_id":"egress-2","ok":true}`), rec("tool.result", `{"tool_use_id":"exec-1","ok":true}`),
	rec("run.final", `{"head_run_seq":5}`))

func TestTallyRecords(t *testing.T) {
	got, err := tallyRecords(lines(
		rec("run.registered", `{"agent":{"name":"tkbox"}}`),
		observed("tkbox.box"), observed("tkbox.task"),
		decision("exec-1", "Bash", "allow"),
		decision("exec-1", "Bash", "allow"), // a retry of the same call: still one command
		decision("exec-2", "Bash", "deny"),
		// a hold a person approved: the call ran
		decision("exec-3", "Bash", "ask"),
		rec("approval.request", `{"approval_id":"a1","binding":{"tool_call_id":"exec-3","attempt":0}}`),
		rec("approval", `{"approval_id":"a1","decision":"approve","binding":"not an object here"}`),
		rec("approval.consumed", `{"approval_id":"a1"}`),
		// a hold no one approved: refused too
		decision("exec-4", "Bash", "ask"),
		rec("approval.request", `{"approval_id":"a2","binding":{"tool_call_id":"exec-4","attempt":0}}`),
		rec("approval.expired", `{"approval_id":"a2"}`),
		decision("egress-5", "WebFetch", "flag"),
		decision("egress-6", "WebFetch", "ask"), // its approval request never got through: it never ran
		// Box's own approvals, its refusals and a blocked secret; a secret sent to its own host is neither
		observed("tkbox.approval"), observed("tkbox.approval"),
		observed("tkbox.egress"), observed("tkbox.secret.leak"), observed("tkbox.secret.use"),
		decision("write-7", "Write", "deny"), // tkbox apply: neither a command nor a connection, but refused
		rec("run.final", `{"head_run_seq":20}`)))
	if err != nil {
		t.Fatal(err)
	}
	// held: exec-3, exec-4, egress-6 and the two Box approvals; refused: exec-2, write-7, exec-4, egress-6, the Box
	// refusal and the blocked secret
	if want := (tally{Commands: 4, Connections: 2, Held: 5, Refused: 6}); got != want {
		t.Fatalf("tally = %+v, want %+v", got, want)
	}

	if _, err := tallyRecords(lines(decision("exec-1", "Bash", "allow"))); err == nil ||
		!strings.Contains(err.Error(), "not a Tracekit Box run") {
		t.Fatalf("a run with no tkbox.box record: err = %v", err)
	}
	if _, err := tallyRecords(lines(observed("tkbox.box"), `{"event":`)); err == nil {
		t.Fatal("a record that is not JSON was counted")
	}
	if _, err := tallyRecords(lines(observed("tkbox.box"), rec("policy.decision", `{"tool":7}`))); err == nil {
		t.Fatal("a decision whose tool is not a string was counted")
	}
}

func TestCountReadsOnlyTheVerifiedRun(t *testing.T) {
	dir := t.TempDir()
	tkb := filepath.Join(dir, "run.tkb")
	run := zfile{"runs/r1.jsonl", boxRun}
	keys := zfile{"keys/records.jsonl", []byte("{}\n")}

	writeBundle(t, tkb, []zfile{keys, run})
	if got, err := count(tkb); err != nil || got != (tally{Commands: 1, Connections: 1}) {
		t.Fatalf("count = %+v, %v", got, err)
	}

	// a second copy of the run file, which a reader that takes the last one would count instead
	forged := zfile{"runs/r1.jsonl", lines(observed("tkbox.box"))}
	writeBundle(t, tkb, []zfile{keys, run}, forged)
	if _, err := count(tkb); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a bundle naming a file twice: err = %v", err)
	}

	// a run file that is not the one the manifest lists
	writeBundle(t, tkb, []zfile{keys, run})
	b, _ := os.ReadFile(tkb)
	writeBundle(t, tkb, []zfile{keys, {run.name, bytes.Replace(run.body, []byte("exec-1"), []byte("exec-9"), 1)}})
	swapManifest(t, tkb, b)
	if _, err := count(tkb); err == nil || !strings.Contains(err.Error(), "does not match its SHA-256") {
		t.Fatalf("a run file the manifest does not list: err = %v", err)
	}

	writeBundle(t, tkb, []zfile{keys, run, {"runs/r2.jsonl", boxRun}})
	if _, err := count(tkb); err == nil || !strings.Contains(err.Error(), "holds 2 runs") {
		t.Fatalf("a bundle of two runs: err = %v", err)
	}
	writeBundle(t, tkb, []zfile{keys})
	if _, err := count(tkb); err == nil || !strings.Contains(err.Error(), "holds 0 runs") {
		t.Fatalf("a bundle of no run: err = %v", err)
	}
}

// swapManifest replaces the manifest.json of the bundle at path with the one in the bundle bytes from.
func swapManifest(t *testing.T, path string, from []byte) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(from), int64(len(from)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest []byte
	for _, f := range zr.File {
		if f.Name == "manifest.json" {
			rc, _ := f.Open()
			manifest, _ = io.ReadAll(rc)
			rc.Close()
		}
	}
	zc, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zc.File {
		rc, _ := f.Open()
		body, _ := io.ReadAll(rc)
		rc.Close()
		if f.Name == "manifest.json" {
			body = manifest
		}
		w, _ := zw.Create(f.Name)
		w.Write(body)
	}
	zc.Close()
	zw.Close()
	os.WriteFile(path, buf.Bytes(), 0o644)
}

const goodYAML = `agent: Claude Code
agent_version: 2.10
image: python:3.12-slim
allow: []
task: >
  Fix the flaky test.
notes: Nothing was held.
`

func TestParseRunYAML(t *testing.T) {
	r, err := parseRunYAML([]byte(goodYAML))
	if err != nil {
		t.Fatal(err)
	}
	if r.AgentVersion != "2.10" || r.Allow == nil || len(*r.Allow) != 0 || r.Task != "Fix the flaky test.\n" {
		t.Fatalf("run.yaml read as %+v", r)
	}
	for _, c := range []struct{ name, yaml, want string }{
		{"no agent", strings.Replace(goodYAML, "agent: Claude Code\n", "", 1), "agent is required"},
		{"no version", strings.Replace(goodYAML, "agent_version: 2.10", "agent_version:", 1), "agent_version is required"},
		{"no image", strings.Replace(goodYAML, "image: python:3.12-slim", "image: ''", 1), "image is required"},
		{"no allow", strings.Replace(goodYAML, "allow: []\n", "", 1), "allow is required"},
		{"null allow", strings.Replace(goodYAML, "allow: []", "allow:", 1), "allow is required"},
		{"no task", strings.Replace(goodYAML, "task: >\n  Fix the flaky test.\n", "", 1), "task is required"},
		{"no notes", strings.Replace(goodYAML, "notes: Nothing was held.\n", "", 1), "notes is required"},
		{"unknown key", goodYAML + "secret: x\n", "secret"},
		{"two documents", goodYAML + "---\nagent: x\n", "more than one YAML document"},
		{"agent on two lines", strings.Replace(goodYAML, "agent: Claude Code", `agent: "Claude\nCode"`, 1), "one line"},
		{"bidi override", strings.Replace(goodYAML, "Fix the", "Fix \u202ethe", 1), "control or format character"},
		{"image with a space", strings.Replace(goodYAML, "python:3.12-slim", "python 3", 1), "holds a space"},
		{"allow entry with a space", strings.Replace(goodYAML, "allow: []", "allow: [pypi, 'a b']", 1), "holds a space"},
		{"empty allow entry", strings.Replace(goodYAML, "allow: []", "allow: ['']", 1), "an allow entry is required"},
		{"long task", strings.Replace(goodYAML, "Fix the flaky test.", strings.Repeat("x", 501), 1), "task is over 500"},
		{"empty", "", "empty"},
	} {
		if _, err := parseRunYAML([]byte(c.yaml)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to say %q", c.name, err, c.want)
		}
	}
}

const readme = "# Runs\n\n" + beginMark + "\nstale\n" + endMark + "\n\nMore text.\n"

// newRoot makes a runs folder with one run, agent/task, whose run.yaml has task.
func newRoot(t *testing.T, task string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "runs")
	dir := filepath.Join(root, "agent", "task")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBundle(t, filepath.Join(dir, "run.tkb"), []zfile{{"runs/r1.jsonl", boxRun}})
	os.WriteFile(filepath.Join(dir, "run.trust.json"), []byte("{}\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "run.yaml"), []byte(strings.Replace(goodYAML, "Fix the flaky test.", task, 1)), 0o644)
	os.WriteFile(filepath.Join(root, "README.md"), []byte(readme), 0o644)
	return root
}

const verified = `{"exit_code": 0, "integrity": "VERIFIED", "checks": [], "failures": []}`

// fakeTracekit is a tracekit CLI that checks it was asked to verify a bundle against a trust file, prints report and
// exits with code.
func fakeTracekit(t *testing.T, report string, code int) string {
	t.Helper()
	dir := t.TempDir()
	rep := filepath.Join(dir, "report.json")
	os.WriteFile(rep, []byte(report), 0o644)
	bin := filepath.Join(dir, "tracekit")
	script := fmt.Sprintf("#!/bin/sh\n[ \"$1\" = verify ] && [ -f \"$2\" ] && [ \"$3\" = --trust ] && [ -f \"$4\" ] && "+
		"[ \"$5\" = --json ] || exit 9\ncat '%s'\nexit %d\n", rep, code)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestRunWritesAndChecksTheTable(t *testing.T) {
	ctx := context.Background()
	root := newRoot(t, "Fix | the <b>flaky</b> [test](https://x.example)\n  now.")
	bin := fakeTracekit(t, verified, 0)
	readmePath := filepath.Join(root, "README.md")

	if err := run(ctx, io.Discard, root, bin, true); err == nil || !strings.Contains(err.Error(), "out of date") {
		t.Fatalf("check with a stale table: err = %v", err)
	}
	if b, _ := os.ReadFile(readmePath); string(b) != readme {
		t.Fatal("check rewrote the README")
	}
	if err := run(ctx, io.Discard, root, bin, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(readmePath)
	want := "# Runs\n\n" + beginMark + "\n" +
		"| Agent | Task | Commands | Connections | Held | Refused | Integrity |\n" +
		"|---|---|--:|--:|--:|--:|---|\n" +
		`| [Claude Code](agent/task/) | Fix \| the \<b\>flaky\</b\> \[test\]\(https://x.example\) now. | 1 | 1 | 0 | 0 | VERIFIED |` + "\n" +
		endMark + "\n\nMore text.\n"
	if string(b) != want {
		t.Fatalf("README:\n%s\nwant:\n%s", b, want)
	}
	if err := run(ctx, io.Discard, root, bin, true); err != nil {
		t.Fatalf("check right after writing: %v", err)
	}

	for _, c := range []struct {
		name, report string
		code         int
		want         string
	}{
		{"failed", `{"exit_code": 1, "integrity": "FAILED", "checks": [{"check": "manifest", "status": "fail",
			"detail": "runs/x.jsonl does not match"}, {"check": "keys", "status": "pass", "detail": "fine"}]}`, 1,
			"Integrity: FAILED (exit 1): manifest: runs/x.jsonl does not match"},
		{"open run", `{"exit_code": 0, "integrity": "VERIFIED TO HEAD 9 (open)", "checks": []}`, 0, "VERIFIED TO HEAD 9"},
		{"verified but a failing exit", verified, 1, "exit status 1"},
		{"no report", "not json", 0, "printed no JSON report"},
		{"no exit code", `{"integrity": "VERIFIED"}`, 0, "printed no JSON report"},
	} {
		os.WriteFile(readmePath, []byte(readme), 0o644)
		err := run(ctx, io.Discard, root, fakeTracekit(t, c.report, c.code), false)
		if err == nil || !strings.Contains(err.Error(), "did not verify") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to say %q", c.name, err, c.want)
		}
		if b, _ := os.ReadFile(readmePath); string(b) != readme {
			t.Errorf("%s: the README was rewritten for a run that did not verify", c.name)
		}
	}

	if err := run(ctx, io.Discard, filepath.Join(filepath.Dir(root), "other"), bin, true); err == nil {
		t.Fatal("a folder that is neither runs nor recipes was accepted")
	}
	os.WriteFile(readmePath, []byte("# Runs\n"), 0o644)
	if err := run(ctx, io.Discard, root, bin, false); err == nil || !strings.Contains(err.Error(), beginMark) {
		t.Fatalf("a README with no table markers: err = %v", err)
	}
}

func TestFindRefusesWhatIsOutsideTheLayout(t *testing.T) {
	for _, c := range []struct {
		name string
		mess func(root string)
		want string
	}{
		{"a file at the top", func(root string) { os.WriteFile(filepath.Join(root, "notes.txt"), nil, 0o644) },
			"notes.txt: put each run in runs/<agent>/<short-name>/"},
		{"a file in an agent folder", func(root string) { os.WriteFile(filepath.Join(root, "agent", "run.tkb"), nil, 0o644) },
			"agent/run.tkb: put each run in"},
		{"another file in a run", func(root string) {
			os.WriteFile(filepath.Join(root, "agent", "task", ".env"), nil, 0o644)
		}, "agent/task/.env: a run folder holds only run.tkb, run.trust.json, run.yaml"},
		{"no run.yaml", func(root string) { os.Remove(filepath.Join(root, "agent", "task", "run.yaml")) },
			"agent/task: no run.yaml"},
		{"a link for a bundle", func(root string) {
			tkb := filepath.Join(root, "agent", "task", "run.tkb")
			os.Rename(tkb, tkb+".real")
			os.Symlink(tkb+".real", tkb)
		}, "agent/task/run.tkb: not a regular file"},
		{"a folder name with a capital", func(root string) { os.Rename(filepath.Join(root, "agent"), filepath.Join(root, "Agent")) },
			"Agent: a folder name is lowercase"},
		{"a bad run.yaml", func(root string) {
			os.WriteFile(filepath.Join(root, "agent", "task", "run.yaml"), []byte("agent: x\n"), 0o644)
		}, "agent/task: run.yaml: agent_version is required"},
		{"a run a level too deep", func(root string) {
			os.MkdirAll(filepath.Join(root, "agent", "task", "more"), 0o755)
		}, "agent/task/more: a run folder holds only"},
	} {
		root := newRoot(t, "Fix the flaky test.")
		c.mess(root)
		if _, err := find(root, layouts["runs"]); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to say %q", c.name, err, c.want)
		}
	}
}

func TestRecipes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recipes")
	dir := filepath.Join(root, "pytest")
	os.MkdirAll(dir, 0o755)
	writeBundle(t, filepath.Join(dir, "run.tkb"), []zfile{{"runs/r1.jsonl", boxRun}})
	os.WriteFile(filepath.Join(dir, "run.trust.json"), []byte("{}\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("# pytest\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "tkbox.yaml"), []byte("image: python:3.12-slim\nallow: [pypi]\n"), 0o644)
	os.WriteFile(filepath.Join(root, "README.md"), []byte(readme), 0o644)
	bin := fakeTracekit(t, verified, 0)
	if err := run(context.Background(), io.Discard, root, bin, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "README.md"))
	if !strings.Contains(string(b), "| Job | Commands | Connections | Held | Refused | Integrity |\n|---|--:|--:|--:|--:|---|\n"+
		"| [pytest](pytest/) | 1 | 1 | 0 | 0 | VERIFIED |\n") {
		t.Fatalf("recipes README:\n%s", b)
	}
	os.WriteFile(filepath.Join(dir, "tkbox.yaml"), []byte("image: python:3.12-slim\nallow_everything: true\n"), 0o644)
	if err := run(context.Background(), io.Discard, root, bin, true); err == nil ||
		!strings.Contains(err.Error(), "pytest: tkbox.yaml") {
		t.Fatalf("a recipe whose tkbox.yaml is not a box config: err = %v", err)
	}
}

func TestReplaceTable(t *testing.T) {
	for _, doc := range []string{"", beginMark + "\n", endMark + "\n" + beginMark + "\n",
		beginMark + "\n" + endMark + "\n" + beginMark + "\n" + endMark + "\n"} {
		if _, err := replaceTable([]byte(doc), "| x |\n"); err == nil {
			t.Errorf("replaceTable(%q) took it", doc)
		}
	}
}

// TestCommittedRuns verifies the runs in this repository with the real CLI (the runs workflow installs it), and that a
// changed record fails.
func TestCommittedRuns(t *testing.T) {
	bin, err := exec.LookPath("tracekit")
	if err != nil {
		t.Skip("no tracekit CLI on PATH (pip install tracekit-ai==1.4.2)")
	}
	ctx := context.Background()
	var out bytes.Buffer
	if err := run(ctx, &out, filepath.Join("..", "..", "runs"), bin, true); err != nil {
		t.Fatal(err)
	}
	// the README demo's run, counted by hand from its records
	if want := "by-hand/readme-demo: VERIFIED; 7 commands, 39 connections, 1 held, 2 refused\n"; !strings.HasPrefix(out.String(), want) {
		t.Fatalf("output:\n%s\nwant it to start with %q", out.String(), want)
	}

	// the same run with one decision changed from flag to allow, and its manifest entry updated to match
	root := filepath.Join(t.TempDir(), "runs")
	dir := filepath.Join(root, "by-hand", "readme-demo")
	os.MkdirAll(dir, 0o755)
	for _, name := range []string{"run.trust.json", "run.yaml"} {
		b, _ := os.ReadFile(filepath.Join("..", "..", "runs", "by-hand", "readme-demo", name))
		os.WriteFile(filepath.Join(dir, name), b, 0o644)
	}
	src, _ := os.ReadFile(filepath.Join("..", "..", "runs", "README.md"))
	os.WriteFile(filepath.Join(root, "README.md"), src, 0o644)
	zr, err := zip.OpenReader(filepath.Join("..", "..", "runs", "by-hand", "readme-demo", "run.tkb"))
	if err != nil {
		t.Fatal(err)
	}
	var files []zfile
	changed := false
	for _, f := range zr.File {
		rc, _ := f.Open()
		body, _ := io.ReadAll(rc)
		rc.Close()
		if strings.HasPrefix(f.Name, "runs/") {
			body = bytes.Replace(body, []byte(`"decision":"flag"`), []byte(`"decision":"allow"`), 1)
			changed = true
		}
		if f.Name != "manifest.json" {
			files = append(files, zfile{f.Name, body})
		}
	}
	zr.Close()
	if !changed {
		t.Fatal("no run file in the committed bundle")
	}
	writeBundle(t, filepath.Join(dir, "run.tkb"), files)
	if err := run(ctx, io.Discard, root, bin, true); err == nil || !strings.Contains(err.Error(), "did not verify") {
		t.Fatalf("a changed record: err = %v", err)
	}
}
