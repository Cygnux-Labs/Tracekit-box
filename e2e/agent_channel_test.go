//go:build e2e

package e2e

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// signer is a Tracekit signer of its own for one test, started from signer.yaml.
type signer struct{ bin, cfg, sock string }

// signer21 starts a signer that serves RPC contract 21 and names this user a Box daemon (box_daemons), with the
// default fail modes (closed), from the tracekit CLI $TKBOX_TRACEKIT21 names. A dev signer can't take box_daemons.
func signer21(t *testing.T) *signer {
	t.Helper()
	bin := os.Getenv("TKBOX_TRACEKIT21")
	if bin == "" {
		t.Skip("TKBOX_TRACEKIT21 not set: name a tracekit CLI that serves RPC protocol 21 (Tracekit 1.6.0 or later), " +
			"e.g. a venv's bin/tracekit after pip install git+https://github.com/Cygnux-Labs/Tracekit@main")
	}
	dir := t.TempDir()
	s := &signer{bin: bin, cfg: filepath.Join(dir, "signer.yaml"), sock: filepath.Join(dir, "signer.sock")}
	yaml := fmt.Sprintf("data_dir: data\nsocket: signer.sock\nbox_daemons: {\"uid:%d\": firecracker}\n", os.Getuid())
	if err := os.WriteFile(s.cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := exec.CommandContext(ctx, bin, "signer", "serve", "--config", s.cfg)
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	c.Cancel = func() error { return c.Process.Signal(os.Interrupt) }
	c.WaitDelay = 30 * time.Second
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); c.Wait() })
	for i := 0; ; i++ {
		st := exec.Command(bin, "status")
		st.Env = append(os.Environ(), "TRACEKIT_SIGNER="+s.sock)
		out, _ := st.Output()
		var v struct {
			Signer struct {
				Running bool   `json:"running"`
				Version string `json:"version"`
				Proto   []int  `json:"proto"`
			} `json:"signer_v2"`
		}
		if json.Unmarshal(out, &v) == nil && v.Signer.Running && len(v.Signer.Proto) == 2 {
			t.Logf("tracekit status: signer %s at %s, protocols %v", v.Signer.Version, s.sock, v.Signer.Proto)
			if v.Signer.Proto[1] < 21 {
				t.Fatalf("%s serves protocols %v; the agent channel needs 21", bin, v.Signer.Proto)
			}
			return s
		}
		if i > 300 {
			t.Fatalf("the signer did not come up at %s: %s", s.sock, out)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *signer) cli(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(s.bin, args...).CombinedOutput()
	return string(out), err
}

// exportVerified exports a run with the signer's config (tkbox export exports only a box's own run) and verifies it,
// until the run is final (integrity VERIFIED, not VERIFIED TO HEAD n (open)); -> verify's output.
func (s *signer) exportVerified(t *testing.T, runID, bundle, trust string) string {
	t.Helper()
	var last string
	for deadline := time.Now().Add(2 * time.Minute); ; {
		out, err := s.cli(t, "export", "--v2", "--run="+runID, "--config", s.cfg, "-o", bundle)
		last = out
		if err == nil {
			out, err = s.cli(t, "verify", bundle, "--trust", trust, "--json")
			last = out
			var rep struct {
				ExitCode  int    `json:"exit_code"`
				Integrity string `json:"integrity"`
			}
			if err == nil && json.Unmarshal([]byte(out), &rep) == nil && rep.ExitCode == 0 && rep.Integrity == "VERIFIED" {
				out, err = s.cli(t, "verify", bundle, "--trust", trust)
				if err != nil {
					t.Fatalf("verify %s: %v\n%s", bundle, err, out)
				}
				return out
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("run %s: no final, verified bundle: %v\n%s", runID, err, last)
		}
		time.Sleep(time.Second)
	}
}

// record is one record of a v2 bundle's run file.
type record struct {
	Event struct {
		Type  string         `json:"type"`
		Seq   int64          `json:"seq"`
		RunID string         `json:"run_id"`
		Data  map[string]any `json:"data"`
		Ext   map[string]any `json:"ext"`
	} `json:"event"`
}

// runRecords reads run runID's records (tenant default) from a v2 bundle: runs/<first 32 hex of sha256>.jsonl.
func runRecords(t *testing.T, bundle, runID string) []record {
	t.Helper()
	z, err := zip.OpenReader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	sum := sha256.Sum256([]byte("default/" + runID))
	f, err := z.Open("runs/" + hex.EncodeToString(sum[:16]) + ".jsonl")
	if err != nil {
		t.Fatalf("%s: run %s: %v", bundle, runID, err)
	}
	defer f.Close()
	var recs []record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var r record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	if err := sc.Err(); err != nil || len(recs) == 0 {
		t.Fatalf("%s: run %s: %d records, %v", bundle, runID, len(recs), err)
	}
	return recs
}

func firstOf(recs []record, typ string) *record {
	for i := range recs {
		if recs[i].Event.Type == typ {
			return &recs[i]
		}
	}
	return nil
}

// asAgent runs the rest of argv as uid and gid 65534 (nobody), with no supplementary groups: the agent is not root.
var asAgent = []string{py, "-I", "-c",
	"import os,sys; os.setgroups([]); os.setgid(65534); os.setuid(65534); os.execvp(sys.argv[1], sys.argv[1:])"}

// sendFramesPy sends each argument as one frame on a connection of its own to the box's signer socket, after hello,
// and prints the answer to each, one per line.
const sendFramesPy = `import socket, sys
for frame in sys.argv[1:]:
    s = socket.socket(socket.AF_UNIX)
    s.connect("/run/tkbox/signer.sock")
    f = s.makefile("rb")
    for line in ('{"method":"hello"}', frame):
        s.sendall(line.encode() + b"\n")
        answer = f.readline()
    print(answer.decode().strip(), flush=True)
    s.close()`

type answer struct {
	RunID    string `json:"run_id"`
	RunToken string `json:"run_token"`
	Error    *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// frames sends frames through box's agent channel as the agent; -> the answers, in order.
func (e *env) frames(t *testing.T, box string, frames ...map[string]any) []answer {
	t.Helper()
	argv := append(slices.Clone(asAgent), py, "-I", "-c", sendFramesPy)
	for _, f := range frames {
		b, _ := json.Marshal(f)
		argv = append(argv, string(b))
	}
	out, _, code := e.exec(t, box, argv...)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) != len(frames) {
		t.Fatalf("frames through %s's channel: exit %d, %d answers for %d frames", box, code, len(lines), len(frames))
	}
	answers := make([]answer, len(lines))
	for i, l := range lines {
		if err := json.Unmarshal([]byte(l), &answers[i]); err != nil {
			t.Fatalf("answer %q: %v", l, err)
		}
	}
	return answers
}

// refusals counts a stopped box's channel.refused refusals per kind (each event's own and those folded into it) and
// lists the methods the events name; any other agent channel, limit or signer problem event fails the test.
func (e *env) refusals(t *testing.T, box string) (map[string]int, []string) {
	t.Helper()
	out, _, _ := e.tk(t, "events", box, "--json")
	n, methods := map[string]int{}, []string(nil)
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var ev struct {
			Kind, Door, Summary string
			Data                struct {
				Refusal, Method, Reason string
				Folded                  int
			}
		}
		if json.Unmarshal([]byte(l), &ev) != nil {
			continue
		}
		switch {
		case ev.Kind == "channel.refused":
			if ev.Data.Reason != "" {
				n[ev.Data.Refusal]++
			}
			n[ev.Data.Refusal] += ev.Data.Folded
			if ev.Data.Method != "" {
				methods = append(methods, ev.Data.Method)
			}
		case ev.Kind == "signer.problem" || ev.Kind == "box.limit" || ev.Door == "agent_channel":
			t.Errorf("%s event: %s %s: %s", box, ev.Kind, ev.Door, ev.Summary)
		}
	}
	t.Logf("%s: refusals by kind %v, methods named %v", box, n, methods)
	return n, methods
}

// refusedByBox: the answer is the scoping proxy's refusal (its own words, which the signer never uses).
func refusedByBox(t *testing.T, what string, a answer, words string) {
	t.Helper()
	if a.Error == nil || a.Error.Code != "forbidden" || !strings.Contains(a.Error.Message, words) {
		t.Errorf("%s: got %+v (error %+v), want the channel's forbidden %q", what, a, a.Error, words)
	}
}

func rid() string {
	return rand.Text()
}

// TestAgentChannel runs Tracekit's Claude Code hook as a non-root agent in a box with --agent-channel, tries what the
// channel must refuse, from that box and from a second one, and checks the agent's run in the exported bundles: the
// box's label, a child of the box run, its decision, closed before the box run, and verify's boxed-agent lines.
// Besides `make e2e`'s needs, it needs $TKBOX_TRACEKIT21 (signer21) and PyPI (the hook client in the box).
func TestAgentChannel(t *testing.T) {
	needKVM(t)
	s := signer21(t)
	e := setup(t, "--signer", s.sock, "--tracekit-bin", s.bin, "--tracekit-config", s.cfg)
	newBox := func(t *testing.T, name string, allow ...string) (b struct {
		ID          string   `json:"id"`
		RunID       string   `json:"run_id"`
		ImageDigest string   `json:"image_digest"`
		Allow       []string `json:"allow"`
	}) {
		args := []string{"run", "--image", "python:3.12-slim", "--agent-channel", "--workspace", e.work, "--name", name,
			"--timeout", "20m", "--json"}
		for _, a := range allow {
			args = append(args, "--allow", a)
		}
		out, _, code := e.tk(t, args...)
		if code != 0 || json.Unmarshal([]byte(out), &b) != nil || b.RunID == "" {
			t.Fatalf("run %s: exit %d: %q", name, code, out)
		}
		t.Cleanup(func() { e.tk(t, "rm", name) })
		return b
	}
	b1 := newBox(t, "ch1", "pypi")

	// agent runs argv in ch1 as the agent, with the hook's environment (and stdin, when there is one)
	agent := func(stdin string, argv ...string) (string, string, int) {
		t.Helper()
		args := []string{"exec", "ch1"}
		if stdin != "" {
			args = append(args, "-i")
		}
		args = append(args, "--env", "HOME=/tmp/agent", "--env", "TRACEKIT_SIGNER=/run/tkbox/signer.sock",
			"--env", "TRACEKIT_RUNTIME_DIR=/tmp/agent/rt", "--")
		return e.tkIn(t, stdin, append(append(args, asAgent...), argv...)...)
	}

	// the agent is not root, and can't write where the socket is
	if out, _, code := agent("", "id", "-u"); code != 0 || strings.TrimSpace(out) != "65534" {
		t.Fatalf("agent uid: %q %d", out, code)
	}
	e.exec(t, "ch1", "ls", "-ld", "/run/tkbox", "/run/tkbox/signer.sock")
	if _, _, code := agent("", "touch", "/run/tkbox/x"); code == 0 {
		t.Fatal("the agent wrote into /run/tkbox")
	}

	// the hook client, installed by the agent
	if _, _, code := agent("", "sh", "-c", "mkdir -p /tmp/agent && touch /tmp/agent/transcript.jsonl && "+
		"python3 -m venv /tmp/agent/venv && /tmp/agent/venv/bin/pip install -q --disable-pip-version-check tracekit-ai==1.5.3"); code != 0 {
		t.Fatalf("installing the hook client: exit %d", code)
	}

	const session, toolUse = "e2e-agent-channel", "toolu_e2e_01"
	hook := func(event string, extra map[string]any) {
		t.Helper()
		p := map[string]any{"session_id": session, "transcript_path": "/tmp/agent/transcript.jsonl", "cwd": "/workspace",
			"permission_mode": "default", "hook_event_name": event, "tool_name": "Bash", "tool_use_id": toolUse,
			"tool_input": map[string]any{"command": "echo hello", "description": "Print hello"}}
		for k, v := range extra {
			p[k] = v
		}
		payload, _ := json.Marshal(p)
		if _, _, code := agent(string(payload), "/tmp/agent/venv/bin/python", "-I", "-m",
			"tracekit.integrations.claude_code", event); code != 0 {
			t.Fatalf("%s hook: exit %d", event, code)
		}
	}
	hook("PreToolUse", nil)

	// the hook's run, from its session state (named by the session id's sha256)
	sum := sha256.Sum256([]byte(session))
	out, _, code := e.exec(t, "ch1", "cat", "/tmp/agent/rt/claude-code-"+hex.EncodeToString(sum[:])+".json")
	var agentRun struct {
		RunID    string `json:"run_id"`
		RunToken string `json:"run_token"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &agentRun) != nil || agentRun.RunID == "" {
		t.Fatalf("the hook's session state: exit %d", code)
	}

	t.Run("refused-in-box", func(t *testing.T) {
		a := e.frames(t, "ch1",
			map[string]any{"method": "approval_decide", "request_id": rid(), "approval_id": "a-1", "decision": "approve"},
			map[string]any{"method": "register_run", "request_id": rid(), "agent": map[string]any{"name": "sub"},
				"parent": map[string]any{"run_id": agentRun.RunID, "run_token": agentRun.RunToken}},
			map[string]any{"method": "close_run", "request_id": rid(), "run_id": b1.RunID, "run_token": "x"},
			map[string]any{"method": "decide", "request_id": rid(), "run_id": b1.RunID, "run_token": "x",
				"stream": "s", "client_seq": 0, "tool_call_id": "t1", "tool": "Bash", "args_source": "parsed",
				"args": map[string]any{"command": "true"}})
		refusedByBox(t, "approval_decide", a[0], `method "approval_decide" is not allowed`)
		refusedByBox(t, "register_run with parent", a[1], "forbidden register_run field")
		refusedByBox(t, "close_run of the box run", a[2], "run is not owned by this box")
		refusedByBox(t, "decide in the box run", a[3], "run is not owned by this box")
	})

	t.Run("second-box", func(t *testing.T) {
		newBox(t, "ch2")
		a := e.frames(t, "ch2",
			map[string]any{"method": "register_run", "request_id": rid(), "agent": map[string]any{"name": "probe"}},
			map[string]any{"method": "decide", "request_id": rid(), "run_id": agentRun.RunID, "run_token": agentRun.RunToken,
				"stream": "s", "client_seq": 0, "tool_call_id": "t1", "tool": "Bash", "args_source": "parsed",
				"args": map[string]any{"command": "true"}},
			map[string]any{"method": "close_run", "request_id": rid(), "run_id": agentRun.RunID, "run_token": agentRun.RunToken})
		if a[0].Error != nil || a[0].RunID == "" || a[0].RunID == agentRun.RunID {
			t.Fatalf("ch2's own register_run: %+v %+v", a[0], a[0].Error)
		}
		refusedByBox(t, "ch1's run through ch2 (decide)", a[1], "run is not owned by this box")
		refusedByBox(t, "ch1's run through ch2 (close_run)", a[2], "run is not owned by this box")
		if _, _, code := e.tk(t, "stop", "ch2"); code != 0 {
			t.Fatal("stop ch2")
		}
		if n, methods := e.refusals(t, "ch2"); n["run"] != 2 || len(n) != 1 || !slices.Contains(methods, "decide") {
			t.Errorf("ch2's events: %v %v, want its two refusals of ch1's run", n, methods)
		}
	})

	// ch1's run is untouched by all of that: the call completes
	hook("PostToolUse", map[string]any{"tool_response": map[string]any{"stdout": "hello", "stderr": "",
		"interrupted": false, "isImage": false}})

	if _, _, code := e.tk(t, "stop", "ch1"); code != 0 {
		t.Fatal("stop ch1")
	}
	// the refusals are the box's events, not only the agent's errors: the method, the parent and the two frames naming
	// the box run (the transcript tailer's tailer_heartbeat is a method refusal too)
	if n, methods := e.refusals(t, "ch1"); n["method"] < 1 || n["field"] != 1 || n["run"] != 2 ||
		!slices.Contains(methods, "register_run") || !slices.Contains(methods, "close_run") {
		t.Errorf("ch1's events: %v %v, want its refusals of approval_decide, parent and the box run", n, methods)
	}

	// the box run as a person exports it (tkbox export, through the daemon's --tracekit-config), the agent run with
	// the signer's own export
	dir := t.TempDir()
	agentBundle, boxBundle := filepath.Join(dir, "agent.tkb"), filepath.Join(dir, "box.tkb")
	if _, _, code := e.tk(t, "export", "ch1", "-o", boxBundle); code != 0 {
		t.Fatal("tkbox export ch1")
	}
	trust := strings.TrimSuffix(boxBundle, ".tkb") + ".trust.json"
	boxOut, err := s.cli(t, "verify", boxBundle, "--trust", trust)
	if err != nil {
		t.Fatalf("verify the box run: %v\n%s", err, boxOut)
	}
	agentOut := s.exportVerified(t, agentRun.RunID, agentBundle, trust)
	for _, x := range []struct{ name, run, out, line string }{
		{"agent run", agentRun.RunID, agentOut, "This run's records are the agent's own account of its calls"},
		{"box run", b1.RunID, boxOut, "This run's records are the box's doors"},
	} {
		out := x.out
		t.Logf("tracekit verify (%s %s):\n%s", x.name, x.run, out)
		for _, want := range []string{"PROOF AGAINST THE BOXED AGENT (micro-VM): the signing key was outside its box for this run.", x.line} {
			if !strings.Contains(out, want) {
				t.Errorf("verify of the %s does not say %q", x.name, want)
			}
		}
	}

	agentRecs, boxRecs := runRecords(t, agentBundle, agentRun.RunID), runRecords(t, boxBundle, b1.RunID)
	reg := agentRecs[0].Event
	label, _ := reg.Ext["box"].(map[string]any)
	t.Logf("agent run.registered: ext %v, parent_run %v", reg.Ext, reg.Data["parent_run"])
	var allow []string
	list, _ := label["allow"].([]any)
	for _, a := range list {
		host, _ := a.(string)
		allow = append(allow, host)
	}
	switch {
	case reg.Type != "run.registered":
		t.Errorf("the agent run starts with %s", reg.Type)
	case label["id"] != b1.ID || label["image_digest"] != b1.ImageDigest || label["engine"] != "firecracker" ||
		label["channel"] != "agent" || !slices.Equal(allow, b1.Allow):
		t.Errorf("ext.box %v, want id %s, image_digest %s, allow %v, engine firecracker, channel agent", label, b1.ID,
			b1.ImageDigest, b1.Allow)
	case reg.Data["parent_run"] != b1.RunID:
		t.Errorf("parent_run %v, want the box run %s", reg.Data["parent_run"], b1.RunID)
	}
	if firstOf(agentRecs, "policy.decision") == nil || firstOf(agentRecs, "tool.result") == nil {
		t.Error("the agent run has no decision or no result of the hook's call")
	}
	ac, bc := firstOf(agentRecs, "run.closing"), firstOf(boxRecs, "run.closing")
	if ac == nil || bc == nil || ac.Event.Seq >= bc.Event.Seq {
		t.Errorf("the box run must close after its channel's run: %+v %+v", ac, bc)
	} else {
		t.Logf("run.closing: agent run at seq %d, box run at seq %d", ac.Event.Seq, bc.Event.Seq)
	}
}
