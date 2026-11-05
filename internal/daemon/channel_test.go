package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// A box with --agent-channel used to close its own run at every stop, so `tkbox apply` refused and left only an
// ungated `git apply`. A stopped channel box keeps its run open and applies its patch through the gate, as a plain
// box does.
func TestChannelBoxAppliesThroughTheGate(t *testing.T) {
	ctx := context.Background()
	for _, channel := range []bool{false, true} {
		e := newTestEnv(t, nil)
		e.tk.RPCVersion = 21
		e.tk.ChannelDial = func() (net.Conn, error) {
			a, z := net.Pipe()
			go io.Copy(io.Discard, z)
			return a, nil
		}
		ws := t.TempDir()
		gitInit(t, ws)
		os.WriteFile(filepath.Join(ws, "a.txt"), []byte("old\n"), 0o644)
		e.guest.Patch = modify("a.txt")
		e.create(api.CreateBoxRequest{Name: "ch", Workspace: ws, AgentChannel: channel})
		if _, err := e.d.Stop(ctx, "ch", api.StopRequest{}); err != nil {
			t.Fatal(err)
		}
		res, err := e.d.Apply(ctx, "ch", api.ApplyRequest{})
		t.Logf("agent_channel=%v: apply %+v, %v", channel, res, err)
		if err != nil {
			t.Fatalf("agent_channel=%v: a stopped box can't apply through the gate: %v", channel, err)
		}
	}
}

// A kill stop (`tkbox stop --kill`, and containment's quarantine) used to close the channel's runs one at a time before
// it killed the VM, each waiting up to 300 s for its close_run answer. The VM goes down first, within seconds,
// whatever the signer does with the close_run calls.
func TestKillIsNotHeldByChannelRunCloses(t *testing.T) {
	e := newTestEnv(t, nil)
	e.tk.RPCVersion = 21
	var mu sync.Mutex
	var peers []net.Conn
	n := 0
	e.tk.ChannelDial = func() (net.Conn, error) {
		a, z := net.Pipe()
		mu.Lock()
		peers = append(peers, z)
		mu.Unlock()
		go func() {
			r := bufio.NewReader(z)
			for {
				line, err := r.ReadBytes('\n')
				if err != nil {
					return
				}
				var m map[string]any
				_ = json.Unmarshal(line, &m)
				if m["method"] == "close_run" {
					continue // a slow signer: the answer never comes
				}
				mu.Lock()
				n++
				id := fmt.Sprintf("child-%d", n)
				mu.Unlock()
				out, _ := json.Marshal(map[string]any{"run_id": id, "run_token": "tok-" + id})
				if _, err := z.Write(append(out, '\n')); err != nil {
					return
				}
			}
		}()
		return a, nil
	}
	e.create(api.CreateBoxRequest{Name: "k", Image: "x", AgentChannel: true})
	c, err := e.machine(0).GuestDial(context.Background(), proto.PortAgentChannel)
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	for i := 0; i < 3; i++ {
		fmt.Fprintf(c, `{"method":"register_run","request_id":"r%d","agent":{"name":"claude-code"}}`+"\n", i)
		if _, err := r.ReadBytes('\n'); err != nil {
			t.Fatal(err)
		}
	}
	c.Close()
	go e.d.Stop(context.Background(), "k", api.StopRequest{Kill: true})
	defer func() {
		mu.Lock()
		for _, p := range peers {
			p.Close()
		}
		mu.Unlock()
	}()
	select {
	case <-e.machine(0).Done():
	case <-time.After(5 * time.Second):
		t.Fatalf("--kill: the VM is still %s 5 s later, waiting on the channel's close_run calls (3 runs x up to 300 s; up to 256 runs)", e.machine(0).State)
	}
}

// A kill used to wait CloseReplyWait (2 s) when any agent frame, such as an approval_wait long poll, was with the
// signer. Only a register_run in flight is waited for now: the VM goes down at once.
func TestKillIsNotHeldByALongPoll(t *testing.T) {
	e := newTestEnv(t, nil)
	e.tk.RPCVersion = 21
	var mu sync.Mutex
	var peers []net.Conn
	e.tk.ChannelDial = func() (net.Conn, error) {
		a, z := net.Pipe()
		mu.Lock()
		peers = append(peers, z)
		mu.Unlock()
		go func() {
			r := bufio.NewReader(z)
			for {
				line, err := r.ReadBytes('\n')
				if err != nil {
					return
				}
				var m map[string]any
				_ = json.Unmarshal(line, &m)
				if m["method"] != "register_run" {
					continue // approval_wait: the person hasn't answered
				}
				if _, err := z.Write([]byte(`{"run_id":"child-1","run_token":"tok"}` + "\n")); err != nil {
					return
				}
			}
		}()
		return a, nil
	}
	defer func() {
		mu.Lock()
		for _, p := range peers {
			p.Close()
		}
		mu.Unlock()
	}()
	e.create(api.CreateBoxRequest{Name: "k", Image: "x", AgentChannel: true})
	c, err := e.machine(0).GuestDial(context.Background(), proto.PortAgentChannel)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	fmt.Fprint(c, `{"method":"register_run","request_id":"r","agent":{"name":"claude-code"}}`+"\n")
	if _, err := r.ReadBytes('\n'); err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, `{"method":"approval_wait","request_id":"w","run_id":"child-1","run_token":"tok","approval_id":"a1"}`+"\n")
	time.Sleep(100 * time.Millisecond) // the long poll is with the signer
	start := time.Now()
	go e.d.Stop(context.Background(), "k", api.StopRequest{Kill: true})
	select {
	case <-e.machine(0).Done():
		took := time.Since(start)
		t.Logf("--kill with a long poll in flight: the VM was killed %v after the stop began", took.Round(10*time.Millisecond))
		if took > time.Second {
			t.Errorf("a kill waited %v on a signer reply (approval_wait)", took.Round(10*time.Millisecond))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("VM not killed in 10 s")
	}
}

// Tracekit's Claude Code hook registers as claude-code, and the GitHub Action names a Claude Code box's run
// --agent claude-code: a rule refusing agent runs the box run's name refused every register_run the hook sent, so every
// tool call was blocked. What tells the box run's records from the agent's is signer-written (the agent run's
// parent_run and copied ext.box label, the box run's none), not the self-asserted name.
func TestTheHooksRegisterRunPassesInAClaudeCodeBox(t *testing.T) {
	e := newTestEnv(t, nil)
	e.tk.RPCVersion = 21
	e.tk.ChannelDial = func() (net.Conn, error) {
		a, z := net.Pipe()
		go func() {
			r := bufio.NewReader(z)
			for {
				if _, err := r.ReadBytes('\n'); err != nil {
					return
				}
				if _, err := z.Write([]byte(`{"run_id":"child-1","run_token":"tok","fail_modes":{"default":"closed"}}` + "\n")); err != nil {
					return
				}
			}
		}()
		return a, nil
	}
	e.create(api.CreateBoxRequest{Name: "cc", Image: "x", Agent: "claude-code", AgentChannel: true})
	c, err := e.machine(0).GuestDial(context.Background(), proto.PortAgentChannel)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// the frame Tracekit 1.5.3's HookClient sends (claude_code.py _register: AGENT "claude-code", CLAUDE_CODE_VERSION)
	fmt.Fprint(c, `{"method":"register_run","agent":{"name":"claude-code","version":"2.1.307"},"request_id":"6a1f0c2e9b8d4f3a"}`+"\n")
	ans, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil || !strings.Contains(string(ans), `"run_id":"child-1"`) {
		t.Fatalf("the hook's register_run in a box run named claude-code: %q %v", ans, err)
	}
}
