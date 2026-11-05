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
