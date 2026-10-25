package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/config"
)

// MCP over stdio: JSON-RPC 2.0, one message per line.
const mcpProtocol = "2025-06-18"

const (
	mcpMaxOutput = 64 << 10  // per stream of tkbox_exec
	mcpMaxDiff   = 256 << 10 // tkbox_diff
	mcpMaxLine   = 4 << 20
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpServer struct {
	c    *client
	base *config.File // operator's tkbox.yaml: the only source of secrets for tkbox_run
	out  io.Writer
	mu   sync.Mutex
}

func cmdMCP(ctx context.Context, args []string, env *cliEnv) error {
	fs, sock := newFlags("mcp", env)
	cfgPath := fs.String("config", "", "tkbox.yaml whose image, allowlist and secrets every tkbox_run starts from")
	if _, err := parseAll(fs, args); err != nil {
		return err
	}
	s := &mcpServer{c: newClient(*sock), out: env.stdout}
	if *cfgPath != "" {
		f, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		s.base = f
	}
	return s.serve(ctx, env.stdin)
}

func (s *mcpServer) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.Write(append(b, '\n'))
}

func (s *mcpServer) serve(ctx context.Context, in io.Reader) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), mcpMaxLine)
	var wg sync.WaitGroup
	defer wg.Wait()
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
			s.send(rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error: want one JSON-RPC 2.0 message per line"}})
			continue
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue // a notification (notifications/initialized, cancelled, …): nothing to answer
		}
		// tool calls can take minutes (an exec); answer each in its own goroutine
		wg.Add(1)
		go func(req rpcRequest) {
			defer wg.Done()
			res, rerr := s.handle(ctx, req)
			resp := rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: res, Error: rerr}
			if rerr == nil && res == nil {
				resp.Result = struct{}{}
			}
			s.send(resp)
		}(req)
	}
	return sc.Err()
}

func (s *mcpServer) handle(ctx context.Context, req rpcRequest) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": mcpProtocol,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "tkbox", "version": version},
			"instructions": "Tracekit Box runs commands in a Firecracker micro-VM with no network card: every command, " +
				"connection and file write is decided by a Tracekit signer. Create a box with tkbox_run, run commands with " +
				"tkbox_exec, read the changes with tkbox_diff and stop it with tkbox_stop. A person applies changes to the " +
				"host with `tkbox apply`.",
		}, nil
	case "ping":
		return struct{}{}, nil
	case "tools/list":
		return map[string]any{"tools": mcpTools()}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return nil, &rpcError{Code: -32602, Message: "tools/call needs {name, arguments}"}
		}
		if len(p.Arguments) == 0 || string(p.Arguments) == "null" {
			p.Arguments = json.RawMessage("{}")
		}
		text, isErr, err := s.call(ctx, p.Name, p.Arguments)
		if err != nil {
			var unknown unknownTool
			if errors.As(err, &unknown) {
				return nil, &rpcError{Code: -32602, Message: err.Error()}
			}
			var b strings.Builder
			printErr(&b, err)
			text, isErr = strings.TrimSpace(b.String()), true
		}
		return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr}, nil
	default:
		return nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
}

type unknownTool string

func (u unknownTool) Error() string { return "unknown tool " + string(u) }

func schema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

var (
	strProp = func(d string) map[string]any { return map[string]any{"type": "string", "description": d} }
	arrProp = func(d string) map[string]any {
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": d}
	}
)

func mcpTools() []map[string]any {
	return []map[string]any{
		{"name": "tkbox_run", "description": "Create a box (a micro-VM) and return its id. Secrets come only from the operator's tkbox.yaml.",
			"inputSchema": schema(map[string]any{
				"image":     strProp("OCI image, e.g. python:3.12-slim (default: the operator's tkbox.yaml)"),
				"name":      strProp("box name: lower case letters, digits and -"),
				"allow":     arrProp("presets (github, pypi, npm, anthropic, openai, apt-ubuntu, go-proxy) or hosts the box may reach"),
				"workspace": strProp("absolute host dir copied into /workspace"),
				"env":       map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "plain env for every command"},
				"cpus":      map[string]any{"type": "integer", "minimum": 1, "maximum": 32},
				"memory":    strProp("e.g. 2GiB"),
				"timeout":   strProp("box lifetime, e.g. 1h"),
				"task":      strProp("the task, recorded in the Tracekit run"),
			})},
		{"name": "tkbox_exec", "description": "Run a command in a box (decided by the Tracekit signer first) and return its exit code and output.",
			"inputSchema": schema(map[string]any{
				"box":     strProp("box id or name"),
				"argv":    arrProp("the command and its arguments, e.g. [\"pytest\", \"-q\"]"),
				"stdin":   strProp("text sent to the command's stdin"),
				"cwd":     strProp("working dir in the box (default /workspace)"),
				"timeout": strProp("e.g. 10m (default the box's exec timeout)"),
			}, "box", "argv")},
		{"name": "tkbox_diff", "description": "Show the workspace changes of a box as a git patch.",
			"inputSchema": schema(map[string]any{"box": strProp("box id or name")}, "box")},
		{"name": "tkbox_stop", "description": "Stop a box (its diff is saved first unless kill is set).",
			"inputSchema": schema(map[string]any{"box": strProp("box id or name"), "kill": map[string]any{"type": "boolean"}}, "box")},
		{"name": "tkbox_ls", "description": "List boxes.", "inputSchema": schema(map[string]any{})},
	}
}

func strictDecode(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &api.ErrorDetail{Code: api.CodeBadRequest, Message: "arguments: " + err.Error()}
	}
	return nil
}

// capWriter keeps the first n bytes and counts the rest.
type capWriter struct {
	buf     bytes.Buffer
	n       int
	dropped int
}

func (c *capWriter) Write(p []byte) (int, error) {
	room := c.n - c.buf.Len()
	if room > 0 {
		k := min(room, len(p))
		c.buf.Write(p[:k])
		c.dropped += len(p) - k
	} else {
		c.dropped += len(p)
	}
	return len(p), nil
}

func (c *capWriter) String() string {
	s := c.buf.String()
	if c.dropped > 0 {
		s += fmt.Sprintf("\n[… %d more bytes not shown]", c.dropped)
	}
	return s
}

func (s *mcpServer) call(ctx context.Context, name string, raw json.RawMessage) (string, bool, error) {
	switch name {
	case "tkbox_run":
		var a struct {
			Image     string            `json:"image"`
			Name      string            `json:"name"`
			Allow     []string          `json:"allow"`
			Workspace string            `json:"workspace"`
			Env       map[string]string `json:"env"`
			CPUs      int               `json:"cpus"`
			Memory    string            `json:"memory"`
			Timeout   string            `json:"timeout"`
			Task      string            `json:"task"`
		}
		if err := strictDecode(raw, &a); err != nil {
			return "", true, err
		}
		if a.Workspace != "" && !strings.HasPrefix(a.Workspace, "/") {
			return "", true, &api.ErrorDetail{Code: api.CodeBadRequest, Message: "workspace must be an absolute path"}
		}
		req, err := config.Request(s.base, config.Flags{Image: a.Image, Name: a.Name, Allow: a.Allow, Workspace: a.Workspace,
			Env: a.Env, CPUs: a.CPUs, Memory: a.Memory, Timeout: a.Timeout, Task: a.Task, Agent: "mcp"}, config.Resolver{})
		if err != nil {
			return "", true, err
		}
		var b api.Box
		if err := s.c.do(ctx, "POST", "/v1/boxes", req, &b); err != nil {
			return "", true, err
		}
		text := fmt.Sprintf("box %s (id %s) is running %s; allowed egress: %s", b.Name, b.ID, b.Image, orNone(b.Allow))
		if b.Unrecorded {
			text += "\n" + unrecordedWarning
		}
		return text, false, nil
	case "tkbox_exec":
		var a struct {
			Box     string   `json:"box"`
			Argv    []string `json:"argv"`
			Stdin   string   `json:"stdin"`
			Cwd     string   `json:"cwd"`
			Timeout string   `json:"timeout"`
		}
		if err := strictDecode(raw, &a); err != nil {
			return "", true, err
		}
		if a.Box == "" || len(a.Argv) == 0 {
			return "", true, &api.ErrorDetail{Code: api.CodeBadRequest, Message: "box and argv are required"}
		}
		req := api.ExecRequest{Argv: a.Argv, Cwd: a.Cwd}
		if a.Timeout != "" {
			d, err := time.ParseDuration(a.Timeout)
			if err != nil {
				return "", true, &api.ErrorDetail{Code: api.CodeBadRequest, Message: "timeout: want e.g. 10m"}
			}
			req.Timeout = api.Duration(d)
		}
		stdout, stderr := &capWriter{n: mcpMaxOutput}, &capWriter{n: mcpMaxOutput}
		var notices []string
		var nmu sync.Mutex
		eio := execIO{Stdout: stdout, Stderr: stderr, OnEvent: func(ev api.ExecEvent) {
			if ev.State == api.ExecNotice || ev.State == api.ExecWaitingApproval || (ev.Message != "" && ev.State == api.ExecRunning) {
				nmu.Lock()
				notices = append(notices, ev.Message)
				nmu.Unlock()
			}
		}}
		if a.Stdin != "" {
			eio.Stdin = strings.NewReader(a.Stdin)
		}
		st, err := s.c.exec(ctx, a.Box, req, eio)
		var b strings.Builder
		nmu.Lock()
		for _, n := range notices {
			fmt.Fprintf(&b, "tkbox: %s\n", n)
		}
		nmu.Unlock()
		if err != nil {
			printErr(&b, err)
			return strings.TrimSpace(b.String()), true, nil
		}
		code := execExitCode(st.Code, st.Signal, st.TimedOut, nil, &cliEnv{stderr: io.Discard})
		fmt.Fprintf(&b, "exit code %d", code)
		if st.TimedOut {
			b.WriteString(" (timed out)")
		} else if st.Signal != "" {
			b.WriteString(" (killed by " + st.Signal + ")")
		}
		fmt.Fprintf(&b, "\n--- stdout ---\n%s\n--- stderr ---\n%s", stdout, stderr)
		return b.String(), code != 0, nil
	case "tkbox_diff":
		var a struct {
			Box string `json:"box"`
		}
		if err := strictDecode(raw, &a); err != nil {
			return "", true, err
		}
		patch, sum, err := s.c.diff(ctx, a.Box)
		if err != nil {
			return "", true, err
		}
		if len(patch) == 0 {
			return "no changes", false, nil
		}
		cw := &capWriter{n: mcpMaxDiff}
		cw.Write(patch)
		return fmt.Sprintf("%d files changed\n%s", len(sum.Files), cw), false, nil
	case "tkbox_stop":
		var a struct {
			Box  string `json:"box"`
			Kill bool   `json:"kill"`
		}
		if err := strictDecode(raw, &a); err != nil {
			return "", true, err
		}
		var b api.Box
		if err := s.c.do(ctx, "POST", boxPath(a.Box, "/stop"), api.StopRequest{Kill: a.Kill, Reason: "stopped over MCP"}, &b); err != nil {
			return "", true, err
		}
		return fmt.Sprintf("box %s %s", b.Name, b.State), false, nil
	case "tkbox_ls":
		if err := strictDecode(raw, &struct{}{}); err != nil {
			return "", true, err
		}
		var boxes []api.Box
		if err := s.c.do(ctx, "GET", "/v1/boxes", nil, &boxes); err != nil {
			return "", true, err
		}
		if len(boxes) == 0 {
			return "no boxes", false, nil
		}
		var b strings.Builder
		for _, x := range boxes {
			fmt.Fprintf(&b, "%s %s %s %s", x.ID, x.Name, x.State, x.Image)
			if x.Unrecorded {
				b.WriteString(" UNRECORDED")
			}
			b.WriteString("\n")
		}
		return strings.TrimSpace(b.String()), false, nil
	default:
		return "", true, unknownTool(name)
	}
}
