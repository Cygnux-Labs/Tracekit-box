package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/config"
	"github.com/Cygnux-Labs/tracekit-box/internal/daemon"
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

// mcpServer is the MCP server. The agent calling it may only narrow what the operator set up: it can't add hosts to
// the allowlist, set env for every command, pick an image the operator did not list, or copy in a host dir outside
// the operator's workspace roots.
type mcpServer struct {
	c      *client
	base   *config.File // operator's tkbox.yaml: the only source of secrets for tkbox_run
	images []string     // images tkbox_run may use: the config's image, then each --image
	roots  []string     // dirs (symlinks resolved) a tkbox_run workspace must be inside
	out    io.Writer
	mu     sync.Mutex
	owned  map[string]string // box id → name of every box this session's tkbox_run created: the only boxes it may use
}

func cmdMCP(ctx context.Context, args []string, env *cliEnv) error {
	fs, sock := newFlags("mcp", env)
	cfgPath := fs.String("config", "", "tkbox.yaml whose image, allowlist, secrets, env and limits every tkbox_run starts from")
	var images, roots stringList
	fs.Var(&images, "image", "an image tkbox_run may use besides the config's (repeatable)")
	fs.Var(&roots, "workspace-root", "a host dir tkbox_run may copy a workspace from, itself or below it (repeatable; default: the config's workspace only)")
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
		if f.Image != "" {
			s.images = append(s.images, f.Image)
		}
	}
	s.images = append(s.images, images.vals...)
	for _, r := range roots.vals {
		abs, err := filepath.Abs(r)
		if err == nil {
			abs, err = filepath.EvalSymlinks(abs)
		}
		if err != nil {
			return fmt.Errorf("--workspace-root %s: %v", r, err)
		}
		s.roots = append(s.roots, abs)
	}
	return s.serve(ctx, env.stdin)
}

// mcpRefused is a tkbox_run argument that would widen the box past what the operator set up.
func mcpRefused(format string, a ...any) error {
	return &api.ErrorDetail{Code: api.CodeForbidden, Message: fmt.Sprintf(format, a...),
		Hint: "an MCP client may only narrow what the operator set up in `tkbox mcp` (--config, --image, --workspace-root); ask the operator"}
}

// runRequest builds a tkbox_run create request from the operator's setup, narrowed by the agent's arguments.
func (s *mcpServer) runRequest(a mcpRunArgs) (api.CreateBoxRequest, error) {
	if len(a.Env) > 0 {
		return api.CreateBoxRequest{}, mcpRefused("tkbox_run may not set env for every command (it would apply to commands without being decided); put env in the command itself")
	}
	if a.Task != "" {
		// the run records the task as the operator's trusted instruction; an agent's words must not take its place
		return api.CreateBoxRequest{}, mcpRefused("tkbox_run takes no task: the run records only the operator's configured task as trusted; keep your own notes in your prompt")
	}
	image := a.Image
	switch {
	case len(s.images) == 0:
		return api.CreateBoxRequest{}, mcpRefused("tkbox mcp was started without an image: the operator passes --config with image: or --image")
	case image == "":
		image = s.images[0]
	case !slices.Contains(s.images, image):
		return api.CreateBoxRequest{}, mcpRefused("image %q is not one the operator allows (%s)", image, strings.Join(s.images, ", "))
	}
	var baseAllow []string
	if s.base != nil {
		baseAllow = s.base.Allow
	}
	for _, h := range a.Allow {
		if !slices.Contains(baseAllow, h) {
			return api.CreateBoxRequest{}, mcpRefused("tkbox_run may not add %q to the allowlist: it is not in the operator's (%s)", h, orNone(baseAllow))
		}
	}
	workspace := ""
	if a.Workspace != "" {
		// the path checked is the path used: symlinks resolved once, here, so it can't change between the two
		real, err := s.checkWorkspace(a.Workspace)
		if err != nil {
			return api.CreateBoxRequest{}, err
		}
		workspace = real
	}
	// each limit may only go down from the operator's; one the config leaves unset is the daemon's default
	l := s.limits()
	if a.CPUs > l.CPUs {
		return api.CreateBoxRequest{}, mcpRefused("cpus %d is over the operator's %d", a.CPUs, l.CPUs)
	}
	if a.Memory != "" {
		if m, err := config.ParseSize(a.Memory); err == nil && m > int(l.Memory) {
			return api.CreateBoxRequest{}, mcpRefused("memory %s is over the operator's %dMiB", a.Memory, int(l.Memory))
		}
	}
	if a.Timeout != "" {
		if d, err := config.ParseDuration(a.Timeout); err == nil && d > time.Duration(l.Timeout) {
			return api.CreateBoxRequest{}, mcpRefused("timeout %s is over the operator's %s", a.Timeout, time.Duration(l.Timeout))
		}
	}
	req, err := config.Request(s.base, config.Flags{Image: image, Name: a.Name, Workspace: workspace,
		CPUs: a.CPUs, Memory: a.Memory, Timeout: a.Timeout, Agent: "mcp"}, config.Resolver{})
	if err != nil {
		return api.CreateBoxRequest{}, err
	}
	if len(a.Allow) > 0 {
		req.Allow = append([]string(nil), a.Allow...) // narrowed to the hosts the agent named
	}
	return req, nil
}

// limits are the most a tkbox_run may ask for: the operator's config limits, and the daemon's defaults for any the
// config leaves unset (never the global maximum).
func (s *mcpServer) limits() config.Limits {
	l := config.Limits{CPUs: daemon.DefaultCPUs, Memory: config.Size(daemon.DefaultMemoryMiB),
		Timeout: config.Duration(daemon.DefaultTimeout), ExecTimeout: config.Duration(daemon.DefaultExecTimeout)}
	if s.base == nil {
		return l
	}
	b := s.base.Limits
	if b.CPUs != 0 {
		l.CPUs = b.CPUs
	}
	if b.Memory != 0 {
		l.Memory = b.Memory
	}
	if b.Timeout != 0 {
		l.Timeout = b.Timeout
	}
	if b.ExecTimeout != 0 {
		l.ExecTimeout = b.ExecTimeout
	}
	return l
}

// checkWorkspace allows a workspace only inside an operator root (--workspace-root), or the config's own workspace.
// It returns the resolved path (symlinks evaluated): the one that was checked is the one the box must use.
func (s *mcpServer) checkWorkspace(ws string) (string, error) {
	if !filepath.IsAbs(ws) {
		return "", &api.ErrorDetail{Code: api.CodeBadRequest, Message: "workspace must be an absolute path"}
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(ws))
	if err != nil {
		return "", &api.ErrorDetail{Code: api.CodeBadRequest, Message: fmt.Sprintf("workspace %s: %v", ws, err)}
	}
	if len(s.roots) == 0 && s.base != nil {
		if cw := s.base.WorkspacePath(); cw != "" {
			if rr, err := filepath.EvalSymlinks(cw); err == nil && rr == real {
				return real, nil // exactly the config's workspace
			}
		}
	}
	for _, r := range s.roots {
		if real == r || strings.HasPrefix(real, r+string(filepath.Separator)) {
			return real, nil
		}
	}
	return "", mcpRefused("workspace %s is outside the dirs the operator allows (tkbox mcp --workspace-root)", ws)
}

type mcpRunArgs struct {
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

func (s *mcpServer) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.Write(append(b, '\n'))
}

func (s *mcpServer) serve(parent context.Context, in io.Reader) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), mcpMaxLine)
	// when the client goes away (stdin closes) its in-flight calls are cancelled: execs stop instead of running on
	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
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
		{"name": "tkbox_run", "description": "Create a box (a micro-VM) and return its id. Image, allowlist, secrets and env come from the operator's setup; these arguments can only narrow it.",
			"inputSchema": schema(map[string]any{
				"image":     strProp("OCI image (default: the operator's; only images the operator allows)"),
				"name":      strProp("box name: lower case letters, digits and -"),
				"allow":     arrProp("narrow the egress allowlist to these entries of the operator's allowlist (nothing can be added)"),
				"workspace": strProp("absolute host dir copied into /workspace (default: the operator's; only inside the operator's workspace roots)"),
				"cpus":      map[string]any{"type": "integer", "minimum": 1, "maximum": 32},
				"memory":    strProp("e.g. 2GiB (at most the operator's limit)"),
				"timeout":   strProp("box lifetime, e.g. 1h (at most the operator's limit)"),
			})},
		{"name": "tkbox_exec", "description": "Run a command in a box (decided by the Tracekit signer first) and return its exit code and output.",
			"inputSchema": schema(map[string]any{
				"box":     strProp("id or name of a box this session created with tkbox_run"),
				"argv":    arrProp("the command and its arguments, e.g. [\"pytest\", \"-q\"]"),
				"stdin":   strProp("text sent to the command's stdin"),
				"cwd":     strProp("working dir in the box (default /workspace)"),
				"timeout": strProp("e.g. 10m (default the box's exec timeout)"),
			}, "box", "argv")},
		{"name": "tkbox_diff", "description": "Show the workspace changes of a box as a git patch.",
			"inputSchema": schema(map[string]any{"box": strProp("id or name of a box this session created with tkbox_run")}, "box")},
		{"name": "tkbox_stop", "description": "Stop a box (its diff is saved first unless kill is set).",
			"inputSchema": schema(map[string]any{"box": strProp("id or name of a box this session created with tkbox_run"), "kill": map[string]any{"type": "boolean"}}, "box")},
		{"name": "tkbox_ls", "description": "List the boxes this session created with tkbox_run.", "inputSchema": schema(map[string]any{})},
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

// ownBox resolves the "box" argument of a tool call through the boxes this session created and rewrites it to that
// box's id, so a session can never reach a box someone else started (or a later box that reused an owned name).
func (s *mcpServer) ownBox(raw json.RawMessage) (json.RawMessage, error) {
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &api.ErrorDetail{Code: api.CodeBadRequest, Message: "arguments: " + err.Error()}
	}
	var ref string
	if err := json.Unmarshal(args["box"], &ref); err != nil || ref == "" {
		return nil, &api.ErrorDetail{Code: api.CodeBadRequest, Message: "box is required"}
	}
	s.mu.Lock()
	id := ""
	for bid, name := range s.owned {
		if ref == bid || ref == name {
			id = bid
			break
		}
	}
	s.mu.Unlock()
	if id == "" {
		return nil, mcpRefused("box %s was not created by this tkbox mcp session: it may only use the boxes its tkbox_run created", ref)
	}
	args["box"], _ = json.Marshal(id)
	return json.Marshal(args)
}

func (s *mcpServer) call(ctx context.Context, name string, raw json.RawMessage) (string, bool, error) {
	switch name {
	case "tkbox_exec", "tkbox_diff", "tkbox_stop":
		var err error
		if raw, err = s.ownBox(raw); err != nil {
			return "", true, err
		}
	}
	switch name {
	case "tkbox_run":
		var a mcpRunArgs
		if err := strictDecode(raw, &a); err != nil {
			return "", true, err
		}
		req, err := s.runRequest(a)
		if err != nil {
			return "", true, err
		}
		var b api.Box
		if err := s.c.do(ctx, "POST", "/v1/boxes", req, &b); err != nil {
			return "", true, err
		}
		s.mu.Lock()
		if s.owned == nil {
			s.owned = map[string]string{}
		}
		s.owned[b.ID] = b.Name
		s.mu.Unlock()
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
			if max := time.Duration(s.limits().ExecTimeout); d > max {
				return "", true, mcpRefused("timeout %s is over the operator's exec timeout %s", a.Timeout, max)
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
		code := execExitCode(st, nil, &cliEnv{stderr: io.Discard})
		fmt.Fprintf(&b, "exit code %d", code)
		if st.StdinTruncated {
			b.WriteString(" (" + strings.TrimPrefix(stdinTruncatedMsg(st), "tkbox: ") + ")")
		} else if st.TimedOut {
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
		return fmt.Sprintf("%s changed\n%s", plural(len(sum.Files), "file"), cw), false, nil
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
		s.mu.Lock()
		mine := boxes[:0]
		for _, x := range boxes {
			if _, ok := s.owned[x.ID]; ok {
				mine = append(mine, x)
			}
		}
		s.mu.Unlock()
		boxes = mine
		if len(boxes) == 0 {
			return "no boxes created by this session", false, nil
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
