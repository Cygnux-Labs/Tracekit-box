package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/config"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

const unrecordedWarning = "WARNING: this box is UNRECORDED: nothing it does is recorded in Tracekit and it cannot be exported. The allowlist and Box approvals still apply."

// buildRunRequest turns `tkbox run` flags (and tkbox.yaml) into a create request, resolving secrets from this
// process's env and files.
func buildRunRequest(args []string, env *cliEnv) (api.CreateBoxRequest, string, bool, error) {
	fs, sock := newFlags("run", env)
	var allow, secrets, envs stringList
	allow.split = true
	fl := config.Flags{}
	fs.StringVar(&fl.Image, "image", "", "OCI image, e.g. python:3.12-slim")
	fs.Var(&allow, "allow", "allowed preset or host (repeatable, or comma-separated)")
	fs.StringVar(&fl.Workspace, "workspace", "", "host dir copied into /workspace")
	fs.StringVar(&fl.Name, "name", "", "box name")
	fs.Var(&secrets, "secret", "NAME=env:VAR@host1,host2[#Header] or NAME=file:PATH@hosts[#Header] (repeatable)")
	fs.Var(&envs, "env", "KEY=VALUE for every exec (repeatable)")
	fs.IntVar(&fl.CPUs, "cpus", 0, "vCPUs (1..32, default 2)")
	fs.StringVar(&fl.Memory, "memory", "", "memory, e.g. 2GiB (default 2GiB)")
	fs.StringVar(&fl.Disk, "disk", "", "workspace disk, e.g. 4GiB (default 4GiB)")
	fs.StringVar(&fl.Timeout, "timeout", "", "box lifetime, e.g. 1h (default 1h)")
	fs.StringVar(&fl.Inspect, "inspect", "", `"bound" (default) or "all"`)
	fs.StringVar(&fl.Task, "task", "", "the task, recorded in the Tracekit run")
	fs.StringVar(&fl.Agent, "agent", "", `agent name recorded in the run (default "tkbox")`)
	cfgPath := fs.String("config", "", "tkbox.yaml (default ./tkbox.yaml if present)")
	noConfig := fs.Bool("no-config", false, "don't read ./tkbox.yaml")
	jsonOut := fs.Bool("json", false, "print the box as JSON")
	pos, err := parseAll(fs, args)
	if err != nil {
		return api.CreateBoxRequest{}, "", false, err
	}
	if len(pos) > 0 {
		return api.CreateBoxRequest{}, "", false, usagef("unexpected argument %q (flags only; the command goes to `tkbox exec`)", pos[0])
	}
	if *noConfig && *cfgPath != "" {
		return api.CreateBoxRequest{}, "", false, usagef("--config and --no-config: pick one")
	}
	var file *config.File
	path := *cfgPath
	if path == "" && !*noConfig {
		if _, err := os.Stat(config.DefaultFile); err == nil {
			path = config.DefaultFile
			fmt.Fprintf(env.stderr, "tkbox: reading settings from ./%s (pass --no-config to skip it)\n", config.DefaultFile)
		}
	}
	if path != "" {
		if file, err = config.Load(path); err != nil {
			return api.CreateBoxRequest{}, "", false, err
		}
	}
	fl.Allow = allow.vals
	if fl.Env, err = parseEnvList(envs.vals); err != nil {
		return api.CreateBoxRequest{}, "", false, err
	}
	for _, s := range secrets.vals {
		name, sec, err := config.ParseSecretFlag(s)
		if err != nil {
			return api.CreateBoxRequest{}, "", false, err
		}
		if fl.Secrets == nil {
			fl.Secrets = map[string]config.Secret{}
		}
		fl.Secrets[name] = sec
	}
	req, err := config.Request(file, fl, config.Resolver{})
	return req, *sock, *jsonOut, err
}

func cmdRun(ctx context.Context, args []string, env *cliEnv) error {
	req, sock, jsonOut, err := buildRunRequest(args, env)
	if err != nil {
		return err
	}
	c := newClient(sock)
	// the daemon checks the request first, so a bad flag is reported before anything is pulled or booted
	check := req
	check.ValidateOnly = true
	var preview api.Box
	if err := c.do(ctx, "POST", "/v1/boxes", check, &preview); err != nil {
		return err
	}
	fmt.Fprintf(env.stderr, "tkbox: creating a box from %s…\n", req.Image)
	var b api.Box
	if err := c.do(ctx, "POST", "/v1/boxes", req, &b); err != nil {
		return err
	}
	if jsonOut {
		return json.NewEncoder(env.stdout).Encode(b)
	}
	fmt.Fprintln(env.stdout, b.ID)
	fmt.Fprintf(env.stderr, "tkbox: box %s (%s) running %s", b.Name, b.ID, b.Image)
	if b.RunID != "" {
		fmt.Fprintf(env.stderr, ", Tracekit run %s", b.RunID)
	}
	fmt.Fprintf(env.stderr, "; expires %s\n", b.ExpiresAt.Local().Format(time.Kitchen))
	fmt.Fprintf(env.stderr, "tkbox: allowed egress: %s\n", orNone(b.Allow))
	for _, n := range b.Secrets {
		if h := b.SecretHeaders[n]; h != "" {
			fmt.Fprintf(env.stderr, "tkbox: secret %s goes only in the %s header, only to its bound hosts\n", n, h)
		}
	}
	for _, n := range b.Notices {
		fmt.Fprintf(env.stderr, "tkbox: %s\n", printable(env.stderr, n))
	}
	if b.Unrecorded {
		fmt.Fprintln(env.stderr, "tkbox: "+unrecordedWarning)
	}
	fmt.Fprintf(env.stderr, "tkbox: next: tkbox exec %s -- <command>\n", b.Name)
	return nil
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "(none: unknown hosts wait for `tkbox approve`)"
	}
	return strings.Join(s, ", ")
}

// Linux signal numbers (the guest is Linux; x86_64 and arm64 share them) for exit codes 128+n, with the usual aliases.
var signalNumbers = map[string]int{"SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGILL": 4, "SIGTRAP": 5, "SIGABRT": 6,
	"SIGIOT": 6, "SIGBUS": 7, "SIGFPE": 8, "SIGKILL": 9, "SIGUSR1": 10, "SIGSEGV": 11, "SIGUSR2": 12, "SIGPIPE": 13,
	"SIGALRM": 14, "SIGTERM": 15, "SIGSTKFLT": 16, "SIGCHLD": 17, "SIGCLD": 17, "SIGCONT": 18, "SIGSTOP": 19,
	"SIGTSTP": 20, "SIGTTIN": 21, "SIGTTOU": 22, "SIGURG": 23, "SIGXCPU": 24, "SIGXFSZ": 25, "SIGVTALRM": 26,
	"SIGPROF": 27, "SIGWINCH": 28, "SIGIO": 29, "SIGPOLL": 29, "SIGPWR": 30, "SIGSYS": 31, "SIGUNUSED": 31}

// Real-time signals as glibc and `kill -l` number them.
const sigRTMin, sigRTMax = 34, 64

// signalNumber maps a signal name ("SIGTERM", "SIGRTMIN+3", "SIGRTMAX-1", "signal 40") to its Linux number.
func signalNumber(name string) (int, bool) {
	if n, ok := signalNumbers[name]; ok {
		return n, true
	}
	num := func(s string) (int, bool) {
		n, err := strconv.Atoi(s)
		return n, err == nil && n >= 0
	}
	switch {
	case name == "SIGRTMIN":
		return sigRTMin, true
	case name == "SIGRTMAX":
		return sigRTMax, true
	case strings.HasPrefix(name, "SIGRTMIN+"):
		if n, ok := num(strings.TrimPrefix(name, "SIGRTMIN+")); ok && sigRTMin+n <= sigRTMax {
			return sigRTMin + n, true
		}
	case strings.HasPrefix(name, "SIGRTMAX-"):
		if n, ok := num(strings.TrimPrefix(name, "SIGRTMAX-")); ok && sigRTMax-n >= sigRTMin {
			return sigRTMax - n, true
		}
	case strings.HasPrefix(name, "signal "):
		if n, ok := num(strings.TrimPrefix(name, "signal ")); ok && n >= 1 && n <= sigRTMax {
			return n, true
		}
	}
	return 0, false
}

func cmdExec(args []string, env *cliEnv) int {
	fs, sock := newFlags("exec", env)
	interactive := fs.Bool("i", false, "forward stdin")
	timeout := fs.Duration("timeout", 0, "per-command timeout, 1s..24h (default the box's exec timeout)")
	cwd := fs.String("cwd", "", "working dir in the box (default /workspace)")
	var envs stringList
	fs.Var(&envs, "env", "KEY=VALUE (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(env.stderr, "tkbox exec: name the box: tkbox exec <box> -- <command>")
		return 2
	}
	box := rest[0]
	if err := fs.Parse(rest[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fmt.Fprintln(env.stderr, "tkbox exec: no command: tkbox exec <box> -- <command> [args...]")
		return 2
	}
	if *timeout != 0 && (*timeout < time.Second || *timeout > config.MaxExecTimeout) {
		fmt.Fprintf(env.stderr, "tkbox exec: --timeout %s: use 1s..24h\n", *timeout)
		return 2
	}
	envMap, err := parseEnvList(envs.vals)
	if err != nil {
		printErr(env.stderr, err)
		return 2
	}
	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigc)
	names := make(chan string, 4)
	go func() {
		interrupts := 0
		for s := range sigc {
			switch s {
			case os.Interrupt:
				// Ctrl-C goes to the process in the box (before it starts, it cancels it); the third one gives up here
				if interrupts++; interrupts >= 3 {
					fmt.Fprintln(env.stderr, "tkbox: giving up on the command (it may still run in the box; `tkbox stop` stops the box)")
					os.Exit(130)
				}
				names <- "SIGINT"
			case syscall.SIGTERM:
				names <- "SIGTERM"
			case syscall.SIGHUP:
				names <- "SIGHUP"
			case syscall.SIGQUIT:
				names <- "SIGQUIT"
			}
		}
	}()
	eio := execIO{Stdout: env.stdout, Stderr: env.stderr, Signals: names, OnEvent: func(ev api.ExecEvent) {
		switch ev.State {
		case api.ExecNotice:
			fmt.Fprintf(env.stderr, "tkbox: %s\n", printable(env.stderr, ev.Message))
		case api.ExecWaitingApproval:
			fmt.Fprintf(env.stderr, "tkbox: waiting for approval %s: %s\n", ev.ApprovalID, ev.Message)
		case api.ExecRunning:
			if ev.Message != "" {
				fmt.Fprintf(env.stderr, "tkbox: %s\n", ev.Message)
			}
		}
	}}
	if *interactive {
		eio.Stdin = env.stdin
	}
	st, err := newClient(*sock).exec(context.Background(), box,
		api.ExecRequest{Argv: argv, Env: envMap, Cwd: *cwd, Timeout: api.Duration(*timeout)}, eio)
	return execExitCode(st, err, env)
}

// stdinTruncatedMsg is what tkbox says when a command was stopped because it did not take its stdin.
func stdinTruncatedMsg(st proto.ExitStatus) string {
	return fmt.Sprintf("tkbox: stdin was not consumed fast enough (%d bytes dropped); the command was stopped: write large input to a file in /workspace and read it from there", st.StdinDroppedBytes)
}

// execExitCode maps an exec outcome to tkbox exec's exit code: the process's own, 128+n when a signal killed it,
// 124 timed out, 126 denied, 127 not found, 125 a tkbox error (including a command cancelled before it started, and
// one stopped because it did not take its stdin fast enough).
func execExitCode(st proto.ExitStatus, err error, env *cliEnv) int {
	if err != nil {
		printErr(env.stderr, err)
		var ae *api.ErrorDetail
		if errors.As(err, &ae) {
			switch {
			case ae.Code == api.CodeDenied:
				return exitDenied
			case ae.Code == api.CodeTimeout:
				return exitTimedOut
			case ae.Code == api.CodeNotFound && strings.HasPrefix(ae.Message, "start "):
				return exitNotFound
			}
		}
		return exitTkbox
	}
	if st.Truncated {
		fmt.Fprintf(env.stderr, "tkbox: output past %d MiB was dropped; write large output to a file and read the part you need\n", proto.DefaultMaxOutputBytes>>20)
	}
	switch {
	case st.StdinTruncated:
		fmt.Fprintln(env.stderr, stdinTruncatedMsg(st))
		return exitTkbox
	case st.TimedOut:
		fmt.Fprintln(env.stderr, "tkbox: the command was killed by its exec timeout; pass a longer --timeout (up to 24h) or set limits.exec_timeout")
		return exitTimedOut
	case st.Signal != "":
		if st.Signal == "SIGKILL" {
			fmt.Fprintln(env.stderr, "tkbox: the process was killed (SIGKILL); if the box ran out of memory, raise --memory (writes outside /workspace use memory too)")
		}
		if n, ok := signalNumber(st.Signal); ok {
			return 128 + n
		}
		return 128 + 9
	case st.Code < 0 || st.Code > 255:
		return exitTkbox
	}
	return st.Code
}

func cmdLs(ctx context.Context, args []string, env *cliEnv) error {
	fs, sock := newFlags("ls", env)
	jsonOut := fs.Bool("json", false, "print JSON")
	if _, err := parseAll(fs, args); err != nil {
		return err
	}
	var boxes []api.Box
	if err := newClient(*sock).do(ctx, "GET", "/v1/boxes", nil, &boxes); err != nil {
		return err
	}
	if *jsonOut {
		return json.NewEncoder(env.stdout).Encode(boxes)
	}
	tw := tabwriter.NewWriter(env.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tSTATE\tIMAGE\tAGE\tEXECS\tRUN")
	unrecorded := false
	var problems []string
	for _, b := range boxes {
		run := b.RunID
		if b.Unrecorded {
			run, unrecorded = "UNRECORDED", true
		}
		state := b.State
		if b.Error != "" {
			problems = append(problems, fmt.Sprintf("%s %s: %s", b.Name, b.State, b.Error))
		} else if b.StopReason != "" && b.State == api.StateStopped {
			state += " (" + b.StopReason + ")"
		}
		if b.DiffError != "" && !alive(b.State) {
			problems = append(problems, fmt.Sprintf("%s: %s", b.Name, b.DiffError))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", b.ID, b.Name, state, b.Image,
			time.Since(b.CreatedAt).Round(time.Second), b.Execs, run)
	}
	tw.Flush()
	for _, p := range problems {
		fmt.Fprintf(env.stderr, "tkbox: %s\n", printable(env.stderr, p))
	}
	if unrecorded {
		fmt.Fprintln(env.stderr, "tkbox: WARNING: boxes marked UNRECORDED record nothing in Tracekit")
	}
	return nil
}

func alive(state string) bool {
	switch state {
	case api.StateCreating, api.StateRunning, api.StatePaused, api.StateStopping:
		return true
	}
	return false
}

func oneBox(name string, pos []string) (string, error) {
	if len(pos) != 1 {
		return "", usagef("name one box: tkbox %s <box>", name)
	}
	return pos[0], nil
}

func cmdStop(ctx context.Context, args []string, env *cliEnv) error {
	fs, sock := newFlags("stop", env)
	kill := fs.Bool("kill", false, "kill the VM now (no clean shutdown, no diff saved)")
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	box, err := oneBox("stop", pos)
	if err != nil {
		return err
	}
	var b api.Box
	if err := newClient(*sock).do(ctx, "POST", boxPath(box, "/stop"), api.StopRequest{Kill: *kill}, &b); err != nil {
		return err
	}
	fmt.Fprintf(env.stderr, "tkbox: box %s %s (%s)\n", b.Name, b.State, b.StopReason)
	switch {
	case b.DiffSaved:
		fmt.Fprintf(env.stderr, "tkbox: see its changes with `tkbox diff %s`; apply them with `tkbox apply %s` before `tkbox export %s -o %s.tkb`\n",
			b.Name, b.Name, b.Name, b.Name)
	case b.DiffError != "" && !*kill:
		fmt.Fprintf(env.stderr, "tkbox: WARNING: %s\n", printable(env.stderr, b.DiffError))
		fmt.Fprintln(env.stderr, "tkbox: WARNING: nothing can be applied from this box")
	case b.DiffError != "":
		fmt.Fprintf(env.stderr, "tkbox: %s\n", printable(env.stderr, b.DiffError))
	}
	return nil
}

func cmdRm(ctx context.Context, args []string, env *cliEnv) error {
	fs, sock := newFlags("rm", env)
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	box, err := oneBox("rm", pos)
	if err != nil {
		return err
	}
	if err := newClient(*sock).do(ctx, "DELETE", boxPath(box, ""), nil, nil); err != nil {
		return err
	}
	fmt.Fprintf(env.stderr, "tkbox: removed %s\n", box)
	return nil
}

func cmdDiff(ctx context.Context, args []string, env *cliEnv) error {
	fs, sock := newFlags("diff", env)
	stat := fs.Bool("stat", false, "list changed files only")
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	box, err := oneBox("diff", pos)
	if err != nil {
		return err
	}
	patch, sum, err := newClient(*sock).diff(ctx, box)
	if err != nil {
		return err
	}
	if *stat {
		for _, f := range sum.Files {
			fmt.Fprintf(env.stdout, "%-9s %s\n", f.Status, printable(env.stdout, f.Path))
		}
		return nil
	}
	io.WriteString(env.stdout, printable(env.stdout, string(patch)))
	fmt.Fprintf(env.stderr, "tkbox: %s changed\n", plural(len(sum.Files), "file"))
	return nil
}

func cmdApply(ctx context.Context, args []string, env *cliEnv) error {
	fs, sock := newFlags("apply", env)
	dir := fs.String("dir", "", "checkout to apply to (default the box's workspace)")
	check := fs.Bool("check", false, "validate and decide only; write nothing")
	sensitive := fs.Bool("allow-sensitive", false, "let the patch change .gitignore, .gitattributes, .gitmodules, tkbox.yaml, .husky/, .github/workflows/, .envrc, .pre-commit-config.yaml")
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	box, err := oneBox("apply", pos)
	if err != nil {
		return err
	}
	req := api.ApplyRequest{Check: *check, AllowSensitive: *sensitive}
	if *dir != "" {
		if req.Dir, err = filepath.Abs(*dir); err != nil {
			return err
		}
	}
	c := newClient(*sock)
	// the signer may ask a person about a file: show its approval while the apply waits
	seen := len(c.events(ctx, box))
	wctx, stopWatch := context.WithCancel(ctx)
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		for {
			select {
			case <-wctx.Done():
				return
			case <-time.After(time.Second):
			}
			evs := c.events(wctx, box)
			for _, e := range evs[min(seen, len(evs)):] {
				if e.Kind == api.EventApproval && e.Door == "apply" {
					fmt.Fprintf(env.stderr, "tkbox: %s\n", printable(env.stderr, e.Summary))
				}
			}
			seen = max(seen, len(evs))
		}
	}()
	var res api.ApplyResult
	err = c.do(ctx, "POST", boxPath(box, "/apply"), req, &res)
	stopWatch()
	<-watched
	if err != nil {
		return err
	}
	if len(res.Ignored) > 0 {
		fmt.Fprintf(env.stderr, "tkbox: left out %s the checkout ignores (.gitignore): %s\n", plural(len(res.Ignored), "new file"),
			printable(env.stderr, strings.Join(res.Ignored, ", ")))
	}
	if len(res.Denied) > 0 {
		for _, p := range res.Denied {
			fmt.Fprintf(env.stderr, "tkbox: denied by the signer: %s\n", printable(env.stderr, p))
		}
		return &api.ErrorDetail{Code: api.CodeDenied, Message: fmt.Sprintf("%s refused, so nothing was applied", plural(len(res.Denied), "file")),
			Hint: "apply the rest by hand from " + res.Patch + ", or change the signer's policy"}
	}
	verb := "applied"
	if res.Checked {
		verb = "would apply (check only, nothing written)"
	}
	for _, p := range res.Applied {
		fmt.Fprintf(env.stdout, "%s\n", printable(env.stdout, p))
	}
	if len(res.Sensitive) > 0 {
		fmt.Fprintf(env.stderr, "tkbox: sensitive files (they steer the next run or host automation): %s\n", printable(env.stderr, strings.Join(res.Sensitive, ", ")))
	}
	fmt.Fprintf(env.stderr, "tkbox: %s %s\n", verb, plural(len(res.Applied), "file"))
	return nil
}

func cmdEvents(ctx context.Context, args []string, env *cliEnv) error {
	fs, sock := newFlags("events", env)
	follow := fs.Bool("f", false, "keep printing new events while the box is alive")
	jsonOut := fs.Bool("json", false, "print the raw NDJSON lines")
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	box, err := oneBox("events", pos)
	if err != nil {
		return err
	}
	path := boxPath(box, "/events")
	if *follow {
		path += "?follow=1"
	}
	c := newClient(*sock)
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://tkbox"+path, nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		var dd *daemonDown
		if errors.As(err, &dd) {
			return dd
		}
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeError(resp)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Bytes()
		var e api.Event
		if *jsonOut || json.Unmarshal(line, &e) != nil {
			fmt.Fprintf(env.stdout, "%s\n", printable(env.stdout, string(line)))
			continue
		}
		door := e.Door
		if door == "" {
			door = "-"
		}
		fmt.Fprintf(env.stdout, "%s  %-9s %-16s %s\n", e.Time.Local().Format("15:04:05"), door, e.Kind, printable(env.stdout, e.Summary))
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func cmdExport(ctx context.Context, args []string, env *cliEnv) error {
	fs, sock := newFlags("export", env)
	out := fs.String("o", "", "bundle path (FILE.tkb)")
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	box, err := oneBox("export", pos)
	if err != nil {
		return err
	}
	if *out == "" {
		return usagef("pass -o FILE.tkb")
	}
	abs, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	var res api.ExportResult
	if err := newClient(*sock).do(ctx, "POST", boxPath(box, "/export"), api.ExportRequest{Out: abs}, &res); err != nil {
		return err
	}
	fmt.Fprintf(env.stdout, "bundle: %s\ntrust:  %s\nverify: %s\n", res.Bundle, res.Trust, res.Verify)
	return nil
}

func cmdImage(ctx context.Context, args []string, env *cliEnv) error {
	if len(args) == 0 || args[0] != "build" {
		return usagef("usage: tkbox image build <ref>")
	}
	fs, sock := newFlags("image build", env)
	pos, err := parseAll(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: tkbox image build <ref>")
	}
	var img api.Image
	if err := newClient(*sock).do(ctx, "POST", "/v1/images", api.ImageBuildRequest{Ref: pos[0]}, &img); err != nil {
		return err
	}
	fmt.Fprintf(env.stdout, "%s %s %s (%d bytes) %s\n", img.Ref, img.Digest, img.Arch, img.Size, img.Path)
	return nil
}

func cmdApprovals(ctx context.Context, args []string, env *cliEnv) error {
	fs, sock := newFlags("approvals", env)
	jsonOut := fs.Bool("json", false, "print JSON")
	if _, err := parseAll(fs, args); err != nil {
		return err
	}
	var list []api.Approval
	if err := newClient(*sock).do(ctx, "GET", "/v1/approvals", nil, &list); err != nil {
		return err
	}
	if *jsonOut {
		return json.NewEncoder(env.stdout).Encode(list)
	}
	if len(list) == 0 {
		fmt.Fprintln(env.stderr, "tkbox: nothing is waiting for approval")
		return nil
	}
	tw := tabwriter.NewWriter(env.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tBOX\tKIND\tTARGET\tEXPIRES IN")
	for _, a := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", a.ID, a.BoxName, a.Kind, a.Target, time.Until(a.ExpiresAt).Round(time.Second))
	}
	tw.Flush()
	fmt.Fprintln(env.stderr, "tkbox: answer with `tkbox approve <id>` (add --box to allow the host for the rest of the box) or `tkbox reject <id>`")
	return nil
}

func cmdDecide(ctx context.Context, args []string, env *cliEnv, decision string) error {
	fs, sock := newFlags(decision, env)
	forBox := false
	if decision == "approve" {
		fs.BoolVar(&forBox, "box", false, "approve the host for the rest of the box, not just this connection")
	}
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: tkbox %s <approval id>", decision)
	}
	dec := api.ApprovalDecision{Decision: decision}
	if forBox {
		dec.Scope = "box"
	}
	var a api.Approval
	if err := newClient(*sock).do(ctx, "POST", "/v1/approvals/"+pos[0], dec, &a); err != nil {
		return err
	}
	fmt.Fprintf(env.stderr, "tkbox: %s %s (%s on box %s)\n", a.State, a.ID, a.Target, a.BoxName)
	return nil
}
