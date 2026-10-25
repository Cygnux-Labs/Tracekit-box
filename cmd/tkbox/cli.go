package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/config"
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
	jsonOut := fs.Bool("json", false, "print the box as JSON")
	pos, err := parseAll(fs, args)
	if err != nil {
		return api.CreateBoxRequest{}, "", false, err
	}
	if len(pos) > 0 {
		return api.CreateBoxRequest{}, "", false, usagef("unexpected argument %q (flags only; the command goes to `tkbox exec`)", pos[0])
	}
	var file *config.File
	path := *cfgPath
	if path == "" {
		if _, err := os.Stat(config.DefaultFile); err == nil {
			path = config.DefaultFile
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
	fmt.Fprintf(env.stderr, "tkbox: creating a box from %s…\n", req.Image)
	var b api.Box
	if err := newClient(sock).do(ctx, "POST", "/v1/boxes", req, &b); err != nil {
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

// Linux signal numbers (the guest is Linux) for exit codes 128+n.
var signalNumbers = map[string]int{"SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGILL": 4, "SIGTRAP": 5, "SIGABRT": 6,
	"SIGBUS": 7, "SIGFPE": 8, "SIGKILL": 9, "SIGUSR1": 10, "SIGSEGV": 11, "SIGUSR2": 12, "SIGPIPE": 13, "SIGALRM": 14,
	"SIGTERM": 15}

func cmdExec(args []string, env *cliEnv) int {
	fs, sock := newFlags("exec", env)
	interactive := fs.Bool("i", false, "forward stdin")
	timeout := fs.Duration("timeout", 0, "per-command timeout (default the box's exec timeout)")
	cwd := fs.String("cwd", "", "working dir in the box (default /workspace)")
	var envs stringList
	fs.Var(&envs, "env", "KEY=VALUE (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(env.stderr, "tkbox exec: name the box: tkbox exec <box> -- <command>")
		return 2
	}
	box := rest[0]
	if err := fs.Parse(rest[1:]); err != nil {
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fmt.Fprintln(env.stderr, "tkbox exec: no command: tkbox exec <box> -- <command> [args...]")
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
		for s := range sigc {
			switch s {
			case os.Interrupt:
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
			fmt.Fprintf(env.stderr, "tkbox: %s\n", ev.Message)
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
	return execExitCode(st.Code, st.Signal, st.TimedOut, err, env)
}

// execExitCode maps an exec outcome to tkbox exec's exit code: the process's own, 128+n when a signal killed it,
// 124 timed out, 126 denied, 125 a tkbox error.
func execExitCode(code int, sig string, timedOut bool, err error, env *cliEnv) int {
	if err != nil {
		printErr(env.stderr, err)
		var ae *api.ErrorDetail
		if errors.As(err, &ae) {
			switch ae.Code {
			case api.CodeDenied:
				return exitDenied
			case api.CodeTimeout:
				return exitTimedOut
			}
		}
		return exitTkbox
	}
	switch {
	case timedOut:
		fmt.Fprintln(env.stderr, "tkbox: the command timed out and was killed")
		return exitTimedOut
	case sig != "":
		if n, ok := signalNumbers[sig]; ok {
			return 128 + n
		}
		return 128 + 9
	case code < 0 || code > 255:
		return exitTkbox
	}
	return code
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
	for _, b := range boxes {
		run := b.RunID
		if b.Unrecorded {
			run, unrecorded = "UNRECORDED", true
		}
		state := b.State
		if b.Error != "" {
			state += ": " + b.Error
		} else if b.StopReason != "" && b.State == api.StateStopped {
			state += " (" + b.StopReason + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", b.ID, b.Name, state, b.Image,
			time.Since(b.CreatedAt).Round(time.Second), b.Execs, run)
	}
	tw.Flush()
	if unrecorded {
		fmt.Fprintln(env.stderr, "tkbox: WARNING: boxes marked UNRECORDED record nothing in Tracekit")
	}
	return nil
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
	if !*kill {
		fmt.Fprintf(env.stderr, "tkbox: see its changes with `tkbox diff %s`; apply them with `tkbox apply %s`\n", b.Name, b.Name)
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
			fmt.Fprintf(env.stdout, "%-9s %s\n", f.Status, f.Path)
		}
		return nil
	}
	env.stdout.Write(patch)
	fmt.Fprintf(env.stderr, "tkbox: %d files changed\n", len(sum.Files))
	return nil
}

func cmdApply(ctx context.Context, args []string, env *cliEnv) error {
	fs, sock := newFlags("apply", env)
	dir := fs.String("dir", "", "checkout to apply to (default the box's workspace)")
	check := fs.Bool("check", false, "validate and decide only; write nothing")
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	box, err := oneBox("apply", pos)
	if err != nil {
		return err
	}
	req := api.ApplyRequest{Check: *check}
	if *dir != "" {
		if req.Dir, err = filepath.Abs(*dir); err != nil {
			return err
		}
	}
	var res api.ApplyResult
	if err := newClient(*sock).do(ctx, "POST", boxPath(box, "/apply"), req, &res); err != nil {
		return err
	}
	if len(res.Denied) > 0 {
		for _, p := range res.Denied {
			fmt.Fprintf(env.stderr, "tkbox: denied by the signer: %s\n", p)
		}
		return &api.ErrorDetail{Code: api.CodeDenied, Message: fmt.Sprintf("%d files were refused, so nothing was applied", len(res.Denied)),
			Hint: "apply the rest by hand from " + res.Patch + ", or change the signer's policy"}
	}
	verb := "applied"
	if res.Checked {
		verb = "would apply (check only, nothing written)"
	}
	for _, p := range res.Applied {
		fmt.Fprintf(env.stdout, "%s\n", p)
	}
	fmt.Fprintf(env.stderr, "tkbox: %s %d files\n", verb, len(res.Applied))
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
