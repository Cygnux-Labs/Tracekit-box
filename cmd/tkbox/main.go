// Command tkbox is the host binary of Tracekit Box: the daemon (`tkbox daemon`), the CLI that talks to it over its
// Unix socket, and an MCP server (`tkbox mcp`).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
)

// version is set at build time (-X main.version=…).
var version = "dev"

// Exit codes of tkbox exec (and every other command on a tkbox error).
const (
	exitTkbox    = 125 // tkbox, the daemon or the signer failed
	exitDenied   = 126 // the signer or a person refused the command
	exitTimedOut = 124
	exitNotFound = 127 // the command's executable is not in the box
)

const usage = `tkbox: run AI agent jobs in Firecracker micro-VMs, every door decided and signed by Tracekit.

Usage:
  tkbox daemon [flags]                     run the box manager (Linux with /dev/kvm)
  tkbox run --image IMG [flags]            create a box; prints its id
  tkbox exec <box> [-i] [--timeout D] [--env K=V] [--cwd DIR] -- CMD [ARGS...]
  tkbox ls                                 list boxes
  tkbox stop [--kill] <box>                stop a box (its diff is saved first)
  tkbox rm <box>                           stop and delete a box
  tkbox diff <box> [--stat]                print the box's workspace patch
  tkbox apply <box> [--dir DIR] [--check] [--allow-sensitive]
                                           apply the saved patch of a stopped box (every file decided first)
  tkbox export <box> -o FILE.tkb           write the box's Tracekit bundle
  tkbox events <box> [-f]                  print what happened at each door (events.ndjson)
  tkbox image build <ref>                  pull and build an image ahead of time
  tkbox approvals                          list egress waiting for a person
  tkbox approve <id> [--box]               allow it (once, or for the rest of the box)
  tkbox reject <id>                        refuse it
  tkbox mcp                                MCP server on stdio (tools: tkbox_run, tkbox_exec, tkbox_diff, tkbox_stop, tkbox_ls)
  tkbox version

Every command takes --socket (default $TKBOX_SOCKET, else <state dir>/run/tkbox.sock).
`

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func runMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	env := &cliEnv{stdin: stdin, stdout: stdout, stderr: stderr}
	var err error
	switch cmd {
	case "daemon":
		stop() // the daemon handles its own signals
		err = cmdDaemon(rest, env)
	case "run":
		err = cmdRun(ctx, rest, env)
	case "exec":
		stop() // signals are forwarded to the process in the box
		return cmdExec(rest, env)
	case "ls", "list":
		err = cmdLs(ctx, rest, env)
	case "stop":
		err = cmdStop(ctx, rest, env)
	case "rm":
		err = cmdRm(ctx, rest, env)
	case "diff":
		err = cmdDiff(ctx, rest, env)
	case "apply":
		err = cmdApply(ctx, rest, env)
	case "export":
		err = cmdExport(ctx, rest, env)
	case "events":
		err = cmdEvents(ctx, rest, env)
	case "image":
		err = cmdImage(ctx, rest, env)
	case "approvals":
		err = cmdApprovals(ctx, rest, env)
	case "approve":
		err = cmdDecide(ctx, rest, env, "approve")
	case "reject":
		err = cmdDecide(ctx, rest, env, "reject")
	case "mcp":
		err = cmdMCP(ctx, rest, env)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "tkbox %s (api %s, %s, %s/%s)\n", version, api.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "tkbox: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintf(stderr, "tkbox %s: %s\n", cmd, ue.msg)
			return 2
		}
		var fe flagError
		if errors.As(err, &fe) {
			return 2 // the flag package already said what is wrong
		}
		printErr(stderr, err)
		return 1
	}
	return 0
}

// flagError is a flag the flag package refused (it printed why and the usage): exit 2.
type flagError struct{ err error }

func (e flagError) Error() string { return e.err.Error() }

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// printErr prints an error with its rule ids (once) and what to do next.
func printErr(w io.Writer, err error) {
	var ae *api.ErrorDetail
	if errors.As(err, &ae) {
		fmt.Fprintf(w, "tkbox: %s", ae.Message)
		if len(ae.RuleIDs) > 0 && !strings.Contains(ae.Message, ae.RuleIDs[0]) {
			fmt.Fprintf(w, " [%s]", strings.Join(ae.RuleIDs, ", "))
		}
		fmt.Fprintln(w)
		if ae.Hint != "" {
			fmt.Fprintf(w, "tkbox: %s\n", ae.Hint)
		}
		return
	}
	fmt.Fprintf(w, "tkbox: %v\n", err)
}

// plural is "1 file" / "2 files".
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// isTerminal reports whether w is a terminal (a character device): text from the box is then cleaned of control
// characters before it is printed, so a patch can't rewrite what the reviewer sees.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// sanitize shows terminal control characters (ESC, C1 controls, CR, …) as escapes; newlines and tabs stay.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(&b, "\\x%02x", r)
		case r == '‪' || r == '‫' || r == '‬' || r == '‭' || r == '‮' || (r >= '⁦' && r <= '⁩'):
			fmt.Fprintf(&b, "\\u%04x", r) // bidi overrides reorder what the reviewer reads
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// printable is s cleaned for w: as is unless w is a terminal.
func printable(w io.Writer, s string) string {
	if isTerminal(w) {
		return sanitize(s)
	}
	return s
}

type cliEnv struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// defaultStateDir is /var/lib/tkbox as root, else $XDG_STATE_HOME/tkbox (default ~/.local/state/tkbox).
func defaultStateDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/tkbox"
	}
	if x := os.Getenv("XDG_STATE_HOME"); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, "tkbox")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "tkbox-"+fmt.Sprint(os.Getuid()))
	}
	return filepath.Join(home, ".local", "state", "tkbox")
}

// defaultSocket is --socket's default: $TKBOX_SOCKET, else the default state dir's run/tkbox.sock.
func defaultSocket() string {
	if s := os.Getenv("TKBOX_SOCKET"); s != "" {
		return s
	}
	return filepath.Join(defaultStateDir(), "run", "tkbox.sock")
}

// newFlags makes a subcommand's FlagSet with --socket.
func newFlags(name string, env *cliEnv) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("tkbox "+name, flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	sock := fs.String("socket", defaultSocket(), "daemon API socket")
	return fs, sock
}

// parseAll parses flags placed before, between or after positional args and returns the positionals.
func parseAll(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, flagError{err}
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// stringList is a repeatable flag; values may also be comma-separated when split is set.
type stringList struct {
	vals  []string
	split bool
}

func (s *stringList) String() string { return strings.Join(s.vals, ",") }

func (s *stringList) Set(v string) error {
	if !s.split {
		s.vals = append(s.vals, v)
		return nil
	}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			s.vals = append(s.vals, p)
		}
	}
	return nil
}

// parseEnvList turns K=V flags into a map.
func parseEnvList(vals []string) (map[string]string, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	m := map[string]string{}
	for _, kv := range vals {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, usagef("--env %q: want KEY=VALUE", kv)
		}
		m[k] = v
	}
	return m, nil
}
