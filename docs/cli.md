# tkbox command line

`tkbox` is one binary: the daemon, the CLI that talks to it, and an MCP server. Every command except `tkbox daemon`
and `tkbox version` talks to a running daemon over its Unix socket, which every command takes as `--socket PATH`:

- default `$TKBOX_SOCKET` if set, else `<state dir>/run/tkbox.sock`;
- the state dir is `/var/lib/tkbox` as root, else `$XDG_STATE_HOME/tkbox` (when that is an absolute path), else
  `~/.local/state/tkbox`.

The daemon accepts connections only from its own uid or root. Boxes are named by id (`tkb-…`) or by `--name`. Flags
may come before or after a command's arguments; `-flag` and `--flag` are the same.

## Summary

| Command | What it does |
|---|---|
| `tkbox daemon` | Run the daemon (boxes, egress proxies, the API socket) |
| `tkbox run` | Check the settings, then create and start a box |
| `tkbox exec <box> -- argv…` | Run a command in a box |
| `tkbox ls` | List boxes |
| `tkbox stop <box>` | Stop a box and save its patch |
| `tkbox rm <box>` | Delete a box (stopping it first) |
| `tkbox diff <box>` | Print the box's workspace changes as a git-format patch |
| `tkbox apply <box>` | Apply a stopped box's patch to the host checkout, file by file through the signer |
| `tkbox export <box> -o x.tkb` | Close the box's Tracekit run and write its signed bundle and trust file |
| `tkbox events <box>` | Print the box's events |
| `tkbox image build <ref>` | Pull an image and build its rootfs ahead of time |
| `tkbox approvals` | List pending Box approvals |
| `tkbox approve <id>` / `tkbox reject <id>` | Answer one |
| `tkbox mcp` | Serve boxes as MCP tools on stdio |
| `tkbox version` | Print the version |

## Exit codes

`tkbox exec` passes the command's own exit code through; see [tkbox exec](#tkbox-exec). Every other command exits 0 on
success, 1 on an error (the daemon's message, and a hint on a second `tkbox:` line) and 2 on a usage error. With no
daemon at the socket, every command says `no tkbox daemon answering at <socket> (…): start one with `tkbox daemon` (as
root on a server), or pass --socket`.

## tkbox daemon

```
tkbox daemon [--state-dir DIR] [--signer SOCKET] [--unrecorded] [--max-boxes N] [--approval-timeout DUR]
             [--tracekit-bin PATH] [--firecracker FILE] [--kernel FILE] [--guest-dir DIR]
```

| Flag | Default | Meaning |
|---|---|---|
| `--state-dir` | `/var/lib/tkbox` as root, else `$XDG_STATE_HOME/tkbox` or `~/.local/state/tkbox` | Images, boxes and the API socket (`run/tkbox.sock`) |
| `--signer` | discovered like Tracekit's SDK: `$TRACEKIT_SIGNER`, then `/etc/tracekit/client.json`, then the same-user dev signer | The Tracekit signer's Unix socket. The signer must be on this host |
| `--unrecorded` | off | Run boxes without a signer. Nothing is recorded or decided by a signer and boxes cannot be exported; the allowlist and Box approvals still apply. Box warns at start and on every box. For debugging Box only |
| `--max-boxes` | 8 | Boxes alive at once (1 to 1024). Stopped boxes do not count |
| `--approval-timeout` | `2m` | How long a connection to a host off the allowlist waits for `tkbox approve` (1s to 4m) |
| `--tracekit-bin` | `tracekit` on `PATH` | The `tracekit` CLI that `tkbox export` runs |
| `--firecracker` | the pinned Firecracker v1.17.0, downloaded and checked by SHA-256 | A local `firecracker` binary instead |
| `--kernel` | the pinned guest kernel 6.1.155, downloaded and checked by SHA-256 | A local `vmlinux` instead |
| `--guest-dir` | the directory of the `tkbox` binary | Where `tkbox-guest-linux-<arch>` is |

Two more flags exist for Box's own end-to-end tests and must not be used anywhere else: `--egress-allow-private CIDR`
lets boxes reach a private range, and `--upstream-ca FILE` replaces the system roots for upstream TLS. Each logs a
warning.

The daemon listens on `--socket` when it is given, else on `<state dir>/run/tkbox.sock`.

At start the daemon first checks `/dev/kvm`, before it downloads anything (`this host can't run boxes: /dev/kvm is not
usable (…): enable KVM (nested virtualization on a VM) and add this user to the kvm group`). Then it claims its socket
(a second daemon fails with `another tkbox daemon is already listening on …`), downloads Firecracker and the kernel into
`<state dir>/images/assets` if they are not cached yet, checks the guest agent, and connects to the signer. If no
signer answers it exits with `tkbox: the daemon needs a Tracekit signer: no signer answering at …` and ``start one with
`tracekit up`, or pass --unrecorded to run boxes that record nothing``. It logs to stderr with the prefix `tkbox:`,
ending with `tkbox <version> serving on <socket> (state <dir>, max 8 boxes)`. A bad flag value exits 2.

On SIGINT or SIGTERM it logs `stopping every box…` and stops every box cleanly within 60 seconds, saving each box's
patch, and closes every open Tracekit run (including those of boxes already stopped and waiting for `tkbox apply`) so
that each can still be exported. Boxes that a previous daemon left running are marked failed (`daemon restarted`).

The run token that lets the daemon record into and close a box's run lives only in the daemon's memory; it is never
written to disk. So after a restart:

- After a clean shutdown (SIGINT or SIGTERM), `tkbox diff` and `tkbox export` still work on stopped boxes, but
  `tkbox apply` refuses them, because their runs are closed.
- After a crash or `kill -9`, the runs of that daemon's boxes stay open in the signer and no daemon can close them:
  `tkbox export` refuses those boxes at once (`… was left open: the daemon that held its token stopped without closing
  it (it crashed or was killed), and a restarted daemon can't close it`), and `tkbox apply` refuses them too. Start a
  new box for a bundle.

In both cases you can still review the saved patch (`<state dir>/boxes/<id>/diff.patch`) and apply it by hand. Run the
daemon in the foreground under systemd as a dedicated user (stopped with SIGTERM, never SIGKILL), or in the background
for a dev session.

## tkbox run

```
tkbox run --image REF [--name NAME] [--workspace DIR] [--allow ENTRY]... [--secret SPEC]... [--env K=V]...
          [--cpus N] [--memory SIZE] [--disk SIZE] [--timeout DUR] [--inspect bound|all] [--task TEXT]
          [--agent NAME] [--config FILE | --no-config] [--json]
```

| Flag | Meaning |
|---|---|
| `--image` | OCI image reference (`python:3.12-slim`, `node:22-slim`, `ghcr.io/org/img:tag`) |
| `--name` | A unique name (default: the box id). Lower-case letters, digits and `-`, at most 63 characters |
| `--workspace` | A host directory copied into `/workspace` (default: none, `/workspace` is empty). See [config.md](config.md#keys) for what is copied |
| `--allow` | Repeatable or comma-separated. Presets `github`, `pypi`, `npm`, `anthropic`, `openai`, `claude-code`, `apt-ubuntu`, `debian`, `go-proxy`, or hosts (`api.example.com`, `*.example.com`, `host:8443`); see [config.md](config.md#allow-entries) |
| `--secret` | Repeatable. `NAME=env:VAR@host1,host2[#Header]` or `NAME=file:PATH@hosts[#Header]`. The box sees a placeholder in `$NAME`; the value goes only to the hosts (exact names: no ports, no wildcards), only in the one header (default `Authorization`) |
| `--env` | Repeatable `K=V`, plain environment for every exec |
| `--cpus` | vCPUs, 1 to 32 (default 2) |
| `--memory` | Memory with a unit, such as `4GiB` or `512MiB` (default 2GiB, 128MiB to 64GiB) |
| `--disk` | Space for writes to `/workspace`, with a unit, such as `16GiB` (default 4GiB, 64MiB to 1TiB) |
| `--timeout` | Box lifetime as a duration, such as `90m` or `2h` (default `1h`, 10s to 168h) |
| `--inspect` | `bound` (default) or `all`; see [config.md](config.md#keys) |
| `--task` | The task, recorded in the run as trusted content (at most 64 KiB) |
| `--agent` | The agent's name recorded in the run (default `tkbox`) |
| `--config` | Read settings from this [tkbox.yaml](config.md); flags override it |
| `--no-config` | Read no `tkbox.yaml` |
| `--json` | Print the box as JSON on stdout, and nothing else |

`tkbox run` reads `./tkbox.yaml` when it exists and `--config` is not given, and says so: `tkbox: reading settings from
./tkbox.yaml (pass --no-config to skip it)`. `--config FILE` reads another file; `--no-config` reads none (giving both
is a usage error). The per-exec timeout (`exec_timeout`, default 30m) can be set only in the file.

The daemon first checks the whole request (limits, allowlist, secrets, workspace) without creating anything, so a bad
value is reported before any image is pulled or VM booted. Then `tkbox run` prints `tkbox: creating a box from
<image>…`, and once the VM has booted and the guest agent answers, the box id on stdout and on stderr the box's name,
Tracekit run and expiry, its allowed egress, one line per secret saying which header it goes in (`tkbox: secret GH goes
only in the Authorization header, only to its bound hosts`), any notice (such as `<dir> is not a git work tree: copying
every file except credential files`), and the next command to run. A flag the flag parser refuses exits 2.
The first run of an image pulls it and builds its rootfs, which can take a minute; later runs reuse it by digest.

## tkbox exec

```
tkbox exec <box> [-i] [--timeout DUR] [--env K=V]... [--cwd DIR] [--] argv...
```

Runs `argv` in the box (as root, in `/workspace` unless `--cwd` says otherwise) and streams its output. `argv` is passed
as is, with no shell: use `sh -c '…'` for pipes and variables. `--` is needed only when the command starts with `-`.

The signer decides the command before it starts, as a `Bash` decision with the arguments `{command, cwd, env, stdin}`:
the shell-quoted command line, the working directory, this exec's `--env` (a secret's placeholder shown as
`tkbox_NAME_…`, a secret's real value pasted into a value shown as `[secret NAME]`) and whether stdin was given. The
box's own `--env` is not repeated per exec; it is recorded once, when the box is created. Commands that the command
itself starts inside the box are not decided one by one. Box prints approvals to give, egress refusals and other
notices on stderr as `tkbox: …` lines.

| Flag | Meaning |
|---|---|
| `-i` | Send this terminal's stdin to the command (there is no TTY). The daemon holds up to 4 MiB the process has not read yet (the guest 1 MiB more, while the process keeps reading). A process that does not take its stdin fast enough is never handed a false end of input: it is killed, and `tkbox exec` prints `tkbox: stdin was not consumed fast enough (N bytes dropped); the command was stopped: write large input to a file in /workspace and read it from there` and exits 125 |
| `--timeout` | This exec's time limit, 1s to 24h (default: the box's exec timeout, 30m) |
| `--env` | Repeatable `K=V` for this exec only. `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `ENV` and `PROMPT_COMMAND` are refused (`env LD_PRELOAD can't be set per command`), as are the proxy and CA variables Box sets |
| `--cwd` | The working directory in the box (default `/workspace`) |

SIGINT, SIGTERM, SIGHUP and SIGQUIT are passed to the command in the box at once, whatever the command does with its
stdin. A signal that arrives before the command starts (while the signer decides or an approval waits) cancels it: the
decision is abandoned, a pending signer approval is withdrawn, and `tkbox exec` prints `tkbox: cancelled before the
command started (nothing ran)` and exits 125. A third Ctrl-C gives up waiting: `tkbox exec` exits 130 and the command
may still run in the box (`tkbox stop` stops the box). If the connection to the daemon closes, the daemon stops the
command.

Notices `tkbox exec` may print: the process was killed by SIGKILL (maybe out of memory), output past 256 MiB was
dropped, the exec timeout killed the command, the command was too long to record (over 1 MiB), the command was stopped because it did not take its stdin, an
egress connection failed or was refused (for example 502 when the host did not accept the connection), an approval to
give, expired or withdrawn, a secret blocked on its way to the wrong host. The texts are in [limits.md](limits.md).

Exit codes:

| Code | Meaning |
|---|---|
| the process's | The command ran; its own exit code (0 to 255) |
| 128 + n | The command was killed by signal n, 1 to 64 (137 for SIGKILL, for example after running out of memory; 143 for SIGTERM) |
| 124 | The command reached its exec timeout and was killed |
| 125 | tkbox error: no daemon, no such box, the box is not running or stopped during the command, a limit, the signer unavailable, the command was cancelled before it started, or it was stopped because it did not take its stdin fast enough (`-i`) |
| 126 | The signer or a person denied the command, or its approval expired; it did not run |
| 127 | The executable was not found in the box |
| 2 | Usage error (including a bad flag or a `--timeout` outside 1s..24h) |
| 130 | You gave up with a third Ctrl-C |

## tkbox ls

```
tkbox ls [--json]
```

One line per box: `ID  NAME  STATE  IMAGE  AGE  EXECS  RUN`. State is `creating`, `running`, `paused`, `stopping`,
`stopped (<reason>)` or `failed`; RUN is the Tracekit run id, or `UNRECORDED`. `--json` prints the boxes as JSON.

## tkbox stop

```
tkbox stop <box> [--kill]
```

Ends the box's running commands (SIGTERM, 3 seconds, then SIGKILL, 2 more seconds), saves the box's workspace patch,
shuts the VM down cleanly (the guest syncs and unmounts) and keeps the box's state, and says whether the patch was
saved; when it was not, it prints the reason and `tkbox: WARNING: nothing can be applied from this box`. The Tracekit run stays open, so `tkbox apply` can still record its file decisions;
`tkbox export` closes it. `--kill` kills the VM at once: no patch is saved, so there is nothing to apply. Stopping a
stopped box prints its state again.

## tkbox rm

```
tkbox rm <box>
```

Stops a running box, closes its Tracekit run, then deletes its state (disks, logs, the saved patch). Export the bundle
first if you need it; the record itself stays in the signer. While the box still has a decision in flight (an apply
waiting for approval, say) it waits up to 10 s, then refuses and deletes nothing: `box demo still has 1 call in flight
(an apply waiting for approval?); wait or answer it`.

## tkbox diff

```
tkbox diff <box> [--stat]
```

Prints a git-format patch of what changed under `/workspace` (added, modified, deleted, mode changes, symlinks, binary
files) and `tkbox: N files changed` on stderr. `--stat` lists the changed files only, one `status path` line each. On a
running box the guest computes it from the workspace overlay, so the image needs no git; on a stopped box it is the
patch saved at stop. The file list is built on the host from the patch itself, not taken from the guest. Paths that the
workspace's `.gitignore` ignores and generated directories (`node_modules`, `__pycache__`, `.venv`, `venv`, `.tox`,
`.mypy_cache`, `.pytest_cache`, `.gradle`, `.next`, `.cache`, at any depth) are left out.

When stdout is a terminal, control characters (escape sequences, carriage returns, C1 controls) and Unicode bidi
overrides in the patch are printed as escapes (`\x1b`, `‮`), so a patch cannot redraw what you review. Redirected
to a file, the patch is written as is. A stopped box with no saved patch says why: `box demo (stopped) has no saved
diff: <reason>` (see [limits.md](limits.md#commands-approvals-and-changes)).

## tkbox apply

```
tkbox apply <box> [--dir DIR] [--check] [--allow-sensitive]
```

Applies a stopped box's saved patch to the host checkout (default: the box's `--workspace`). It works only on a
stopped box, from the patch saved at stop, while the box's Tracekit run is open: after `tkbox stop` and before
`tkbox export` or `tkbox rm`, and not on a box from before a daemon restart. On a running box it is refused (`box demo
is running`, hint ``stop the box first so the patch can't change under you: `tkbox stop demo` ``).

- Every path is validated (relative, no `..`, no `.git` in any case or spelling a file system reads as `.git`, inside
  `DIR`, no writes through symlinks). Copy and rename sections are refused, and so is a section whose old and new names
  differ without a rename header (`git apply` would delete the old file). Every path `git apply` touches, old and new,
  is decided.
- Changes to files the checkout's `.gitignore` ignores are refused (ignored files never reach the box). New files the
  checkout ignores are left out of the apply and listed: `tkbox: left out 2 new files the checkout ignores
  (.gitignore): …`. When the box's workspace was a git work tree and `DIR` is not one (or git fails there), the apply
  is refused: what `DIR` ignores can't be checked.
- Writes inside the checkout's git dir or hooks dir are refused. The hooks dir is the one git itself would use
  (`git rev-parse --git-path hooks` with the repo's, global and system config, running no other program), compared
  without regard to case.
- Changes to `.gitignore`, `.gitattributes`, `.gitmodules`, `tkbox.yaml`, `tkbox.yml`, `.envrc`,
  `.pre-commit-config.yaml`, `.gitlab-ci.yml`, `.yarnrc.yml` and `lefthook.yml` (in any directory), to
  `.vscode/tasks.json` and `.cargo/config.toml`, to anything under `.husky/`, `.github/workflows/`, `.github/actions/`,
  `.circleci/` or `.devcontainer/`, and to credential files (`.npmrc`, `.netrc`, `.pypirc`, `*.pem`, `*.key`, … the
  files a workspace never copies into a box, see [limits.md](limits.md#behaviour)) steer the next run or host
  automation. They are refused unless you pass `--allow-sensitive`, and listed after a successful apply.
- Two applies of the same box run one after the other.
- The signer decides every file as a `Write` with the arguments `{file_path, sha256, mode, symlink, deleted,
  patch_sha256}` (plus `sensitive: true` for the files above) before anything is written. If the signer denies any
  file, nothing is applied and the denied paths are listed (`tkbox: denied by the signer: <path>`). If the signer holds
  a file for approval, `tkbox apply` prints the approval to give.
- `git apply --binary` runs with a fresh, empty bare git dir and with `GIT_CONFIG_GLOBAL=/dev/null`,
  `GIT_CONFIG_NOSYSTEM=1` and `GIT_ATTR_NOSYSTEM=1`, so neither the checkout's `.git/config` nor the host's global or
  system git config or attributes are read: no filter drivers, hooks or LFS run.
  Once every file is decided it runs to the end (at most 2 minutes) even if the client goes away. If it fails after
  writing some files, they are named (`git apply failed after writing 1 file: a.txt: …`).
- Afterwards every written file is checked against what the signer decided; a file that differs is reported
  (`applied, but … differ from what was decided: …`).

`--check` validates and decides only, and writes nothing. `tkbox apply` prints the paths written on stdout and
`tkbox: applied N files` on stderr (with `--check`, `tkbox: would apply (check only, nothing written) N files`).

## tkbox export

```
tkbox export <box> -o FILE.tkb
```

Closes the box's Tracekit run, waits until the run is final in the signer, then writes the bundle (`tracekit export
--v2`) and the signer's trust file next to it: `run.tkb` gets `run.trust.json`. The box must be stopped, the output
directory must exist, and an unrecorded box cannot be exported. After export, `tkbox apply` is refused. A box whose run
was left open by a daemon that crashed cannot be exported (see [tkbox daemon](#tkbox-daemon)). While the box still has a
decision in flight (an apply waiting for approval, say), export waits up to 10 s, then refuses without closing the run:
`box demo still has 1 call in flight (an apply waiting for approval?); wait or answer it`. It prints:

```
bundle: /path/run.tkb
trust:  /path/run.trust.json
verify: tracekit verify /path/run.tkb --trust /path/run.trust.json
```

## tkbox events

```
tkbox events <box> [-f] [--json]
```

Prints the box's events from `<state dir>/boxes/<id>/events.ndjson`, one line each: `time  door  kind  summary`
(lifecycle, decisions, connections and refusals, approvals, secret use and leaks, model calls, apply). `--json` prints
the raw NDJSON lines instead. `-f` keeps printing new events while the box is alive. On a terminal, control and bidi
characters are escaped as in `tkbox diff`. The file is capped at 64 MiB: past that one `events.capped` line is written
and egress and signer-problem lines are dropped, while lifecycle, exec, secret, approval, containment and apply lines are
still written. At 256 MiB nothing more is written (beyond the box's own stop lines) and the box is stopped with the
reason `events log over its hard cap`. This file is Box's local log; the signed record is the Tracekit run (see
[limits.md](limits.md#commands-approvals-and-changes) for what happens when a record Box must keep cannot be sent to the
signer).

## tkbox image build

```
tkbox image build <ref>
```

Pulls `ref` for the host's architecture and builds its rootfs, so a later `tkbox run` starts without the pull. Prints
the reference, digest, architecture, size and cached path.

## tkbox approvals, approve, reject

```
tkbox approvals [--json]
tkbox approve <id> [--box]
tkbox reject <id>
```

Box approvals are connections to hosts off a box's allowlist, held until a person on the host answers (2 minutes, the
daemon's `--approval-timeout`, then refused). `tkbox approvals` lists them as `ID  BOX  KIND  TARGET  EXPIRES IN`, with
ids like `apr-…` and targets like `https://example.com:443`; `--json` adds each approval's state and `waiters`, the
connections waiting on it now. A box can have at most 16 pending approvals, and may open at most 30 a minute; a
connection that would need another is refused at once. When the last connection waiting on an approval goes away, the
approval is withdrawn and dropped: it leaves the list and can no longer be approved. `approve` lets the waiting connections through; `--box` approves the host
for the rest of the box's life. Each answer is recorded as `tkbox.approval` with who answered; an approval is recorded
in the signer before any connection uses it, and one that cannot be recorded allows nothing.

Commands that the signer's own policy holds are answered on the signer: `tracekit approvals approve <id>`. The exec's
`tkbox:` line says which one to use.

## tkbox mcp

```
tkbox mcp [--config FILE] [--image REF]... [--workspace-root DIR]...
```

Serves boxes as MCP tools over stdio (JSON-RPC, one message per line), for an agent orchestrator running on the host,
not inside a box. It talks to the daemon at `--socket` like every other command.

| Tool | What it does |
|---|---|
| `tkbox_run` | Create a box and return its id |
| `tkbox_exec` | Run a command in a box (decided by the signer first) and return its exit code and output (64 KiB of each stream) |
| `tkbox_diff` | Show a box's workspace changes as a git patch (up to 256 KiB) |
| `tkbox_stop` | Stop a box (its patch is saved first unless `kill` is set) |
| `tkbox_ls` | List boxes |

`--config FILE` is the operator's [tkbox.yaml](config.md): every `tkbox_run` starts from its image, allowlist, secrets,
env and limits. A `tkbox_run` call can only narrow those settings:

- `allow`: only entries that are in the config's `allow` list (without `--config`, none); given, it replaces the
  config's list. A secret's hosts still join the allowlist, as for every box.
- `image`: the config's `image` (the default) or one passed with `--image` (repeatable). With neither, `tkbox_run` is
  refused.
- `workspace`: a directory inside a `--workspace-root DIR` (repeatable, symlinks resolved); without any
  `--workspace-root`, only the config's own `workspace`. The box gets the resolved path, the one that was checked.
- `cpus`, `memory`, `timeout`: at most the config's values; a value the config leaves unset (or no `--config`) caps
  at the daemon's default (2 cpus, 2GiB, 1h), never the maximum.
- `tkbox_exec`'s `timeout`: at most the config's `exec_timeout` (default 30m).
- `env`: refused. The box gets the config's `env` and `secrets`; a call can add to neither.

A refused call says what it would have widened, with the hint ``an MCP client may only narrow what the operator set up
in `tkbox mcp` (--config, --image, --workspace-root); ask the operator``. Boxes made over MCP record the agent name
`mcp`. `tkbox mcp` does not read `./tkbox.yaml` on its own. There are no MCP tools for apply or export: a person does
those with the CLI.

## tkbox version

```
tkbox version
```

Prints `tkbox <version> (api v1, <Go version>, <os>/<arch>)`. Also `tkbox --version`.
