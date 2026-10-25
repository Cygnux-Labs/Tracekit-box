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
| `tkbox run` | Create and start a box |
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

At start the daemon claims its socket (a second daemon on the same state dir fails with `another tkbox daemon is
already listening on …`), downloads Firecracker and the kernel into `<state dir>/images/assets` if they are not cached
yet, checks `/dev/kvm` and the guest agent, and connects to the signer. If no signer answers it exits: `no Tracekit
signer answering at …: start one with `tracekit up`, or pass --unrecorded to run boxes that record nothing`. It logs to
stderr with the prefix `tkbox:`, ending with `tkbox <version> serving on <socket> (state <dir>, max 8 boxes)`.

On SIGINT or SIGTERM it logs `stopping every box…` and stops every box cleanly within 60 seconds, saving each box's
patch and closing its Tracekit run so that it can still be exported. Boxes that a previous daemon left running are
marked failed (`daemon restarted`). After a restart, `tkbox diff` and `tkbox export` still work on stopped boxes, but
`tkbox apply` refuses them, because their runs are closed: review the saved patch (`<state dir>/boxes/<id>/diff.patch`)
and apply it by hand. Run the daemon in the foreground under systemd as a
dedicated user, or in the background for a dev session.

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
| `--secret` | Repeatable. `NAME=env:VAR@host1,host2[#Header]` or `NAME=file:PATH@hosts[#Header]`. The box sees a placeholder in `$NAME`; the value goes only to the hosts (exact names, no ports), in the header (default `Authorization`) |
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

`tkbox run` reads `./tkbox.yaml` when it exists and `--config` is not given (and says so); `--config FILE` reads another
file; `--no-config` reads none. The per-exec timeout (`exec_timeout`, default 30m) can be set only in the file.

It prints `tkbox: creating a box from <image>…`, and once the VM has booted and the guest agent answers, the box id on
stdout and on stderr the box's name, state, Tracekit run and expiry, its allowed egress, and the next command to run.
The first run of an image pulls it and builds its rootfs, which can take a minute; later runs reuse it by digest.

## tkbox exec

```
tkbox exec <box> [-i] [--timeout DUR] [--env K=V]... [--cwd DIR] [--] argv...
```

Runs `argv` in the box (as root, in `/workspace` unless `--cwd` says otherwise) and streams its output. `argv` is passed
as is, with no shell: use `sh -c '…'` for pipes and variables. `--` is needed only when the command starts with `-`.

The signer decides the command before it starts, as a `Bash` decision that records the command line, the working
directory, the exec's environment (placeholders redacted) and whether stdin was given. Commands that the command
itself starts inside the box are not decided one by one. Box prints decisions, approvals to give and egress refusals on
stderr as `tkbox: …` lines.

| Flag | Meaning |
|---|---|
| `-i` | Send this terminal's stdin to the command (there is no TTY) |
| `--timeout` | This exec's time limit (default: the box's exec timeout, 30m; at most 24h) |
| `--env` | Repeatable `K=V` for this exec only. `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `ENV` and `PROMPT_COMMAND` are refused |
| `--cwd` | The working directory in the box (default `/workspace`) |

SIGINT, SIGTERM, SIGHUP and SIGQUIT are passed to the command in the box. A third Ctrl-C gives up waiting: `tkbox exec`
exits 130 and the command may still run in the box (`tkbox stop` stops the box).

Exit codes:

| Code | Meaning |
|---|---|
| the process's | The command ran; its own exit code |
| 128 + n | The command was killed by signal n (137 for SIGKILL, for example after running out of memory) |
| 124 | The command timed out and was killed |
| 125 | tkbox error: no daemon, no such box, the box is not running or stopped during the command, a limit, the signer unavailable |
| 126 | The signer or a person denied the command, or its approval expired; it did not run |
| 127 | The executable was not found in the box |
| 2 | Usage error |
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

Saves the box's workspace patch, shuts the VM down cleanly (the guest syncs and unmounts) and keeps the box's state, and
says whether the patch was saved. The Tracekit run stays open, so `tkbox apply` can still record its file decisions;
`tkbox export` closes it. `--kill` kills the VM at once: no patch is saved, so there is nothing to apply. Stopping a
stopped box prints its state again.

## tkbox rm

```
tkbox rm <box>
```

Stops a running box, closes its Tracekit run, then deletes its state (disks, logs, the saved patch). Export the bundle
first if you need it; the record itself stays in the signer.

## tkbox diff

```
tkbox diff <box> [--stat]
```

Prints a git-format patch of what changed under `/workspace` (added, modified, deleted, mode changes, symlinks, binary
files) and `tkbox: N files changed` on stderr. `--stat` lists the changed files only, one `status path` line each. On a
running box the guest computes it from the workspace overlay, so the image needs no git; on a stopped box it is the
patch saved at stop. Paths that the workspace's `.gitignore` ignores and generated directories (`node_modules`,
`__pycache__`, `.venv`, `venv`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.gradle`, `.next`, `.cache`) are left out.

## tkbox apply

```
tkbox apply <box> [--dir DIR] [--check] [--allow-sensitive]
```

Applies a stopped box's saved patch to the host checkout (default: the box's `--workspace`). It works only after
`tkbox stop` and before `tkbox export`, and not on a box from before a daemon restart.

- Every path is validated (relative, no `..`, inside `DIR`, no writes through symlinks). Copy and rename sections are
  refused.
- Changes to `.gitignore`, `.gitattributes`, `.gitmodules`, `tkbox.yaml`, `.husky/**` and `.github/workflows/**` are
  refused unless you pass `--allow-sensitive`.
- The signer decides every file as a `Write` (with the patch's digest and the file's content hash, mode and whether it
  is a symlink) before anything is written. If the signer denies any file, nothing is applied and the denied paths are
  listed (`tkbox: denied by the signer: <path>`).
- `git apply` runs without the host's or the checkout's git config, so no filters, hooks or LFS run.

`--check` validates and decides only, and writes nothing. It prints the paths written and `tkbox: applied N files`.

## tkbox export

```
tkbox export <box> -o FILE.tkb
```

Closes the box's Tracekit run, waits until the run is final in the signer, then writes the bundle (`tracekit export
--v2`) and the signer's trust file next to it: `run.tkb` gets `run.trust.json`. The box must be stopped, the output
directory must exist, and an unrecorded box cannot be exported. After export, `tkbox apply` is refused. It prints:

```
bundle: /path/run.tkb
trust:  /path/run.trust.json
verify: tracekit verify /path/run.tkb --trust /path/run.trust.json
```

## tkbox events

```
tkbox events <box> [-f]
```

Prints the box's events, one JSON object per line, as kept in `<state dir>/boxes/<id>/events.ndjson`: lifecycle,
decisions, connections and refusals, approvals, secret use and leaks, model calls. `-f` keeps printing new events until
the box stops. Events Box must keep (secret use and leaks, approvals, containment, lifecycle) are never dropped: if Box
cannot record one, it stops the box. The file is capped at 64 MiB, and bursts of egress refusals are summarised.

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
ids like `apr-…` and targets like `https://example.com:443`. A box can have at most 16 pending approvals. `approve` lets
that one connection through; `--box` approves the host for the rest of the box's life. Each answer is recorded as
`tkbox.approval` with who answered.

Commands that the signer's own policy holds are answered on the signer: `tracekit approvals approve <id>`. The exec's
`tkbox:` line says which one to use.

## tkbox mcp

```
tkbox mcp [--config FILE] [--workspace-root DIR]
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

`--config FILE` is the operator's [tkbox.yaml](config.md): every `tkbox_run` starts from its image, allowlist, secrets
and limits. A `tkbox_run` call can only narrow those settings: it cannot add allowlist entries, set environment
variables or secrets, and it can use a workspace only under `--workspace-root DIR`. `tkbox mcp` does not read
`./tkbox.yaml` on its own. There are no MCP tools for apply or export: a person does those with the CLI.

## tkbox version

```
tkbox version
```

Prints `tkbox <version> (api v1, <Go version>, <os>/<arch>)`. Also `tkbox --version`.
