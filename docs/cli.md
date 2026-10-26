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
daemon at the socket, every command says ``no tkbox daemon answering at <socket> (…): start one with `tkbox daemon`, or
pass --socket``.

## tkbox daemon

```
tkbox daemon [--state-dir DIR] [--signer SOCKET] [--unrecorded] [--max-boxes N] [--approval-timeout DUR]
             [--egress-block CIDR]... [--tracekit-bin PATH] [--firecracker FILE] [--kernel FILE] [--guest-dir DIR]
```

| Flag | Default | Meaning |
|---|---|---|
| `--state-dir` | `/var/lib/tkbox` as root, else `$XDG_STATE_HOME/tkbox` or `~/.local/state/tkbox` | Images, boxes and the API socket (`run/tkbox.sock`) |
| `--signer` | discovered like Tracekit's SDK: a signer named in the root-owned `/etc/tracekit/client.json` wins (a different `$TRACEKIT_SIGNER` or `--signer` is then refused); without one, `$TRACEKIT_SIGNER`, then the same-user dev signer | The Tracekit signer's Unix socket. The signer must be on this host |
| `--unrecorded` | off | Run boxes without a signer. Nothing is recorded or decided by a signer and boxes cannot be exported; the allowlist and Box approvals still apply. Box warns at start and on every box. For debugging Box only |
| `--max-boxes` | 8 | Boxes alive at once (1 to 1024). Stopped boxes do not count |
| `--approval-timeout` | `2m` | How long a connection to a host off the allowlist waits for `tkbox approve` (1s to 4m) |
| `--egress-block` | none | Repeatable or comma-separated. A range (`203.0.113.0/24`) or a bare address (`203.0.113.7`, taken as a single address) that boxes never connect to, on top of the built-in private and metadata ranges and this host's own interface addresses; a connection there is refused with `it resolves to an address of this host or one the operator blocked, which Box never connects to`. An IPv6 range that spans the IPv4-mapped range `::ffff:0:0/96` (such as `::/0`) blocks the IPv4 addresses it covers there too, since Box connects to `::ffff:a.b.c.d` as `a.b.c.d`. On a cloud VM (EC2, GCE, Azure, GitHub-hosted runners) the host's public IP is NAT'd and on no interface, so Box can't see it and does not block it unless you pass it here (`--egress-block 203.0.113.7`); otherwise a box allowed to reach that IP could reach services the host listens on. A bad value exits 2: `--egress-block "x": want a CIDR like 203.0.113.7/32 or an address` |
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
(a second daemon fails with `another tkbox daemon is already listening on …`) and connects to the signer, still before
any download: if no signer answers it exits with `tkbox: the daemon needs a Tracekit signer: no signer answering at …`
and ``start one with `tracekit up`, or pass --unrecorded to run boxes that record nothing``. Only then does it download
Firecracker and the kernel into `<state dir>/images/assets` if they are not cached yet, check Firecracker and check the
guest agent. It logs to stderr with the prefix `tkbox:`, ending with `tkbox <version> serving on <socket> (state <dir>,
max 8 boxes)`. A bad flag value that the flag parser itself checks (`--max-boxes`, `--approval-timeout`,
`--egress-block`, an unknown flag) exits 2; a bad file (`--upstream-ca` with no PEM, a missing `--firecracker` or
`--guest-dir`) is an error and exits 1.

On SIGINT or SIGTERM it logs `stopping every box…` and stops every box cleanly, saving each box's patch, and closes
every open Tracekit run (including those of boxes already stopped and waiting for `tkbox apply`) so that each can still
be exported. Each box's stop has its own bounds (about 5 s for its commands, up to 60 s for its patch, then the run's
close), and the boxes stop in parallel; only the final wait is bounded at 60 seconds, so a shutdown can take longer
than that. Boxes that a previous daemon left running are marked failed (`daemon restarted`).

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
for a dev session. A dedicated user does not own your checkouts, so git refuses them ("dubious ownership") unless they
are in `safe.directory` in that user's global git config or the system one (`git config --global --add
safe.directory /path/to/checkout`, run as that user): Box reads those values (never a repository's own) and passes
them to its contained git. Without that, a box can't be built from the checkout, and apply into it is refused.

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
`tkbox_NAME_…`; a value that holds a secret's real value is refused, `env TOKEN holds the value of secret GH`, and so is
a command, cwd or up-front stdin that holds one: `the command, its cwd or its stdin holds the value of secret GH`) and
`stdin`, true when the exec has stdin of either kind below. A first word that contains `=` or is a shell reserved word
(`if`, `then`, `for`, `do`, …) is recorded quoted (`'X=1' echo hi`), so the signer's shell parser sees the program
that runs, not an assignment or a keyword. A first word starting with `%` is refused (`a program name may not start
with %: a shell reads it as a job spec, so the record could not name the program`): bash runs `%1`, quoted or not, as
`fg %1`; run such a program by path (`./%1`). With `--env`, the command line starts with `env K=V …` (sorted), as if the
command had been typed with them, so the signer's own env rules see them too:
`tkbox exec b --env DEBIAN_FRONTEND=noninteractive -- apt-get install -y curl` is decided as
`env DEBIAN_FRONTEND=noninteractive apt-get install -y curl`.

Stdin comes in one of two kinds:

- **Known before the start.** The API's `stdin_data` (at most 1 MiB, base64 in the JSON request) is decided with the
  command as `stdin_sha256` and `stdin_bytes`, plus `stdin_text` when it is UTF-8 of at most 4 KiB (a secret's
  placeholder shown as `tkbox_NAME_…`, its value as `[secret NAME]`), and exactly that data is the process's stdin.
  MCP's `tkbox_exec` sends its `stdin` this way, and so does the SDK for bytes or str of at most 1 MiB. `stdin_text`
  is signed verbatim: a credential that is not a Box secret (a password for `docker login --password-stdin`) is in
  the record for good. Stream credentials instead (`-i`; a file object in the SDK), so only their digest is recorded.
- **Streamed** (`-i`; in the SDK, larger input and file objects). It can't be known before the start, so the exec's
  completion record has its `stdin_sha256` and `stdin_bytes`: what the process was given, whether it exits, fails, is
  stopped with the box or loses its client.

`stdin_data` over 1 MiB is refused (`stdin_data is 1100000 bytes, over the 1 MiB limit`, or for a body too large to
read, `the exec request is too large: the command is too long to record (over 1 MiB) or stdin_data is over 1 MiB`), and
so is a request with both kinds at once (`stdin and stdin_data are both set`). The box's own `--env` is not repeated
per exec; it is recorded once, when the box is created. Commands that the command itself starts inside the box are not
decided one by one. Box prints approvals to give, egress refusals and other notices on stderr as `tkbox: …` lines.

| Flag | Meaning |
|---|---|
| `-i` | Send this terminal's stdin to the command (there is no TTY). The daemon holds up to 4 MiB the process has not read yet (the guest 1 MiB more, while the process keeps reading). A process that does not take its stdin fast enough is never handed a false end of input: it is killed, and `tkbox exec` prints `tkbox: stdin was not consumed fast enough (N bytes dropped); the command was stopped: write large input to a file in /workspace and read it from there` and exits 125 |
| `--timeout` | This exec's time limit, 1s to 24h (default: the box's exec timeout, 30m) |
| `--env` | Repeatable `K=V` for this exec only, decided as a leading `env K=V …` on the command line. Variables that change what runs are refused (`env LD_PRELOAD can't be set per command`): every name starting `LD_`, `DYLD_`, `GIT_`, `XDG_`, `PYTHON`, `PERL`, `RUBY`, `NODE_`, `JAVA_`, `JDK_`, `_JAVA_`, `LUA_`, `BASH_` or `NPM_CONFIG_` (a few harmless ones such as `GIT_AUTHOR_NAME`, `NODE_ENV` and `PYTHONUNBUFFERED` excepted), and `PATH`, `HOME`, `SHELLOPTS`, `PS4`, `CLASSPATH`, `MAKEFILES`, `GOFLAGS`, `RUSTC_WRAPPER`, `CC`, `EDITOR`, `PAGER` and the rest listed in [limits](limits.md), as are the proxy and CA variables Box sets. Plain settings such as `DEBIAN_FRONTEND` or `PIP_ROOT_USER_ACTION` are fine. A value that holds a secret's real value is refused too (`env TOKEN holds the value of secret GH`): use the secret's placeholder |
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
stopped box prints its state again. A box's egress closes the moment any stop starts (`tkbox stop`, the box timeout,
a fail-closed stop, the events log's hard cap, containment): the egress proxy with its open connections and sessions
and the vsock egress listener are closed, and every egress decision from then on is refused (`the box is going down,
so nothing more leaves it`), so no secret is swapped in while the commands end and the patch is saved (the patch comes
over the guest channel, not the network).

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
patch saved at stop. The file list is built on the host from the patch itself, not taken from the guest, and is
served as JSON at `GET /v1/boxes/{box}/diff/summary`, which `--stat` reads. The diff response carries it in the
`X-Tkbox-Diff-Summary` header only when that JSON is at most 8 KiB; otherwise it sends
`X-Tkbox-Diff-Summary-Omitted: 1`, and clients (`tkbox diff`, the SDK's `diff()`, MCP's `tkbox_diff`) fetch the
endpoint, so a patch with very many or very long paths still reviews. Every summary names the sha256 of the patch it
was built from (`patch_sha256`), and the diff response names its body's in `X-Tkbox-Diff-Sha256`: on a running box
the endpoint is a second guest diff, so when the two differ the client reads both once more, and then fails with
`the workspace changed while the diff was read; run it again` (stop the box to read the patch saved at stop).
`--stat` reads only the endpoint, whose list is of one diff. Generated directories (`node_modules`, `__pycache__`,
`.venv`, `venv`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.gradle`, `.next`, `.cache`, at any depth) are left out of
the patch; that fixed list is all the guest leaves out. Files the workspace's `.gitignore` ignores that the agent
created (build output such as `dist/`) are in the patch and count toward its 64 MiB; only `tkbox apply` leaves such new
files out.

When stdout is a terminal, control characters (escape sequences, carriage returns, C1 controls) and Unicode bidi
overrides in the patch are printed as escapes (`\x1b`, `\u202e`), so a patch cannot redraw what you review. Redirected
to a file, the patch is written as is. A stopped box with no saved patch says why: `box demo (stopped) has no saved
diff: <reason>` (see [limits.md](limits.md#commands-approvals-and-changes)).

## tkbox apply

```
tkbox apply <box> [--dir DIR] [--check] [--allow-sensitive]
```

Applies a stopped box's saved patch to the host checkout (default: the box's `--workspace`). It works only on a
stopped box, from the patch saved at stop, while the box's Tracekit run is open: after `tkbox stop` and before
`tkbox export` or `tkbox rm`, and not on a box from before a daemon restart. (A box that ran `--unrecorded` on an
unrecorded daemon has no run: it applies, with no decisions, even after a restart.) On a running box it is refused (`box demo
is running`, hint ``stop the box first so the patch can't change under you: `tkbox stop demo` ``). A daemon that has a
signer refuses the patch of a box that ran `--unrecorded`, since its files would be written with no `Write` decisions:
`box demo ran unrecorded, so this recording daemon can't decide or record its writes; apply the saved patch by hand
after review: <state dir>/boxes/<id>/diff.patch`.

`git apply` never runs on the checkout. Box checks the patch, has the signer decide every file, and then writes the
files itself:

- Every path is validated (relative, no `..`, no `.git` in any case or spelling a file system reads as `.git`, inside
  `DIR`, no writes through symlinks). Copy and rename sections are refused, and so is a section whose old and new names
  differ without a rename header (`git apply` would delete the old file), and a patch with more than one section for
  a path (`the patch has more than one section for "l"`). Every path the patch touches, old and new, is decided.
- The patch is parsed strictly: anything git could read as a header outside a git file section is refused, and a
  `GIT binary patch` section is read exactly as git reads it: a `literal N` or `delta N` line, base85 lines whose
  length character matches their length, a terminating empty line, and at most one more (reverse) hunk. Anything else
  in it refuses the patch.
- Changes to files the checkout's `.gitignore` ignores are refused (ignored files never reach the box). New files the
  checkout ignores are left out of the apply and listed: `tkbox: left out 2 new files the checkout ignores
  (.gitignore): …`. When the box's workspace was a git work tree and `DIR` is not one (or git fails there), the apply
  is refused: what `DIR` ignores can't be checked.
- Writes inside the checkout's git dir or hooks dir are refused. The hooks dir is the one git itself would use:
  `core.hooksPath` as the repo's, global and system config set it, passed to `git rev-parse --git-path hooks`. It is
  compared without regard to case and by file identity. When `DIR` is in a git repository but git can't say where
  those dirs are (it refuses the repository, for example for its owner), the apply is refused: `… is in a git
  repository, but git can't say where its git and hooks dirs are (…), so writes into them can't be refused`.
- Changes to `.gitignore`, `.gitattributes`, `.gitmodules`, `tkbox.yaml`, `tkbox.yml`, `.envrc`,
  `.pre-commit-config.yaml`, `.gitlab-ci.yml`, `.yarnrc.yml` and `lefthook.yml` (in any directory), to
  `.vscode/tasks.json` and `.cargo/config.toml`, to anything under `.husky/`, `.github/workflows/`, `.github/actions/`,
  `.circleci/` or `.devcontainer/`, and to credential files (`.npmrc`, `.netrc`, `.pypirc`, `*.pem`, `*.key`, … the
  files a workspace never copies into a box, see [limits.md](limits.md#behaviour)) steer the next run or host
  automation. They are refused unless you pass `--allow-sensitive`, and listed after a successful apply.
- Two applies of the same box run one after the other.
- Git must read the patch as Box does. On the filtered patch (without the left-out new files), with an empty git dir
  and an empty work tree, `git apply --numstat -z` and `git apply --summary -z` must report the same paths in the same
  order, the same binary flags and the same creations, deletions and modes as Box's parser. Any difference, or anything
  git writes on stderr, refuses the patch: `git reads the patch differently than tkbox does, so it is refused: …`.
- The result is built in a scratch copy of the files the patch touches, outside the checkout, by `git apply --binary`
  with a fresh, empty bare git dir, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_ATTR_NOSYSTEM=1`,
  `HOME` and `XDG_CONFIG_HOME` pointed at an empty dir and `core.attributesFile=/dev/null` (no filter drivers, hooks,
  LFS or attribute conversions such as `eol=crlf`). A patch that does not apply there is refused: `the patch does not
  apply to <dir>: …`.
- The signer decides every file as a `Write` with the arguments `{file_path, sha256, mode, symlink, deleted,
  patch_sha256}` (plus `sensitive: true` for the files above) before anything is written. If the signer denies any
  file, nothing is applied and the denied paths are listed (`tkbox: denied by the signer: <path>`). If the signer holds
  a file for approval, `tkbox apply` prints the approval to give.
- Before anything is written, each path in the scratch copy is checked again against what the signer decided
  (sha256, mode, symlink, deleted), and the checkout must be unchanged since the decisions; otherwise nothing is
  written (`the patched 2 files differ from what was decided: …`, `the checkout changed while the patch was
  decided: …`).
- Only then does Box write the files, deletions first: each file goes to a temp file in its own directory (opened
  `O_EXCL|O_NOFOLLOW`), gets its mode and is renamed over the target; a symlink is made under a temp name and renamed;
  every parent is checked with lstat just before the write and may not be a symlink; a deletion removes only a file or
  a symlink. Once every file is decided this runs to the end even if the client goes away. Each file is written
  atomically, but the apply as a whole is not: a failure part way is not rolled back. The files written before it
  stay, and the error names exactly which they are (`writing the patched files failed after writing 1 file: a.txt:
  …`), as do the run's `Write` completions (`written_paths`).
- Afterwards every written file is checked against what the signer decided; a file that differs is reported
  (`applied, but … differ from what was decided: …`).

Every git command Box runs in the real checkout (apply's `rev-parse` and `check-ignore`, the work-tree check when a
box is created, and the workspace builder's `ls-files`) runs so that no program the checkout's config names can run:

- every `GIT_*` variable of the daemon's environment removed, and `GIT_PAGER=cat`, `PAGER=cat`,
  `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1` and `GIT_ATTR_NOSYSTEM=1` set;
- `--no-pager` and
  `-c core.fsmonitor=false -c core.pager=cat -c diff.external= -c core.untrackedCache=false`, plus
  `-c core.hooksPath=/dev/null` where hooks don't matter;
- the settings they need from outside the checkout passed back with `-c`: `core.excludesFile` and `core.hooksPath`
  (as git resolves them from the system, global and checkout config) and every `safe.directory` value of the system
  and global config.

Those settings are read first by `git config -z --get-all` (with `--type=path` for the two paths), which runs no
program. These reads are the only git commands that see the system and global config: they drop the daemon's `GIT_*`
variables and set the same `-c` and pager settings, but not `GIT_CONFIG_GLOBAL` or `GIT_CONFIG_NOSYSTEM`. The
workspace build and apply read `core.excludesFile` the same way, so a file ignored through the system's excludes file
is ignored by both.

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
in the signer before any connection uses it, and one that cannot be recorded allows nothing. Who answered is recorded
as the peer uid of the API socket (`uid:<n>`), not a verified person: the daemon accepts its own uid and root, so any
process running as the daemon's user (an agent with a shell, say) can approve and is recorded the same way. Keep
agents off that uid (see [tkbox mcp](#tkbox-mcp)).

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
| `tkbox_run` | Create a box and return its id (it takes no `name` and no `task`) |
| `tkbox_exec` | Run a command in a box this session created (decided by the signer first) and return its exit code and output (64 KiB of each stream). Its `stdin` is sent as `stdin_data`, so the signer decides it with the command (at most 1 MiB; see [tkbox exec](#tkbox-exec)) |
| `tkbox_diff` | Show the workspace changes of a box this session created, as a git patch (up to 256 KiB) |
| `tkbox_stop` | Stop a box this session created (its patch is saved first unless `kill` is set) |
| `tkbox_ls` | List the boxes this session created |

`tkbox_exec`, `tkbox_diff`, `tkbox_stop` and `tkbox_ls` reach only the boxes this `tkbox mcp` process created with
`tkbox_run`: a `box` argument (id or name) is resolved through those boxes to the owned box's id, and every other box
on the daemon (another job's, one a person started, a later box that reused a name) is refused (`box demo was not
created by this tkbox mcp session: it may only use the boxes its tkbox_run created`) and not listed, so an MCP client
can't use another box's allowlist, secrets or workspace, or kill it. A second key that spells `box` in another case
(`"BOX"`) is refused (`argument "BOX": use "box"`), so it can't decide which box is used.

When the session ends (the client closes `tkbox mcp`'s stdin, or `tkbox mcp` gets SIGTERM or SIGINT, even with stdin
still open), `tkbox mcp` stops every box the session created, since no later session can reach them: their patches are
saved and their Tracekit runs stay open, so the operator can still `tkbox apply` and `tkbox export` them. A
`tkbox mcp` killed outright (SIGKILL, a crash) can't: its boxes run until their timeout.

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
- `task`: refused (`tkbox_run takes no task: …`). The box records the config's `task` (the operator's), the only task
  recorded as trusted; what the orchestrator asks of the agent goes in its commands, which are decided one by one.
- `name`: refused (`tkbox_run takes no name: a box created over MCP is named by its id`). The box gets its id as its
  name, even when the config sets `name`.

A refused call says what it would have widened, with the hint ``an MCP client may only narrow what the operator set up
in `tkbox mcp` (--config, --image, --workspace-root); ask the operator``. Boxes made over MCP record the agent name
`mcp`. `tkbox mcp` does not read `./tkbox.yaml` on its own. There are no MCP tools for apply or export: a person does
those with the CLI.

The narrowing holds only if the MCP client has no other way to act as the daemon's user. The daemon's API accepts any
process of its own uid (and root): an orchestrator that also has a shell as that user can call the API directly,
create boxes with any allowlist, or run `tkbox approve` on the approval ids `tkbox_exec` shows it, and such an approval
is recorded as `uid:<n>` like a person's. Run the orchestrator as another user, start `tkbox mcp` as the daemon's user
through a rule that allows exactly that command (a sudoers entry for `tkbox mcp --config …`, say), and keep the people
who approve off the orchestrator's uid.

## tkbox version

```
tkbox version
```

Prints `tkbox <version> (api v1, <Go version>, <os>/<arch>)`. Also `tkbox --version`.
