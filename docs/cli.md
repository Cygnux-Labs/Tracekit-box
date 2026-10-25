# tkbox command line

`tkbox` is one binary: the daemon, the CLI that talks to it, and an MCP server. Every command except `tkbox daemon`
and `tkbox version` talks to a running daemon over its Unix socket:

- `$TKBOX_SOCKET` if set, else `<state dir>/run/tkbox.sock`;
- the state dir is `/var/lib/tkbox` as root, else `$XDG_STATE_HOME/tkbox` (default `~/.local/state/tkbox`).

The daemon accepts connections only from its own uid or root. Boxes are named by id or by `--name`.

<!-- TODO(lead): check every flag below against agent F's cmd/tkbox once it lands (`tkbox <cmd> --help`). -->

## Summary

| Command | What it does |
|---|---|
| `tkbox daemon` | Run the daemon (boxes, egress proxies, the API socket) |
| `tkbox run` | Create and start a box |
| `tkbox exec <box> -- argv…` | Run a command in a box |
| `tkbox ls` | List boxes |
| `tkbox stop <box>` | Stop a box |
| `tkbox rm <box>` | Delete a box (stopping it first) |
| `tkbox diff <box>` | Print the box's workspace changes as a git-format patch |
| `tkbox apply <box>` | Apply the box's changes to the host checkout, file by file through the signer |
| `tkbox export <box> -o x.tkb` | Write the box's signed bundle and trust file |
| `tkbox image build <ref>` | Pull an image and build its rootfs ahead of time |
| `tkbox approvals` | List pending Box approvals |
| `tkbox approve <id>` / `tkbox reject <id>` | Answer one |
| `tkbox mcp` | Serve the API as MCP tools on stdio |
| `tkbox version` | Print the version |

## tkbox daemon

```
tkbox daemon [--state-dir DIR] [--signer SOCKET] [--unrecorded]
```

| Flag | Default | Meaning |
|---|---|---|
| `--state-dir` | `/var/lib/tkbox` as root, else `$XDG_STATE_HOME/tkbox` | Images, boxes and the API socket |
| `--signer` | discovered like Tracekit's SDK: `$TRACEKIT_SIGNER`, then `/etc/tracekit/client.json`, then the same-user dev signer | The Tracekit signer's socket |
| `--unrecorded` | off | Run boxes without a signer. Nothing is recorded or decided by a signer; Box warns at start and on every box. For debugging Box only |

The daemon checks `/dev/kvm` and the signer at start. Without a signer that answers it refuses to create boxes (fail
closed); `tkbox run` then says so and how to start one. Run it in the foreground under systemd, or with `&` for a dev
session; stopping it stops its boxes.
<!-- TODO(lead): confirm "stopping the daemon stops its boxes", and list any other daemon flags (max boxes, approval timeout). -->

## tkbox run

```
tkbox run --image REF [--name NAME] [--workspace DIR] [--allow ENTRY]... [--secret SPEC]... [--env K=V]...
          [--cpus N] [--memory MIB] [--disk MIB] [--timeout DUR] [--inspect bound|all] [--task TEXT]
          [--config tkbox.yaml]
```

| Flag | Meaning |
|---|---|
| `--image` | OCI image reference (`python:3.12-slim`, `node:22-slim`, `ghcr.io/org/img:tag`) |
| `--name` | A unique name (default: the box id) |
| `--workspace` | A git work tree on the host, copied into `/workspace` |
| `--allow` | Repeatable or comma-separated. Presets `github`, `pypi`, `npm`, `anthropic`, `openai`, `apt-ubuntu`, `go-proxy`, or hosts (`api.example.com`, `*.example.com`, `host:8443`) |
| `--secret` | Repeatable. `NAME=env:VAR@host1,host2[#Header]` or `NAME=file:PATH@hosts[#Header]`. The box sees a placeholder in `$NAME`; the value goes only to the hosts, in the header if given |
| `--env` | Repeatable `K=V`, plain environment for every exec |
| `--cpus`, `--memory`, `--disk` | vCPUs, MiB, MiB (defaults 2, 2048, 4096) |
| `--timeout` | Box lifetime (default `1h`) |
| `--inspect` | `bound` (default) or `all`; see [config.md](config.md) |
| `--task` | The task, recorded in the run as trusted content |
| `--config` | Read settings from a [tkbox.yaml](config.md); flags override it |

It prints the box's id and name once the VM has booted and the guest agent answers. The first run of an image pulls it
and builds its rootfs, which can take a minute; later runs reuse it by digest.

## tkbox exec

```
tkbox exec <box> [-i] [--timeout DUR] -- argv...
```

Runs `argv` in the box (as root, in `/workspace` when the box has one) and streams its output. `argv` is passed as is,
with no shell: use `sh -c '…'` for pipes and variables. The signer decides the command before it starts; Box prints
decisions, approvals to give and egress refusals on stderr as `tkbox: …` lines.

| Flag | Meaning |
|---|---|
| `-i` | Send this terminal's stdin to the command |
| `--timeout` | This exec's time limit (default: the box's exec timeout, 30 min) |

Exit codes:

| Code | Meaning |
|---|---|
| the process's | The command ran; its own exit code (128 + n when killed by signal n) |
| 124 | The command timed out and was killed |
| 125 | tkbox error: no daemon, no such box, the box is not running, a limit, the signer unavailable |
| 126 | The signer or a person denied the command; it did not run |

<!-- TODO(lead): confirm that signer-unavailable is 125 (not 126) and that signal deaths map to 128+n. -->

## tkbox ls

```
tkbox ls
```

One line per box: id, name, state (`creating`, `running`, `paused`, `stopping`, `stopped`, `failed`), image, age, and
the Tracekit run id.

## tkbox stop

```
tkbox stop <box> [--kill]
```

Shuts the VM down cleanly (the guest syncs and unmounts), closes the Tracekit run and keeps the box's state so `diff`,
`apply` and `export` still work. `--kill` kills the VM at once instead.
<!-- TODO(lead): confirm diff/apply work after stop (the daemon saves diff.patch at stop?), since the action runs stop before apply. -->

## tkbox rm

```
tkbox rm <box>
```

Stops a running box, then deletes its state (disks, logs, the saved patch). Export the bundle first if you need it; the
record itself stays in the signer.

## tkbox diff

```
tkbox diff <box>
```

Prints a git-format patch of everything that changed under `/workspace` (added, modified, deleted, mode changes,
symlinks, binary files). It needs no git in the image: the guest compares the workspace's overlay with the original.

## tkbox apply

```
tkbox apply <box> [--dir DIR] [--check]
```

Applies the box's patch to the host checkout (default: the box's `--workspace`). Every path is validated (relative, no
`..`, inside `DIR`) and decided by the signer as a `Write` before anything is written; if the signer denies any file,
nothing is applied and the denied paths are listed. `--check` validates and decides only, and writes nothing. Prints the
paths written.

## tkbox export

```
tkbox export <box> -o run.tkb
```

Waits until the run is final in the signer, then writes the bundle (`tracekit export --v2`) and the signer's trust file
next to it, and prints the command that verifies it:

```
tracekit verify run.tkb --trust run.trust.json
```

<!-- TODO(lead): api.ExportRequest says the trust file is "<out>.trust.json" (run.tkb.trust.json); Tracekit's own `tracekit last` and this doc use run.trust.json. Pick one. -->

## tkbox image build

```
tkbox image build <ref>
```

Pulls `ref` for the host's architecture and builds its rootfs, so a later `tkbox run` starts without the pull. Prints
the digest and the cached path.

## tkbox approvals, approve, reject

```
tkbox approvals
tkbox approve <id> [--box]
tkbox reject <id>
```

Box approvals are connections to hosts off a box's allowlist, held until a person on the host answers (2 minutes, then
refused). `tkbox approvals` lists them with the box and the target (`https://example.com:443`). `approve` lets that one
connection through; `--box` approves the host for the rest of the box's life. Each answer is recorded as
`tkbox.approval` with who answered.

Commands that the signer's own policy holds are answered on the signer: `tracekit approvals approve <id>`. The exec's
`tkbox:` line says which one to use.

## tkbox mcp

```
tkbox mcp
```

Serves the daemon's API as MCP tools over stdio, for an agent orchestrator running on the host (not inside a box).
<!-- TODO(lead): list the MCP tool names once agent F lands them. -->

## tkbox version

Prints the version of `tkbox`, the guest agent it found next to itself, and the API version.
