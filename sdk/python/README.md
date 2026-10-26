# tracekit-box (Python)

A Python client of the Tracekit Box daemon (`tkbox daemon`). It speaks the daemon's HTTP API over its Unix socket:
create a box, run commands in it, read its changes, apply them and export the signed `.tkb` bundle. Standard library
only, Python 3.9 or newer. It talks to a daemon on the same machine; it does not start VMs itself.

```sh
pip install ./sdk/python        # from a checkout of this repository (the package name is tracekit-box)
```

```python
import os
from tracekit_box import Client, Secret, Limits, Denied

c = Client()  # $TKBOX_SOCKET, else <state dir>/run/tkbox.sock
c.create_box(
    "python:3.12-slim",
    name="demo",
    allow=["pypi"],
    workspace=".",
    secrets={"GH": Secret(os.environ["GH_TOKEN"], ["api.github.com"], "Authorization")},
    limits=Limits(cpus=2, memory_mib=2048, timeout="1h"),
)

r = c.exec("demo", ["python", "-c", "print(1+1)"])
print(r.exit_code, r.stdout_text)        # 0 2

try:
    c.exec("demo", ["rm", "-rf", "/workspace"])
except Denied as e:
    print("refused:", e.rule_ids)

c.stop("demo")                           # saves the patch; the run stays open for apply
print(c.diff("demo").files)
print(c.apply("demo", check=True))       # decide every file, write nothing
print(c.apply("demo"))                   # {"applied": [...], "sha256": ..., "ignored": [...], ...}
print(c.export("demo", "demo.tkb"))      # closes the run: {"bundle": ..., "trust": ".../demo.trust.json", ...}
```

Order matters: `apply` works only on a stopped box, from the patch saved at stop, and only before `export`, which
closes the box's Tracekit run (`Conflict` otherwise). `stop(kill=True)` saves no patch. Commands you run with `exec`
are decided by the signer and recorded; the processes they start inside the box are not recorded one by one.

A secret is bound to exact host names (no wildcards, no ports) and is swapped into one header, `Authorization` when
`header` is empty.

`apply` writes every file the signer allows, or nothing. A patch that changes files which steer the next run or host
automation (`.gitignore`, `.gitattributes`, `.gitmodules`, `tkbox.yaml`, `tkbox.yml`, `.envrc`,
`.pre-commit-config.yaml`, anything under `.husky/` or `.github/workflows/`) is refused with `BadRequest` unless you
pass `allow_sensitive=True` after reading those changes. The result is the daemon's `ApplyResult`: `applied`, `denied`,
`patch`, `checked`, `sensitive` (the applied paths of that kind), `ignored` (new files the checkout's `.gitignore`
ignores, left out) and `sha256` (of the patch that was decided).

## API

| Method | Route |
|---|---|
| `health()` | `GET /v1/health` |
| `create_box(image, *, name, allow, secrets, env, workspace, limits, inspect, agent, task)` (alias `run`) | `POST /v1/boxes` |
| `list_boxes()`, `get_box(box)` | `GET /v1/boxes`, `GET /v1/boxes/{box}` |
| `exec(box, argv, stdin=None, env=None, cwd=None, timeout=None, *, on_output=None, on_event=None)` | `POST /v1/boxes/{box}/exec`, upgraded to `tkbox-exec/1` |
| `stop(box, *, kill=False, reason=None)`, `rm(box)` | `POST …/stop`, `DELETE /v1/boxes/{box}` |
| `diff(box)` | `GET …/diff` → `Diff(patch, summary)`; the summary comes from the `X-Tkbox-Diff-Summary` header when it is at most 8 KiB, else from `GET …/diff/summary` |
| `diff_summary(box)` | `GET …/diff/summary` → the summary (`files`, `bytes`) without the patch |
| `apply(box, *, dir=None, check=False, allow_sensitive=False)` | `POST …/apply` |
| `export(box, out)` | `POST …/export` |
| `events(box, *, follow=False)` | `GET …/events` (a generator of dicts) |
| `approvals()`, `approve(id, *, scope="once")`, `reject(id)` | `GET /v1/approvals`, `POST /v1/approvals/{id}` |
| `build_image(ref)` | `POST /v1/images` |

Boxes, approvals and results are returned as plain dicts with the field names of the daemon API
([`internal/api/api.go`](../../internal/api/api.go)).

`exec` returns an `ExecResult` (`exit_code`, `stdout`, `stderr`, `signal`, `timed_out`, `notices`, `events`,
`duration_ms`, `truncated`, `stdin_truncated`, `stdin_dropped_bytes`) whatever the exit code. `exit_code` is the raw
status: the process's code, or -1 with `signal` set when a signal killed it (`timed_out` too when the exec timeout
did); `tkbox exec` maps the same outcomes to 128+n and 124. `notices` are messages the daemon wants a person to see,
such as an egress refusal or an approval to give with `tkbox approve <id>`.

`stdin` as bytes or str of at most 1 MiB is sent in the request (`stdin_data`): the signer decides it with the command
(its sha256 and size, and the text itself when it is UTF-8 of at most 4 KiB), and exactly that data is the process's
stdin. Larger input and file objects are streamed, and the sha256 and size of what the process was given are recorded
with the outcome instead; the daemon holds at most 4 MiB the process has not read yet, and past that stops the process
rather than hand it a false end of input (`stdin_truncated`, and `ok` is false). A per-command `env` may not set
`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `PATH`, `NODE_OPTIONS`,
`PYTHONPATH`, `PERL5OPT`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `GCONV_PATH`, `GIT_CONFIG` or any `GIT_CONFIG_*` name, and no
value may hold a secret's value (`BadRequest`). The exec stream has no client-side timeout: the daemon enforces the exec timeout
(default 30 minutes, 1s to 24h) and approval waits. Closing the connection (for example on `KeyboardInterrupt`) cancels
the command if it has not started and stops it if it has.

## Errors

Every error is a `TkboxError` with `code`, `message`, `rule_ids`, `hint` and `status`:

| Exception | Code | When |
|---|---|---|
| `Denied` | `denied` | the signer or a person refused the command or action; `rule_ids` names the rules |
| `Unavailable` | `unavailable` | the Tracekit signer can't be reached, so Box refused (fail closed) |
| `LimitError` | `limit`, `too_large`, `busy` | a limit was hit; `hint` says what to do ([limits](../../docs/limits.md)) |
| `Cancelled` | `cancelled` | the command was cancelled before it started (nothing ran), or the client went away while it ran |
| `Conflict` | `conflict` | the name is taken or the box is in the wrong state: `apply` on a running box or after `export`, a box that stopped before or while the command ran, `export` of a run a crashed daemon left open |
| `NotFound` | `not_found` | no such box or approval; from `exec`, the executable does not exist in the box |
| `BadRequest`, `Forbidden`, `TimedOut`, `NotSupported` | as named | |
| `DaemonUnreachable` | | no daemon at the socket: start `tkbox daemon` or set `TKBOX_SOCKET` |
| `ProtocolError` | | the daemon answered something this client does not understand |

An error that ends an exec stream also carries the `stdout`, `stderr` and `events` that arrived before it.

## Tests

```sh
cd sdk/python && python3 -m pytest -q
```

The tests run against a fake daemon (`tests/fake_daemon.py`) that speaks the same HTTP, upgrade and frames over a Unix
socket, so they need no Linux host, KVM or signer.
