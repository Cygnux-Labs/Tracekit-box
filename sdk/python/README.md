# tracekit-box (Python)

A Python client of the Tracekit Box daemon (`tkbox daemon`). It speaks the daemon's HTTP API over its Unix socket:
create a box, run commands in it, read its changes, apply them and export the signed `.tkb` bundle. Standard library
only, Python 3.9 or newer. It talks to a daemon on the same machine; it does not start VMs itself.

```sh
pip install tracekit-box
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

c.stop("demo")
print(c.diff("demo").files)
print(c.apply("demo", check=True))       # decide every file, write nothing
print(c.export("demo", "demo.tkb"))      # {"bundle": ..., "trust": ..., "verify": "tracekit verify ..."}
```

## API

| Method | Route |
|---|---|
| `health()` | `GET /v1/health` |
| `create_box(image, *, name, allow, secrets, env, workspace, limits, inspect, agent, task)` (alias `run`) | `POST /v1/boxes` |
| `list_boxes()`, `get_box(box)` | `GET /v1/boxes`, `GET /v1/boxes/{box}` |
| `exec(box, argv, stdin=None, env=None, cwd=None, timeout=None, *, on_output=None, on_event=None)` | `POST /v1/boxes/{box}/exec`, upgraded to `tkbox-exec/1` |
| `stop(box, *, kill=False, reason=None)`, `rm(box)` | `POST …/stop`, `DELETE /v1/boxes/{box}` |
| `diff(box)` | `GET …/diff` → `Diff(patch, summary)` |
| `apply(box, *, dir=None, check=False)` | `POST …/apply` |
| `export(box, out)` | `POST …/export` |
| `events(box, *, follow=False)` | `GET …/events` (a generator of dicts) |
| `approvals()`, `approve(id, *, scope="once")`, `reject(id)` | `GET /v1/approvals`, `POST /v1/approvals/{id}` |
| `build_image(ref)` | `POST /v1/images` |

Boxes, approvals and results are returned as plain dicts with the field names of the daemon API
([`internal/api/api.go`](../../internal/api/api.go)).

`exec` returns an `ExecResult` (`exit_code`, `stdout`, `stderr`, `signal`, `timed_out`, `notices`, `events`,
`duration_ms`, `truncated`) whatever the exit code. `notices` are messages the daemon wants a person to see, such as an
egress refusal or an approval to give with `tkbox approve <id>`. The exec stream has no client-side timeout: the daemon
enforces the exec timeout (default 30 minutes) and approval waits.

## Errors

Every error is a `TkboxError` with `code`, `message`, `rule_ids`, `hint` and `status`:

| Exception | Code | When |
|---|---|---|
| `Denied` | `denied` | the signer or a person refused the command or action; `rule_ids` names the rules |
| `Unavailable` | `unavailable` | the Tracekit signer can't be reached, so Box refused (fail closed) |
| `LimitError` | `limit`, `too_large`, `busy` | a limit was hit; `hint` says what to do ([limits](../../docs/limits.md)) |
| `NotFound`, `Conflict`, `BadRequest`, `Forbidden`, `TimedOut`, `NotSupported` | as named | |
| `DaemonUnreachable` | | no daemon at the socket: start `tkbox daemon` or set `TKBOX_SOCKET` |
| `ProtocolError` | | the daemon answered something this client does not understand |

An error that ends an exec stream also carries the `stdout`, `stderr` and `events` that arrived before it.

## Tests

```sh
cd sdk/python && python3 -m pytest -q
```

The tests run against a fake daemon (`tests/fake_daemon.py`) that speaks the same HTTP, upgrade and frames over a Unix
socket, so they need no Linux host, KVM or signer.
