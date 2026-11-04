# Integrating with Tracekit Box: the v1 contract

Box is a component: any program on the daemon's host can run an agent in a box and get its changes back through one
versioned contract. The CLI, the MCP server, the [Python SDK](../sdk/python/README.md) and the
[GitHub Action](../action) all use it. **new:** Tracekit's `tracekit up --isolated` is to use only this contract; it
doesn't yet. This page is that contract as a host program sees it. The types and routes are defined in code in
[`internal/api`](../internal/api/api.go), which wins where this page and the code differ.

Each part below is marked **existing** (in v1 today) or **new** (planned; the pull request that adds it updates this
page and moves the mark).

**A daemon started with `--unrecorded` decides and records nothing.** When `GET /v1/health` answers
`unrecorded: true`, or a `Box` has `unrecorded: true`, no signer decided its commands, connections or file writes and
there is no Tracekit run: the allowlist and Box approvals still apply, and nothing below about records holds. A host
program that relies on the record must refuse such a daemon or box.

## Transport and who may call

- **existing:** HTTP/1.1 with JSON bodies on the daemon's Unix socket, `<state dir>/run/tkbox.sock`, mode 0600. There
  is no TCP listener. The daemon makes the socket's directory mode 0700, including a directory named with
  `tkbox daemon --socket PATH`, so give a socket of your own a directory of its own.
- **existing:** the daemon reads the caller's uid from the socket's peer credentials once per connection and checks it
  on every request. A connection from another uid is accepted, and each of its requests is answered 403 `forbidden`;
  only the daemon's own uid and root get through. Anything running as that uid can use the whole API: the contract has no finer permissions.
- **existing:** the CLI is the same contract for scripts. `tkbox run`, `tkbox ls`, `tkbox events` and
  `tkbox approvals` take `--json` and print the API's objects. **new:** `--json` on `tkbox stop`, `tkbox apply` and
  `tkbox export`, printing `Box`, `ApplyResult` and `ExportResult`. Until then, a program that needs those results
  calls the API.

## Versioning

- **existing:** every route is under `/v1/`. `GET /v1/health` answers `api: "v1"`. Call it first: it also says whether
  this host can run boxes (`kvm`), whether the signer answered just now (`signer_ok`), and whether the daemon records
  nothing (`unrecorded`).
- **existing:** request bodies are decoded strictly: a field the daemon doesn't know is refused with `bad_request`.
  "Strict" is Go's `encoding/json` with unknown fields disallowed, so two looser points hold: keys match field names
  without regard to case (`"Image"` is read as `image`), and anything after the first JSON value in a body is not
  checked. Send the exact lower-case names and one JSON value.
- Within v1, responses may gain fields; clients ignore fields they don't know. Removing or renaming a field, or
  changing what one means, is a new version under a new path (`/v2/`), served beside v1 for at least one release.
- `api: "v1"` can't tell a client whether this daemon knows a request field added within v1: an older daemon refuses
  it with `bad_request`. **new:** `GET /v1/health` lists capabilities (for example `"capabilities": ["apply.check",
  "export.tracekit_bin"]`), so a client sends a newer field only to a daemon that names it.

## Operations

| Operation | Route | Request → response | Status |
|---|---|---|---|
| Health | `GET /v1/health` | → `Health` | existing |
| Create a box | `POST /v1/boxes` | `CreateBoxRequest` (image, allow, secrets, env, workspace, limits, inspect, agent, task; `validate_only` checks without creating) → `Box` (201) | existing |
| List, get | `GET /v1/boxes`, `GET /v1/boxes/{box}` | → `[]Box`, `Box` (`{box}` is an id or a name) | existing |
| Run a command | `POST /v1/boxes/{box}/exec` with `Upgrade: tkbox-exec/1` | `ExecRequest` → 101, then frames ([below](#the-exec-stream)) | existing |
| Stream events | `GET /v1/boxes/{box}/events` (`?follow=1` keeps it open) | → `application/x-ndjson` lines of `Event` | existing |
| Stop | `POST /v1/boxes/{box}/stop` | `StopRequest` (`kill`, `reason`) → `Box`; the patch is saved at stop (`diff_saved`, or `diff_error` says why not) | existing |
| Get the patch | `GET /v1/boxes/{box}/diff`, `GET /v1/boxes/{box}/diff/summary` | → `text/x-diff` (header `X-Tkbox-Diff-Sha256`), `DiffSummary` (`patch_sha256`) | existing |
| Apply | `POST /v1/boxes/{box}/apply` | `ApplyRequest` (`dir`, `check`, `allow_sensitive`) → `ApplyResult` (`applied`, `denied`, `sensitive`, `ignored`, `sha256`) | existing |
| Export | `POST /v1/boxes/{box}/export` | `ExportRequest` (`out`) → `ExportResult` (`bundle`, `trust`, `verify`); the daemon runs the `tracekit` CLI it was started with (`tkbox daemon --tracekit-bin PATH`, default `tracekit` on `PATH`) | existing |
| Remove | `DELETE /v1/boxes/{box}` | → 204 (a running box is stopped first) | existing |
| Box approvals | `GET /v1/approvals`, `POST /v1/approvals/{id}` | → `[]Approval`; `ApprovalDecision` → `Approval` | existing |
| Build an image | `POST /v1/images` | `ImageBuildRequest` → `Image` | existing |
| An agent's own hooks | a channel from inside the box to the signer, scoped to the box's run | design note first | **new** |

A host program's usual sequence: health → create → exec (as many as needed) → stop → diff summary → apply → export →
`tracekit verify` on the bundle with its trust file.

`apply` works only on a stopped box whose run is still open (after stop, before export or remove). It never runs
`git apply` on the checkout and runs no git hooks or filters. It refuses sensitive paths (`.github/workflows/`,
`.husky/`, `.devcontainer/`, credential files, coding agents' configs and instructions, …; the list is in
[cli.md](cli.md#tkbox-apply)) unless `allow_sensitive` is set, and nothing is written if the signer denies any file.
`check: true` writes nothing, but it is not a dry run of the record: the signer still makes a signed `Write` decision
for every file (completed as not written), and a file its policy holds waits for a person's approval, so a check can
block until someone answers.

## The exec stream

- **existing:** after 101, both directions carry frames `[type u8][length u32 big-endian][payload]`, with a payload of
  at most 1 MiB ([`internal/proto`](../internal/proto/frame.go)).
- Daemon → client: `json` `ExecEvent` (`deciding`, `waiting_approval` with `approval_id` and `approver`, `running`,
  `notice`), `stdout`, `stderr`, then exactly one of `exit` (`ExitStatus`) or `error` (`code`, `message`, `rule_ids`,
  `hint`).
- Client → daemon: `stdin`, `stdin_eof`, `signal`.
- The command is decided before it starts: a refusal is an `error` frame with code `denied` before any output.
- A command that runs past its timeout is killed and ends with an `exit` frame whose `timed_out` is true, not an error.
  The `timeout` error code is only the daemon's backstop, when the guest didn't answer by then.
- A box that stops (its lifetime ended, `tkbox stop`) sends each running command SIGTERM, then SIGKILL after a grace
  period, and the command ends with an `exit` frame naming the `signal`. Only when the VM goes first (`stop` with
  `kill`, a quarantine, a box paused by a hold) does a running command end with `conflict` ("the box stopped while the
  command ran").
- A client that goes away ends the command, before or after it started: the stream's last frame is an `error` with
  code `cancelled`. After the command started, its `complete` records that the client went away; before, it records
  `not run: cancelled before it started`, or nothing when the command was waiting on an approval that was then
  withdrawn.

## Errors

- **existing:** every non-2xx response has the body `{"error": {"code", "message", "rule_ids"?, "hint"?}}`. `hint` says
  what to do next, and `rule_ids` names the signer's rules behind a denial. Exec errors use the same codes in their
  `error` frame.

| Code | HTTP | Means |
|---|---|---|
| `bad_request` | 400 | A malformed or unknown request, an unknown field |
| `not_found` | 404 | No such box, approval or route |
| `conflict` | 409 | A name taken, or a box in the wrong state (apply on a running box) |
| `denied` | 403 | The signer or an approver refused the action |
| `forbidden` | 403 | The caller's uid may not use this daemon |
| `unavailable` | 503 | The signer can't be reached: Box fails closed |
| `limit` | 422 | A limit was hit; `message` and `hint` say which and what to do |
| `timeout` | 504 | Exec only: the daemon's backstop when the guest didn't answer within the command's timeout (a command that just runs too long ends with `exit` and `timed_out`) |
| `not_supported` | 501 | Exporting a box that ran unrecorded: there is no run to export. A host without `/dev/kvm` gets no daemon at all: it refuses to start |
| `cancelled` | — | Exec frames only: the client went away, before or after the command started |
| `internal` | 500 | A Box bug: report it |
| `too_large`, `busy`, `not_ready` | 500 | The guest agent's own codes, passed through on any route that reaches it: in an exec's `error` frame, and with HTTP 500 elsewhere (`busy`: the box runs its most commands at once; `not_ready`: the guest isn't ready; `too_large`: a request or result over the guest's limit), except a running box's diff that is too large, which is `limit` (422). The guest's `not_found` (a program the image doesn't have) and `bad_request` pass through the same way, as 404 and 400 |

## What is signed where

Each box is one Tracekit run (unless it is unrecorded, above), opened at create and closed at export, removal, daemon
shutdown, quarantine or failure, and at stop when records were lost (then nothing is left to apply). Box speaks the
signer's RPC (protocol 19, which Tracekit 1.4.2 and later serve) over the signer's Unix socket on the same host.

Observes carry a trust level. **Trusted** ones are Box's own word about what the operator asked for or what Box did:
`tkbox.box`, `tkbox.task`, `tkbox.approval`, `tkbox.contained` and `tkbox.gap`. **Untrusted** ones report what the box
did at a door, as Box saw it: `tkbox.secret.use`, `tkbox.secret.leak`, `tkbox.model.call` and `tkbox.egress` (and the
workspace an MCP client chose, as an untrusted `tkbox.box`). The records:

| Operation | Tracekit record |
|---|---|
| Create | `register_run`, then trusted observe `tkbox.box` with `event: "created"` (`box_id`, `name`, `image` as named, `allow`, `limits`, the secrets' names, `workspace`, `inspect`, the box's env, scrubbed; no image digest yet), and the task, if any, as trusted `tkbox.task` |
| Lifecycle | trusted `tkbox.box` with `event`: `started` (with `image_digest`, the image the VM booted), then `stopped` or `failed` with the reason; trusted `tkbox.contained` when the signer holds, quarantines or releases the run |
| Exec | `decide` tool `Bash` with `{command, cwd, env, stdin}` before it starts, then `complete` with the exit status |
| A connection from the box | `decide` tool `WebFetch` with `{url}`, where `url` is `scheme://host:port` with no path (`https://example.com:443`, `tcp://git.example.com:22`, `http://host:80`). One decision per CONNECT tunnel and per plain-HTTP request, not per request inside a tunnel. A Box approval is trusted `tkbox.approval`; a connection Box refused itself (an address it never connects to, an approval that expired) is untrusted `tkbox.egress` |
| Secrets | untrusted `tkbox.secret.use` and `tkbox.secret.leak` (name and host, never the value) |
| Model calls | untrusted `tkbox.model.call` (host, path, status, bytes), only for connections Box inspects (a host with a bound secret, or every host with `inspect: all`) to a host a model preset named; a model call Box doesn't inspect is only its connection's `WebFetch` |
| Apply | `decide` tool `Write` for every file before anything is written (`file_path`, `sha256`, `mode`, `symlink`, `deleted`, `patch_sha256`, `sensitive`), then `complete` with what was written; with `check: true` too, completed as not written |
| Lost records | trusted `tkbox.gap` for what couldn't be recorded; `close_run` with the reason |
| Events (`GET …/events`) | not signed: the daemon's own log, for watching a box; the bundle is the record |

What happens inside the VM without crossing a door, including the processes an exec starts, is not recorded one by
one. The [architecture](architecture.md#doors) has every door in full.

## Platforms behind the contract

The contract is the same wherever the daemon runs:

- **existing:** a Linux host with `/dev/kvm`: Firecracker micro-VMs.
- **new:** a Mac, through a Linux VM with nested virtualization (colima with the `vz` type on Apple M3 or later and
  macOS 15 or later); documented with that pull request.
- **new:** a Docker engine for hosts without KVM, weaker than a micro-VM and labelled so, after the Mac.
