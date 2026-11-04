# Integrating with Tracekit Box: the v1 contract

Box is a component: any program on the daemon's host can run an agent in a box and get its changes back through one
versioned contract. The CLI, the MCP server, the [Python SDK](../sdk/python/README.md) and the
[GitHub Action](../action) all use it, and so does Tracekit's own `tracekit up --isolated`. This page is that contract
as a host program sees it. The types and routes are defined in code in [`internal/api`](../internal/api/api.go), which
wins where this page and the code differ.

Each part below is marked **existing** (in v1 today) or **new** (planned; the pull request that adds it updates this
page and moves the mark).

## Transport and who may call

- **existing:** HTTP/1.1 with JSON bodies on the daemon's Unix socket, `<state dir>/run/tkbox.sock` (mode 0600 in a
  0700 dir; `tkbox daemon --socket PATH` moves it). There is no TCP listener.
- **existing:** the daemon accepts a connection only from its own uid or root, read from the socket's peer credentials.
  Anything running as that uid can use the whole API: the contract has no finer permissions.
- **existing:** the CLI is the same contract for scripts. `tkbox run`, `tkbox ls`, `tkbox events` and
  `tkbox approvals` take `--json` and print the API's objects. **new:** `--json` on `tkbox stop`, `tkbox apply` and
  `tkbox export`, printing `Box`, `ApplyResult` and `ExportResult`. Until then, a program that needs those results
  calls the API.

## Versioning

- **existing:** every route is under `/v1/`. `GET /v1/health` answers `api: "v1"`. Call it first: it also says whether
  this host can run boxes (`kvm`), whether the signer answered just now (`signer_ok`), and whether the daemon records
  nothing (`unrecorded`).
- **existing:** request bodies are decoded strictly. A field the daemon doesn't know is refused with `bad_request`, so
  a client sends only the fields of the version it checked.
- Within v1, responses may gain fields; clients ignore fields they don't know. Removing or renaming a field, or
  changing what one means, is a new version under a new path (`/v2/`), served beside v1 for at least one release.

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

A host program's usual sequence: health → create → exec (as many as needed) → stop → diff summary → apply with
`check: true`, then without → export → `tracekit verify` on the bundle with its trust file.

`apply` works only on a stopped box whose run is still open (after stop, before export or remove). It never runs
`git apply` on the checkout and runs no git hooks or filters. It refuses sensitive paths (`.github/workflows/`,
`.husky/`, `.devcontainer/`, credential files, coding agents' configs and instructions, …; the list is in
[cli.md](cli.md#tkbox-apply)) unless `allow_sensitive` is set, and nothing is written if the signer denies any file.

## The exec stream

- **existing:** after 101, both directions carry frames `[type u8][length u32 big-endian][payload]`, with a payload of
  at most 1 MiB ([`internal/proto`](../internal/proto/frame.go)).
- Daemon → client: `json` `ExecEvent` (`deciding`, `waiting_approval` with `approval_id` and `approver`, `running`,
  `notice`), `stdout`, `stderr`, then exactly one of `exit` (`ExitStatus`) or `error` (`code`, `message`, `rule_ids`,
  `hint`).
- Client → daemon: `stdin`, `stdin_eof`, `signal`.
- The command is decided before it starts: a refusal is an `error` frame with code `denied` before any output.

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
| `timeout` | 504 | A box or approval timeout |
| `not_supported` | 501 | This host can't do it (no `/dev/kvm`) |
| `cancelled` | — | The caller went away before the command started (exec frames only) |
| `internal` | 500 | A Box bug: report it |

## What is signed where

Each box is one Tracekit run, opened at create and closed at export, removal, daemon shutdown, quarantine or failure.
Box speaks the signer's RPC (protocol 19, which Tracekit 1.4.2 and later serve) over the signer's Unix socket on the
same host. The records:

| Operation | Tracekit record |
|---|---|
| Create | `register_run`, then observe `tkbox.box` (`box_id`, `image`, `image_digest`, `allow`, `limits`, and the box's env, scrubbed) and the task, if any, as trusted content |
| Exec | `decide` tool `Bash` with `{command, cwd, env, stdin}` before it starts, then `complete` with the exit status |
| A connection from the box | `decide` tool `WebFetch` with `{url}` per connection; a Box approval as observe `tkbox.approval` |
| Secrets | observe `tkbox.secret.use` and `tkbox.secret.leak` (name and host, never the value) |
| Model calls | observe `tkbox.model.call` (host, path, status, bytes) for a model host's requests |
| Apply | `decide` tool `Write` for every file before anything is written (`file_path`, `sha256`, `mode`, `symlink`, `deleted`, `patch_sha256`, `sensitive`), then `complete` with what was written |
| Stop, containment, lost records | observe lifecycle events, `tkbox.gap` for what couldn't be recorded; `close_run` with the reason |
| Events (`GET …/events`) | not signed: the daemon's own log, for watching a box; the bundle is the record |

What happens inside the VM without crossing a door, including the processes an exec starts, is not recorded one by
one. The [architecture](architecture.md#doors) has every door in full.

## Platforms behind the contract

The contract is the same wherever the daemon runs:

- **existing:** a Linux host with `/dev/kvm`: Firecracker micro-VMs.
- **new:** a Mac, through a Linux VM with nested virtualization (colima with the `vz` type on Apple M3 or later and
  macOS 15 or later); documented with that pull request.
- A Docker engine for hosts without KVM, weaker than a micro-VM and labelled so, is planned after these.
