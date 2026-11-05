# The agent channel: an agent's own hooks inside a box

Status: implemented. The Linux/KVM end-to-end test (`TestAgentChannel`) passed in the colima VM (nested KVM) on
2026-11-05 at 6705867, the head after the review fixes.
The host's per-box vsock listener and scoping proxy, its per-box channel connections and run/approval tables,
the guest Unix-socket relay, named frame/rate/run/byte limits and Claude Code image are implemented. Tracekit contract v21 is implemented in the reference checkout
and Box requires Tracekit 1.6.0 or later (RPC protocol 21) when this option is requested; Box's base Tracekit
requirement remains protocol 19 (Tracekit 1.5.3).

Implementation note: `register_run` is rebuilt from only `request_id` and `agent`; strict JSON and the channel limits
are enforced by the host proxy. The proxy uses the signer response's top-level `run_id`, `run_token`, and
`approval_id` fields to maintain its per-box ownership tables.

## The problem

Box decides and signs what crosses a door: a command started from the host, a connection, a secret's use, a file
written back. An agent such as Claude Code running inside a box makes its own tool calls (a shell command, a file
edit, a fetch), and Box sees those only where they cross a door. Tracekit's Claude Code hooks decide and record each
tool call before it runs, with the agent's reasoning beside it, but they need a Tracekit signer, and the VM has no
network card while the signer listens on a Unix socket on the host.

The agent channel lets those hooks reach the signer from inside the box, for that box's own runs only.

**What it is and isn't.** Hooks run inside the box, under the agent's control: a hostile agent can skip them, lie in
them, or ignore a block. A hook's block is advice to an honest agent, never enforcement. Box's doors are the
enforcement: a connection is still its `WebFetch` decision, and a file is still its `Write` decision at `apply`. The
channel adds the agent's own account of its calls beside the doors, so a verifier can compare the two.

## The design

```
 micro-VM (untrusted)                                      host (trusted)
 Claude Code (non-root) ─ hook ─▶ /run/tkbox/signer.sock ─ vsock 1027 ─▶ tkbox daemon ─▶ signer, as box:<uid>/<box id>
                                  (tkbox-guest, a pipe)                  (scoping proxy)
```

### One signer identity per box (Tracekit contract)

If every box's channel reached the signer as the daemon's own identity, one agent could use up that identity's quotas
(events a second, open runs, pending approvals, waits) and fail every box's door decisions closed. A hold's cooldown
(keyed by owner) would then start every box's runs held, and request-id deduplication and `approval_get` would be
shared across boxes.

So each box's channel gets its own signer connection with its own identity, `box:<daemon uid>/<box id>`:

- The signer's config names each Box daemon and its engine, e.g. `box_daemons: {"uid:1001": firecracker}`. Only that
  daemon, on its own authenticated connection, may open a channel connection for one of its boxes. It names the box,
  and the signer gives that connection the identity `box:1001/<box id>`. **(Tracekit contract)**
- The signer keys everything per identity on it: run owner, quotas, request-id deduplication, hold cooldowns and
  approval visibility. One box can exhaust only its own limits. **(Tracekit contract)**
- Its `authorize` entry grants only the channel's methods (below), whatever the config grants the daemon itself.
  **(Tracekit contract)**
- Parent linking: the signer accepts a parent run's token only from the identity it issued it to, so the channel's
  identity can't send `parent`. When the daemon opens a box's channel, it names the box's run on its own connection,
  and the signer makes every run that the per-box identity registers a child of that box run (`parent_run`). No
  `parent` appears in the agent's request. The per-box identity takes the daemon's tenant. **(Tracekit contract)**

### The guest end

- **Opt-in per box.** `tkbox run --agent-channel` (API: `agent_channel: true` in `CreateBoxRequest`). Without it,
  nothing listens in the VM, and the daemon creates no listener on vsock port 1027 for that box.
- `tkbox-guest` listens on `/run/tkbox/signer.sock`, in a root-owned directory the agent can only connect through, and
  relays each connection over vsock 1027 to the daemon. It speaks the signer's own framing (newline-delimited JSON), so
  Tracekit's unchanged client works with `TRACEKIT_SIGNER=/run/tkbox/signer.sock`. It trusts nothing and decides
  nothing.

### The daemon: the scoping proxy

The required limits are: 16 open connections per box; 1 MiB maximum frame; 10 seconds for the first byte through
newline; 15 seconds idle between frames; a signer link quiet for 25 seconds (under the signer's 30, as frames the
channel refuses keep a guest connection alive without reaching the signer) replaced before the next frame goes out;
330 seconds for a signer reply; 10 seconds for guest writes; JSON
nesting depth 128; 50 frames/second with burst 200, where each new connection costs a frame (it makes the signer set
up a connection of its own); 256 runs over the box's lifetime; 64 MiB across every forwarded frame but `hello` and
`status`, whatever its method, since any of them can reach the signer's content vault; and 1,048,576 forwarded frames
over the box's lifetime (`hello` and `status` included: about 20 times a long coding session, almost six hours of
nonstop sending at the rate limit). Rate and byte limits are per box and are accounted under one shared lock. Across
the daemon's boxes, the strict checks run on at most half the CPUs at once.

**Read pace.** A box's connections share one read budget: 1 MiB a second, 8 MiB at once (`Server.ReadRate` and
`ReadBurst`). Every byte the proxy reads from a guest is reserved from it first, refused frames included, and while
it is spent a read waits: the bytes stay in vsock and the guest's writer stalls, rather than the daemon reading them
at the guest's speed. A coding agent's hook and tailer send a few KiB per tool call and model turn, their largest
frames (a big `Write`'s arguments, a long tool result) stay under 1 MiB, and a box forwards at most 64 MiB in its
life (the byte budget), which this pace passes in about a minute, so real traffic does not meet it. A box flooding
its channel with 1 MiB frames costs the daemon about 0.05 of a core this way, against about 4.6 cores unpaced, and
another box's frames are answered as usual meanwhile (`TestAFloodingBoxIsPaced`). The pace is the box's own: a box
flooding its own channel can hold its own large frames past the 10 seconds a frame may take to arrive, and that
connection is closed; other boxes are unaffected.

**Which box.** The daemon serves 1027 on a per-box Firecracker vsock listener path, `<box dir>/vsock.sock_1027`, so a
connection's box is the listener it arrived on, never anything a frame says. Connections per box are capped. When a
stop begins, the listener and its connections are closed with the egress.

**Reading frames.**
- Each frame is read through a reader bounded at 1 MiB, the signer's line limit, with a deadline per frame. A partial
  frame never stalls the channel.
- Each frame is checked with Tracekit's strict rules: one JSON object, no duplicate keys at any level, valid UTF-8 and
  a depth limit. The check reads the frame in place without building its value: it keeps only the names of the
  objects it is inside, and the top-level fields the rules read.
- A frame that passes is forwarded as the received bytes, verbatim, so nothing is rounded, except `register_run`,
  which the daemon builds fresh from the agent's own `request_id` and `agent` bytes (below), never longer than the
  frame they came in.
- Rate limits answer `quota_exceeded` with `retry_after_ms`, as the signer does. A frame is never held back. A frame
  over the rate is passed over unread: neither kept nor checked. The lifetime frame cap answers `quota_exceeded`
  without `retry_after_ms`: waiting frees nothing.
- Every refusal is also a `channel.refused` event of the box: its kind (`frame`, `method`, `field`, `run`,
  `approval`, `rate`, `run_cap`, `byte_budget`, `frame_cap`, `connections`, `signer`), the method when it is a plain
  name, and the channel's own reason, never the frame's content. A box gets at most one such event per kind a second;
  the refusals in between are counted into the kind's next event (`folded`), and the stop reports what is left. The
  same refusals are signed into the box's run as `tkbox.channel` observes, in the bulk lane egress refusals use.

**Methods.** Only the methods a coding agent's hook and its transcript tailer use pass: `hello` (the client's first
frame), `register_run`, `decide`, `complete`, `observe`, `model_event`, `state_write`, `approval_request`,
`approval_wait`, `approval_consume`, `approval_get`, `approval_abandon`, `constraint_add`, `close_run`, `tailer_lost`
and `status`. Everything else is refused before the signer sees it. That includes `approval_decide` and every
on-behalf, operator, incident, content, PCM and findings call, `delegate_run` and `tailer_heartbeat`; the tailer runs
in the VM beside the hook.

**Fields, not only methods.** Methods pass by an allowlist; fields are refused by deny lists.
- `register_run`: the daemon builds the request itself from only the agent's `request_id` and `agent`. It refuses a
  request that carries `parent`, `principal`, `principal_token`, `caller`, `source`, `tenant`, `analyzes`,
  `replay_of`, `investigation`, `ext` or `box`, and drops `run_id`: the signer names the run. An agent name may
  hold only ASCII letters, digits, `.`, `_`, space and `-` (no lookalike of a reserved name passes), and one that
  starts with `tkbox` (any case) is refused. An agent run may share the box run's name (Tracekit's Claude Code hook
  registers as `claude-code`, the name the GitHub Action gives a Claude Code box): what tells them apart is
  signer-written: the agent run's `parent_run`, which a box run never has (both carry `ext.box`), never the name.
- In every method: `caller`, `on_behalf`, `amended` and `tool_results` are refused. These are what a gateway or a
  bridge sends for someone else.
- `approval_get`: exempt from the run-id check because its schema has no `run_id`; only for approval ids this
  channel's own `approval_request` returned.
- `observe`: a source must be plain ASCII (letters, digits, `.`, `_`, space, `-`, `:` and `/`), and one that starts
  with `tkbox` in any case is refused (Box's own records are Box's). `trust` is left as the hook sent it: the
  hook marks the person's own prompt `trusted`, and forcing it would hold legitimate calls. What the agent's run says
  about trust is the agent's account, under its own run and label, never Box's.
- A byte budget per box covers what can go into the signer's content vault: every forwarded frame but `hello` and
  `status` (a `decide`'s arguments are kept as a `complete`'s result is). These lifetime limits answer without
  `retry_after_ms`, as waiting frees nothing (the run cap sends it only while a registration in flight may yet fail
  and free its place). Past the byte budget, or past the lifetime frame cap, the
  channel refuses with `quota_exceeded`, and the box's events say so.

**Runs.**
- The run table is filled from the signer's `register_run` response, under a lock. An entry is never reused, and the
  box run itself is never in it.
- Every other frame must name a run in that table; the signer checks the run token as well.
- Total runs per box are capped, not only open ones.
- At stop, the channel closes its guest connections and their signer connections at once, except one whose
  `register_run` is with the signer: its reply gets 2 seconds, so the run it registers reaches the run table. A long
  poll (`approval_wait`) holds up no stop. Once the VM is down (a kill waits for no
  signer), every run the channel opened is closed, eight at a time, within 30 seconds. The box's own run stays open
  for `tkbox apply`, as a plain box's does, and closes at export, `rm` or daemon shutdown: after its channel's runs.
- A successful agent `close_run` marks the run closed. It remains counted against the lifetime cap and is not closed
  a second time at stop.

### Fail closed, as far as it can be

- In the Claude Code image, Claude Code runs as a non-root user. The managed settings, the hook and the socket's
  directory are root-owned and read-only to it. `allowManagedHooksOnly` is set, so a project's or the user's own hooks
  don't run.
- A box with the channel requires its signer's `fail_modes` to be closed, so an unreachable signer blocks a call. The
  daemon checks at create.
- A refused frame, a channel that went away, or a box whose run is held or quarantined: the hook gets an error and
  Tracekit's hook blocks the call.
- Against a hostile agent, all of this is advisory (above): Box's doors are what it can't get past.

## What the channel can reach, and what it can't

| The agent, through the channel, can | It can't |
|---|---|
| Register runs as children of its own box's run | Register a run of another box, a run that isn't a child of its box's run, or any other kind of run |
| Send its own calls' decisions, results, prompts and model text into those runs, within its box's byte budget | Touch any other run, including the box's own run (its token stays on the host) |
| Ask for, wait on and consume approvals of its own calls | Answer any approval (`approval_decide` never passes), or read another box's approvals |
| Use up its own box's quotas | Use up another box's quotas, or the daemon's own (each box is its own signer identity) |
| Read the signer's status | Reach the daemon's API, the signer's other methods, its keys or store, or the network: the channel is a pipe to one scoping proxy |

## What the signer and the bundle show

### The box label (Tracekit contract)

The signer establishes the label; the agent never does.

- It is written on the **box's run**, when the daemon registers it as a Box daemon `box_daemons` names. The run's
  `run.registered` carries a signer-written `ext.box` with:
  - the box id;
  - the image digest;
  - the allowlist's names;
  - the engine from the signer's config, never from the request (`firecracker`, a micro-VM);
  - `channel: "agent"` when the box has one.
- The signer copies that label to every run registered as its child over the box's channel identity, so no agent run
  carries a label its box run doesn't.
- Any request carrying `ext` is refused, by the channel and by the signer.
- The engine is the daemon's config, not its word. The box's id, image and allowlist are the daemon's own trusted
  account, the same values as the box run's `tkbox.box` records. A verifier with both can check that they agree.

### What verify says (Tracekit contract)

For a run with this label, `verify` prints:

1. `PROOF AGAINST THE BOXED AGENT (micro-VM): the signing key was outside its box for this run.`
2. `This run's records are the agent's own account of its calls; the box's doors (its connections and file writes) are the record of what it could do.`
3. `Before you run anything the box wrote, review it: code you run on this machine can reach the key.`
4. When a witness cosigned the checkpoint: `anchored by <witness> at <time>`.

It never prints a general "proof against the agent": anything running as the daemon's or the signer's user on the
host is outside the claim. Lines 1 and 3 are the ones Tracekit's pull request #601 uses for its Docker boxes, with the
engine named.

## The Claude Code image

An image, built from [images/claude-code/Dockerfile](../images/claude-code/Dockerfile) and not published by this repository:

- Debian, Node and Python, Claude Code pinned to a version at least two weeks old, and Tracekit's hook client.
- Claude Code runs as a non-root user, with `IS_SANDBOX=1` set as well.
- Root-owned managed settings (`/etc/claude-code/managed-settings.json`) hold Tracekit's v2 hooks, with
  `TRACEKIT_SIGNER=/run/tkbox/signer.sock` pinned in their `env` and `allowManagedHooksOnly: true`. The hooks run
  `/opt/tracekit/bin/python3` and `/bin/grep` by path, and the managed `env` pins `PATH`, `TRACEKIT_RUNTIME_DIR` and
  `TRACEKIT_APPROVAL_WAIT`, empties `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`,
  `BASH_ENV`, `ENV` and `CLAUDE_CODE_SIMPLE`, sets `CLAUDE_CODE_SHELL_PREFIX` to none and `CLAUDE_CODE_SHELL` to the
  image's `/bin/bash`, and sets `disableAllHooks` false, so a project's or the user's settings (which come before
  managed settings in Claude Code's order) can't put a stub in their place, wrap them in a prefix, load code into them,
  turn them off or move the hook's state. `go test -tags image ./images/claude-code` runs the image's own Claude Code in
  such a project, with no API key, and checks that the managed hooks still register and close their run with a fake
  signer ([README](../images/claude-code/README.md)).
- The model key is a Box secret bound to the header the Anthropic API reads, not the default `Authorization`:
  `--secret ANTHROPIC_API_KEY=env:ANTHROPIC_API_KEY@api.anthropic.com#X-Api-Key`. The VM sees only its placeholder.
- Its egress is `--allow claude-code,anthropic`. The `anthropic` preset makes `api.anthropic.com` a model host, so
  Box records each model call (`tkbox.model.call`) on that inspected connection. `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`
  keeps Claude Code off other telemetry hosts.
- The project comes in as the workspace copy, and its changes go out only through `apply`.

Build and run instructions are in [images/claude-code/README.md](../images/claude-code/README.md). The end-to-end test,
`TestAgentChannel` in [e2e/](../e2e/agent_channel_test.go), runs with `make e2e` on a Linux host with KVM when
`TKBOX_TRACEKIT21` names a `tracekit` CLI that serves protocol 21: it starts its own signer from it, with `box_daemons`
naming the test's user ([development.md](development.md#end-to-end-tests)). It runs Tracekit's hook client directly, not
Claude Code, so the managed settings are covered by the image test above, not by it.

## What changes where

| Part | Change |
|---|---|
| Tracekit (one pull request, a new contract version) | `box_daemons`; the per-box channel identity and per-identity quotas, dedup, cooldowns and approval visibility; `ext.box` written on the box run and copied to its children; `ext` refused in requests; the verifiers' lines, with tests |
| `internal/api` | `agent_channel` in `CreateBoxRequest` and `Box` |
| `internal/proto` | port 1027; the guest end's boot config |
| `cmd/tkbox-guest`, `internal/guest` | the root-owned socket and the relay |
| `internal/daemon` | the per-box listener, the scoping proxy (strict bounded reads, a method allowlist and field deny lists, run table, `register_run` built fresh, byte budget, rate limits, run and connection caps), closing at stop, the `fail_modes` check |
| `internal/tracekit` | a per-box channel connection with its own identity, once Tracekit offers it; with an older signer there is no channel |
| `images/claude-code/` | the Claude Code image's Dockerfile |
| Tests | unit tests of every refusal (fake signer), including two boxes that can't touch each other's runs or quotas; an end-to-end test that runs Tracekit's hook in a box and exports a bundle whose agent run carries the box's label; an image test that runs the image's Claude Code in a hostile project against a fake signer |
