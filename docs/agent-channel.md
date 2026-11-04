# The agent channel: an agent's own hooks inside a box (design, not built)

Status: proposal for review. Nothing here exists yet; the pull requests that build it update this page.

## The problem

Box decides and signs what crosses a door: a command started from the host, a connection, a secret's use, a file
written back. An agent such as Claude Code running inside a box makes its own tool calls (a shell command, a file
edit, a fetch), and Box sees those only where they cross a door: a connection, or the patch at stop. Tracekit's Claude
Code hooks decide and record each tool call before it runs, with the agent's reasoning beside it, but they need a
Tracekit signer, and the VM has no network card and the signer listens on a Unix socket on the host.

The agent channel lets those hooks reach the signer from inside the box, for that box's own runs only.

## The design

```
 micro-VM (untrusted)                                   host (trusted)
 Claude Code ─ hook ─▶ /run/tkbox/signer.sock ─ vsock 1027 ─▶ tkbox daemon ─▶ Tracekit signer (Unix socket)
                       (tkbox-guest, the guest end)              (the scoping proxy)
```

1. **Opt-in per box.** `tkbox run --agent-channel` (API: `agent_channel: true` in `CreateBoxRequest`). A box without
   it has no channel: nothing listens on the guest end and the daemon refuses port 1027 for it.
2. **The guest end.** `tkbox-guest` listens on a Unix socket in the VM, `/run/tkbox/signer.sock`, and relays each
   connection over a new vsock port, 1027, to the daemon. It speaks the signer's own framing (newline-delimited JSON,
   as on the signer's Unix socket), so Tracekit's unchanged client works with `TRACEKIT_SIGNER=/run/tkbox/signer.sock`.
   The guest end trusts nothing and decides nothing; it is a pipe.
3. **The daemon scopes every frame.** The daemon holds the only connection to the signer and reads each frame from the
   channel before sending anything on:
   - `register_run` is rewritten as a child run of the box's run: the daemon adds `parent` with the box run's id and
     token, which never reach the VM, and keeps the agent's run id. The signer records the link in the agent run's
     own `run.registered` (`parent_run`: the box's run), so a verifier sees which box the agent's run belongs to. Fields that make another kind of run
     (`analyzes`, `replay_of`, `investigation`, a `tenant`, a `principal_token`) are refused.
   - Every other frame must name a run this box's channel registered; anything else is refused before the signer sees
     it. The signer checks the run token as well.
   - Only the methods a coding agent's hooks and transcript tailer use pass: `register_run`, `decide`, `complete`,
     `observe`, `model_event`, `state_write`, `approval_request`, `approval_wait`, `approval_consume`, `approval_get`,
     `approval_abandon`, `constraint_add`, `close_run`, `tailer_lost` and `status`. Everything else is refused,
     including `approval_decide` and every on-behalf, operator, incident, content, PCM and findings call, and
     `delegate_run` and `tailer_heartbeat`: the tailer runs in the VM beside the hook.
   - Frames are size-limited as the signer limits them, and rate-limited per box. A box's channel holds at most a few
     connections and runs at once.
4. **Fail closed.** No channel, a refused frame or no signer: the hook gets an error, and Tracekit's Claude Code hook
   blocks the call (the box's runs are fail-closed). A box whose run is held or quarantined refuses the channel too.
5. **The box record says so.** The box's `tkbox.box` created observe names the channel (`agent_channel: true`), and
   the daemon counts what it refused in the box's events and, as an untrusted observe, in its run.

## What the channel can reach, and what it can't

| The agent, through the channel, can | It can't |
|---|---|
| Register runs as children of its own box's run | Register a run of another box, or one that isn't a child of its box's run |
| Send its own calls' decisions, results, prompts and model text into those runs | Touch any other run, including the box's own run (its token stays on the host) |
| Ask for and wait on approvals of its own calls, and consume them | Answer any approval: `approval_decide` never passes, so a held call waits for a person on the host |
| Read the signer's status | Reach the daemon's API, the signer's other methods, its keys or store, or the network: the channel is a pipe to one scoped proxy |

What it can do is exactly what an agent's hooks do anywhere. The hooks' records are the agent's account of its own
calls: an agent that controls its hook can lie in them, or skip them. Box's doors stay the authority on what crossed a
door. A connection the hook didn't report is still the door's `WebFetch` decision, and a file still comes back through
`apply` with its `Write` decision. A verifier compares the two.

## What the signer and the bundle show

The signer sees every channel frame from the daemon's identity (its uid), as it sees Box's own. So:

- The agent's runs read the daemon's isolation from the signer: `same-user` with a dev signer the daemon's user runs,
  `separate-user` with a signer of its own user. The agent itself is in the micro-VM in both cases, and neither the
  key nor the store is in the VM.
- That an agent run belongs to a box is its `parent_run` link to the box's run, which only a holder of the box run's
  token can make: the daemon, never the agent.
- **Open question for review:** whether the signer should record a box run's agent runs with their own isolation
  value, as Tracekit's pull request #601 proposes for its container boxes (`ext.box`), so a verifier can say "proof
  against the boxed agent" without reading the run tree. That is a Tracekit format question, decided there.

## The Claude Code image

An image, built from a Dockerfile in this repository and not published by it: Debian with Node and Python, Claude Code
pinned to a version at least two weeks old, Tracekit's hook client, and Claude Code's managed settings
(`/etc/claude-code/managed-settings.json`) holding Tracekit's v2 hooks with `TRACEKIT_SIGNER=/run/tkbox/signer.sock`
pinned in their `env`. Commands run as root in a box, the VM being the boundary, and Claude Code refuses root without
`IS_SANDBOX=1`, which the image sets. The model key is a Box secret bound to `api.anthropic.com`
(`--secret ANTHROPIC_API_KEY=env:ANTHROPIC_API_KEY@api.anthropic.com`); the VM sees only its placeholder. Its egress
is the `claude-code` preset with `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`. The project comes in as the workspace
copy, and its changes go out only through `apply`.

## What changes where

| Part | Change |
|---|---|
| `internal/api` | `agent_channel` in `CreateBoxRequest` and `Box` |
| `internal/proto` | port 1027; the guest end's boot config |
| `cmd/tkbox-guest`, `internal/guest` | the socket and the relay |
| `internal/daemon` | the scoping proxy: method allowlist, run binding, parent rewrite, limits, counts |
| `internal/tracekit` | a raw frame call for the proxy (protocol 19) |
| `examples/` or `images/claude-code/` | the Claude Code image's Dockerfile |
| Tests | unit tests of every refusal (fake signer); an end-to-end test that runs Tracekit's hook in a box and exports a bundle whose agent run's `parent_run` is the box's run |
