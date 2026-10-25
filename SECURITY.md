# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub security advisories](https://github.com/Cygnux-Labs/tracekit-box/security/advisories/new) rather than a public
issue. A vulnerability in the Tracekit signer, its bundles or `tracekit verify` goes to
[Tracekit's advisories](https://github.com/Cygnux-Labs/Tracekit/security/advisories/new). Include the version
(`tkbox version`, and `tracekit --version`), the host's distribution, kernel and architecture, and steps to reproduce.

We follow Tracekit's timeline: we acknowledge a report within 3 business days, confirm or reject it with an initial
severity within 10 business days, and aim for a fix and coordinated disclosure within 90 days of the report (earlier if
the fix ships sooner, later only if you agree). Once a fix is released we publish an advisory and credit you, unless you
ask us not to. Good-faith research within the scope below is covered by the same safe harbour as
[Tracekit's security policy](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md#safe-harbour).

## Supported versions

| Version | Supported |
|---|---|
| Latest release (0.x, newest) | Yes: security fixes |
| Older releases | No: upgrade to the latest release |
| `main` | Development branch: reports welcome, no backported fixes |

## Threat model

Three trust domains:

| Domain | Trust | What runs there |
|---|---|---|
| Host | Trusted | `tkbox daemon`, the egress proxy, the image builder, the secrets you pass in, your checkout |
| Guest (the micro-VM) | Untrusted | The agent, everything it runs, and `tkbox-guest` itself. Assume the agent is hostile: prompt-injected, or following instructions from a file it read |
| Signer | Trusted, separate from the agent | The Tracekit 1.4.2 signer and its signing key |

The attacker controls everything inside the VM, including its kernel's view of the world and every byte the guest
agent sends. The attacker does not control the host, the signer or the person approving on the host.

What the attacker wants, and what stands in the way:

| Goal | What stops it |
|---|---|
| Run code on the host | The KVM boundary and Firecracker's small device model. The guest reaches the host only through Firecracker's virtio devices and the vsock ports the daemon serves; the daemon parses guest input as untrusted (bounded frames, strict JSON, path checks) |
| Reach the network directly | The VM has no network card. The only route out is the egress proxy on vsock |
| Reach internal services or cloud metadata | The proxy resolves names on the host once, refuses loopback, private, link-local, metadata and multicast addresses and the signer's address, and dials the address it checked (no DNS rebinding) |
| Exfiltrate to an arbitrary host | Allowlist; any other host waits for a person on the host, who sees the target first |
| Steal a secret | The value never enters the VM: the box holds a placeholder, and the host proxy swaps the value in only on requests to bound hosts |
| Run a command without a record | Commands run only through the guest agent's exec, which the daemon decides with the signer before it starts |
| Change your repository behind your back | Changes leave only as a patch; `tkbox apply` validates every path (no `..`, no absolute paths, no writes through symlinks) and the signer decides each file before anything is written |
| Rewrite the record | The record is in the signer, in another trust domain. A bundle that was changed fails `tracekit verify` |
| Silence the record | Fail closed: if the signer does not answer, nothing runs |
| Reach the daemon or signer sockets | Both are Unix sockets on the host; the VM has no path to them. The daemon's socket is 0600 in a 0700 directory and checks the caller's uid |

## What Box guarantees

With a signer the agent cannot reach, and within the limits below:

- Every command run in the box through `tkbox exec` (or the SDK, the action or MCP) was decided by the signer before it
  started, and its outcome is in the signed record.
- Every outbound connection was decided before it was dialled: allowed by the allowlist, approved by a person on the
  host, or refused. Each is in the record.
- A bound secret's value is sent only to its bound hosts, and only in the header it is bound to. Each use is recorded by
  name and host, never by value.
- Nothing is written to your checkout that the signer did not allow, file by file.
- The bundle is the signer's record of the run; `tracekit verify` detects any change to it.

## What Box does not guarantee

- **v0 has no jailer or seccomp hardening.** Firecracker runs as the daemon's user, without the jailer's chroot,
  namespaces and cgroups or a seccomp filter on the VMM. A guest that escapes Firecracker through a VMM or KVM bug would
  have the daemon's user's privileges. Run the daemon as a dedicated unprivileged user on hosts that matter. The VMM
  interface is ready for the jailer; it is listed in [docs/limits.md](docs/limits.md#not-in-v0).
- **A same-user dev signer gives only dev assurance.** `tracekit init --dev` runs the signer as your user. The agent in
  the VM still cannot reach it, but any other process running as that user could read the signing key and re-sign
  history, and the bundle says `dev` for that reason. In CI and production run the signer as a separate user or on a
  separate host (Tracekit's system mode), and pin its trust file outside the job.
- **Placeholder checks see only what the proxy inspects.** By default the proxy opens (MITM) only hosts with a bound
  secret. On other HTTPS connections it sees only host and port, so a placeholder sent there is not detected. Only the
  placeholder can leave, never the value, but the attempt is not recorded. `inspect: all` closes this gap and breaks
  certificate pinning. Request bodies are never scanned for placeholders.
- **What an allowed host receives is up to the agent.** Box decides who the agent may talk to, not what it says. An
  agent allowed to reach `api.github.com` with a token can do anything that token permits there. Bind secrets with the
  narrowest scope that works.
- **A verified bundle proves the record is intact**, not that the agent's work is correct or that the agent's intent
  was benign. What the agent did inside the VM that crossed no door (reading files in `/workspace`, computing) is not in
  the record.
- **The host and its operator are trusted.** Root on the host can read secrets, change the daemon or approve anything.
  An operator who controls the signer can sign any history unless checkpoints go to a witness they cannot rewrite (see
  [Tracekit's scope](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md#scope)).
- **Approvals are only as good as the person giving them.** The approval shows the target host and port; it does not
  show what will be sent.
- **`--unrecorded` records nothing.** It exists for debugging Box itself.
- **Denial of service** by the agent against its own box (filling memory or disk, hitting limits) is expected; the
  limits in [docs/limits.md](docs/limits.md) bound it.

## Scope

In scope: escaping the VM through anything Box adds (the guest agent protocol, the boot config, vsock handling, disk
images), reaching the network or a private address without passing the proxy's checks, getting a secret's value into
the VM or to an unbound host, running a command or writing a host file without a decision, `tkbox apply` writing
outside the checkout, making a run's record omit or misstate what passed a door, and reaching the daemon's socket from
the guest.

Out of scope: bugs in Firecracker or KVM themselves (report them upstream; tell us too if Box makes them easier to
reach), the operator and root on the host, the same-user dev signer's documented weakness, and the v0 gaps listed
above.
