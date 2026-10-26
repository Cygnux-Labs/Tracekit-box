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

There is no release yet; until there is, `main` is the only version.

## Threat model

Three trust domains:

| Domain | Trust | What runs there |
|---|---|---|
| Host | Trusted | `tkbox daemon`, the egress proxy, the image builder, the secrets you pass in, your checkout |
| Guest (the micro-VM) | Untrusted | The agent, everything it runs, and `tkbox-guest` itself. Assume the agent is hostile: prompt-injected, or following instructions from a file it read |
| Signer | Trusted, separate from the agent | The Tracekit 1.4.2 signer and its signing key, on the same host as the daemon (Box reaches it only over a Unix socket) |

The attacker controls everything inside the VM, including its kernel's view of the world and every byte the guest
agent sends. The attacker does not control the host, the signer or the person approving on the host.

What the attacker wants, and what stands in the way:

| Goal | What stops it |
|---|---|
| Run code on the host | The KVM boundary and Firecracker's small device model, with Firecracker's default seccomp filter on the VMM (no jailer in v0). The guest reaches the host only through Firecracker's virtio devices and the vsock ports the daemon serves; the daemon parses guest input as untrusted (bounded frames, strict JSON, path checks) |
| Reach the network directly | The VM has no network card. The only route out is the egress proxy on vsock |
| Reach internal services or cloud metadata | The proxy resolves names on the host once, refuses loopback, private, link-local, metadata and multicast addresses and this host's own addresses (read live, so an address the host gains later is refused too), and dials the address it checked (no DNS rebinding). On EC2, GCE, Azure and GitHub-hosted runners the host's NAT'd public IP is on no interface, so Box can't see it and does not block it unless you pass it with `tkbox daemon --egress-block <IP>` (repeatable or comma-separated, a CIDR or a bare address) |
| Exfiltrate to an arbitrary host | The allowlist; any other host waits for a person on the host, who sees the target first (with `inspect: all` it is refused at once). An HTTPS tunnel's TLS server name (SNI) must equal the host it was opened for, as the ClientHello's only name (again after a HelloRetryRequest), and encrypted ClientHellos (ECH) are refused. That stops fronting by SNI only: in a tunnel Box does not inspect, the HTTP `Host` header or HTTP/2 `:authority` can still ask the same server or CDN for another site, while on inspected hosts (a bound secret or `inspect: all`) Box refuses any request that does not name the tunnel's host. A tunnel that is not TLS is allowed only to an allow entry that names its port (`host:port`), and such an entry lets any protocol through to that port. The decision comes before the first byte, so a `CONNECT` to any port other than 443 is decided and recorded as `tcp://host:port`, not as HTTPS; `CONNECT` to port 80 is refused, so plain HTTP goes through the proxy as absolute-form requests it reads |
| Steal a secret | The value never enters the VM: the box holds a placeholder, and the host proxy swaps the value in only in the bound header (default `Authorization`) of requests to the bound hosts. Secret hosts are exact names (wildcards are refused). On connections it reads, the proxy also redacts the value from response headers, bodies and trailers and blocks it in requests anywhere it is not being swapped in, in its raw, percent-encoded, JSON-escaped, hex and base64 forms in any case; a bound host that echoes it in another encoding (HTML character references, split across lines) hands it to the guest; requests to bound hosts ask for unencoded responses so they can be checked |
| Take credentials from your checkout | The workspace builder never copies credential files into the box (`.env*` except examples, `*.pem`, `*.key`, `.netrc`, `.npmrc`, SSH keys, `.ssh/`, `.aws/` and more; the list is in [docs/limits.md](docs/limits.md#behaviour)), even outside git or when `.gitignore` does not ignore them |
| Start a command without a record | Commands started in the box from the host (`tkbox exec`, the SDK, the action, MCP) run only through the guest agent's exec, which the daemon decides with the signer before it starts, with its command line (a first word with `=` or that is a shell reserved word quoted, so the signer parses the program that runs), working directory, env and stdin. Stdin known up front (`stdin_data`, at most 1 MiB: MCP's `tkbox_exec`, the SDK's bytes or str) is decided as its sha256 and size, and its text when it is UTF-8 of at most 4 KiB, and exactly that data is the process's stdin; streamed stdin's sha256 and size are in the completion. A per-exec env may not set `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `PATH`, `NODE_OPTIONS`, `PYTHONPATH`, `PERL5OPT`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `GCONV_PATH`, `GIT_CONFIG` or any `GIT_CONFIG_*` name, which would change what runs without changing the decided command line; the box's own env is recorded when the box is created. Neither env may hold a secret's value (`env K holds the value of secret S`). Inside the VM the agent can start any process without a record; containing that is the VM's job, and what those processes do is recorded where they cross a door |
| Change your repository behind your back | Changes leave only as a patch, saved when the box stops. `tkbox apply` works only on a stopped box, from the patch saved at stop, and before export (a daemon with a signer refuses the patch of a box that ran unrecorded); it validates every path (no `..`, no absolute paths, no `.git`, no writes through symlinks), refuses copy and rename sections, changes to git-ignored files and writes under the checkout's `core.hooksPath`, needs `--allow-sensitive` for files that steer the next run or host automation (`.github/workflows/**`, `.husky/**`, `.gitignore`, `.gitattributes`, `.gitmodules`, `tkbox.yaml`, `.envrc`, `.pre-commit-config.yaml`, …), and refuses the patch unless git itself, with an empty git dir and work tree, reads the same paths, binary flags, creations, deletions and modes from it as Box's strict parser. `git apply` never runs on the checkout: the result is built in a scratch copy with an empty git dir and without the host's or the repository's git config or attributes (no filters, hooks or LFS), the signer decides each file (with its content hash and mode) before anything is written, each result is re-checked against that decision and the checkout must be unchanged since it, and then Box writes the files itself (a temp file in the same dir, `O_EXCL`/`O_NOFOLLOW`, then rename; no symlinked parent; a deletion removes only a file or symlink). The git commands it runs in the checkout read no global or system config and run no pager, fsmonitor or external diff. What was written is checked against what was decided |
| Rewrite the record | The record is in the signer, in another trust domain. A bundle that was changed fails `tracekit verify` |
| Silence the record | Fail closed: if the signer does not answer, nothing runs. Records Box must keep (secret use and leaks, model calls, approvals, containment; lifecycle is sent synchronously) are never dropped silently: if one cannot be queued or the signer refuses it, Box stops the box and records the loss in the run as `tkbox.gap`, or closes the run with the loss as its reason if even that fails. A completion that could not be recorded is counted in `tkbox.gap` too (kind `complete`), and a stopping box closes its egress at once, whatever stopped it, and refuses every egress decision from then on, so nothing leaves and no secret is swapped in while it stops. A Box approval is recorded before any connection uses it. Flooding the box's refusals is rate-limited (20 a second, with a summary), and the local events file is capped (64 MiB) without dropping must-keep lines |
| Reach the daemon or signer sockets | Both are Unix sockets on the host; the VM has no path to them. The daemon's socket is 0600 in a 0700 directory and checks the caller's uid (its own or root), so any process of that uid can use the whole API and its approvals are recorded as `uid:<n>`, like a person's. An MCP client (`tkbox mcp`) reaches only the boxes its own session created (stopped when the session ends) and can only narrow the operator's setup, but that holds only if the orchestrator has no other access as the daemon's user: run it as another user ([docs/cli.md](docs/cli.md#tkbox-mcp)) |

## What Box guarantees

With a signer the agent cannot reach, and within the limits below:

- Every command started in the box through `tkbox exec` (or the SDK, the action or MCP) was decided by the signer
  before it started, and its outcome is in the signed record. The processes those commands start themselves are not
  decided or recorded one by one.
- Every outbound connection was decided before it was dialled: allowed by the allowlist, approved by a person on the
  host, or refused. Each is in the record.
- A bound secret's value is sent only to its bound hosts, and only in the header it is bound to (`Authorization` unless
  you name another). Each use is recorded by name and host, never by value.
- Nothing is written to your checkout by `tkbox apply` that the signer did not allow, file by file.
- The bundle is the signer's record of the run; `tracekit verify` detects any change to it.

## What Box does not guarantee

- **v0 has no jailer.** Firecracker runs as the daemon's user with its default seccomp filter, but without the jailer's
  chroot, namespaces and cgroups. A guest that escapes Firecracker through a VMM or KVM bug would have the daemon's
  user's privileges. Run the daemon as a dedicated unprivileged user on hosts that matter. The jailer is listed in
  [docs/limits.md](docs/limits.md#not-in-v0).
- **Code the agent wrote runs wherever you run it.** `tkbox apply` writes the agent's changes to your checkout;
  building or testing them on the host runs them outside the box. Test them in a box, or in a CI job with no write
  token and no secrets.
- **A same-user dev signer gives only dev assurance.** `tracekit init --dev` runs the signer as your user. The agent in
  the VM still cannot reach it, but any other process running as that user could read the signing key and re-sign
  history, and the bundle says `dev` for that reason. The signer must be on the same host as the daemon (Box reaches it
  only over a Unix socket), so in production run it as a separate user (Tracekit's system mode) and pin its trust file
  somewhere the host cannot change. The GitHub Action makes a dev signer and its trust file in the same job, so the
  action's bundles have dev assurance only.
- **Leak checks see only what the proxy reads.** The proxy reads (MITM) the hosts a secret is bound to, every allowed
  HTTPS host with `inspect: all`, and plain HTTP requests. On those it checks the request line, headers and body for
  placeholders. On other HTTPS connections it sees only the host, port and TLS server name, so a placeholder sent there
  is not detected and the attempt is not recorded; only the placeholder can leave, never the value. `inspect: all`
  closes this gap and breaks certificate pinning.
- **What an allowed host receives is up to the agent.** Box decides who the agent may talk to, not what it says. An
  agent allowed to reach `api.github.com` with a token can do anything that token permits there. Bind secrets with the
  narrowest scope that works. An allowed host that fetches on its caller's behalf relays data further: through the
  `go-proxy` preset (`proxy.golang.org`, `sum.golang.org`) the agent can make the mirror contact any domain it names
  and carry workspace data there (not secret values, which never enter the box).
- **A verified bundle proves the record is intact**, not that the agent's work is correct or that the agent's intent
  was benign. What the agent did inside the VM that crossed no door (the processes it started itself, reading files in
  `/workspace`, computing) is not in the record.
- **The host and its operator are trusted.** Root on the host can read secrets, change the daemon or approve anything.
  An operator who controls the signer can sign any history unless checkpoints go to a witness they cannot rewrite (see
  [Tracekit's scope](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md#scope)).
- **Approvals are only as good as the person giving them.** The approval shows the target host and port; it does not
  show what will be sent.
- **`--unrecorded` records nothing.** It exists for debugging Box itself.
- **A daemon crash leaves runs open.** The run token is held only in the daemon's memory, never on disk. A clean
  shutdown closes every open run; after a crash or `kill -9`, the runs of that daemon's boxes stay open in the signer
  (their records so far are kept), but those boxes can be neither applied nor exported, and their bundles cannot be
  produced. Stop the daemon with SIGTERM.
- **Clients that send ECH cannot use HTTPS through Box.** Encrypted ClientHellos are refused so Box can check the
  server name. Chromium-based clients send a GREASE ECH extension by default and may be refused; turn ECH off in them
  (not verified against every version).
- **Denial of service** by the agent against its own box (filling memory or disk, hitting limits) is expected; the
  limits in [docs/limits.md](docs/limits.md) bound it.

## Scope

In scope: escaping the VM through anything Box adds (the guest agent protocol, the boot config, vsock handling, disk
images), reaching the network or a private address without passing the proxy's checks, getting a secret's value into
the VM or to an unbound host, starting a command from the host or writing a host file without a decision, `tkbox apply`
writing outside the checkout or writing a file the signer did not decide, getting a credential file from the workspace
into the VM, making a run's record omit or misstate what passed a door, and reaching the daemon's socket from
the guest.

Out of scope: bugs in Firecracker or KVM themselves (report them upstream; tell us too if Box makes them easier to
reach), the operator and root on the host, the same-user dev signer's documented weakness, and the v0 gaps listed
above.
