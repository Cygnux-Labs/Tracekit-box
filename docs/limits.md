# Limits

Every limit of Tracekit Box v0 is on this page, with its default, what Box says when you hit it, and what to do. When
Box refuses something because of a limit, the error has code `limit` (or `timeout`) and a hint that says what to do;
the CLI prints both, and the [Python SDK](../sdk/python) raises `LimitError` or `TimedOut` with `.hint` set.

Defaults apply when neither `tkbox run` flags nor [tkbox.yaml](config.md) set a value.

## Box resources

| Limit | Default | What Box says when hit | What to do |
|---|---|---|---|
| vCPUs per box | 2 (1 to 32) | Out of range at create: `limits.cpus must be between 1 and 32`. Inside the box, processes just get N CPUs | `--cpus N` or `limits.cpus` |
| Memory per box | 2048 MiB (128 to 65536) | The guest kernel's OOM killer ends a process: the exec exits with signal `SIGKILL` (CLI exit 137) and Box adds a notice `the box ran out of memory (2048 MiB); writes outside /workspace also use memory` <!-- TODO(lead): confirm the daemon detects OOM (console.log) and prints this notice --> | `--memory 4096` or `limits.memory`. Files written outside `/workspace` count against memory (see below) |
| Workspace disk (writes to `/workspace`) | 4096 MiB (64 to 1048576) | The write fails inside the box with `No space left on device` (ENOSPC) | `--disk 16384` or `limits.disk`; keep build output and caches out of `/workspace` |
| Box lifetime | 1 h | `box demo reached its timeout (1h0m0s) and was stopped; its changes are kept: tkbox diff, apply and export still work`. A running exec ends with error `timeout`; the run's close reason is `timeout` | `--timeout 2h` or `limits.timeout` |
| Time per exec | 30 min | `timed out after 30m0s (the box's exec timeout)`; the process group is killed with SIGKILL and `tkbox exec` exits 124 | `tkbox exec --timeout 2h`, or `limits.exec_timeout` for every exec |
| Boxes per daemon | 8, any state <!-- TODO(lead): confirm "any state" vs running only, and whether a daemon flag changes it --> | `limit: 8 boxes exist (the daemon's limit)` with hint `remove boxes you are done with: tkbox rm <box>` | `tkbox ls`, then `tkbox rm` stopped boxes after exporting them |
| Concurrent execs per box | 64 | `busy: 64 execs are already running in this box` | Wait for one to finish; run fewer background processes per exec |
| Output per exec (stdout + stderr) | 256 MiB | The rest is dropped and Box prints `output truncated at 256 MiB`; the exec's exit status has `truncated` set | Write large output to a file in the box and read the part you need |
| Console log | 8 MiB per box (`boxes/<id>/console.log`) | Nothing in the box; the log stops growing at 8 MiB <!-- TODO(lead): confirm whether it keeps the first or the last 8 MiB --> | Read the box's events (`tkbox` API `/events`) for what happened at the doors; the console log is for boot problems |

## Commands, files and changes

| Limit | Default | What Box says when hit | What to do |
|---|---|---|---|
| Approval wait (a host off the allowlist) | 2 min | The connection is refused with 403 and the exec shows `approval ap_… for https://example.com:443 expired after 2m0s; nothing was sent` | Answer sooner with `tkbox approve <id>`, approve for the whole box with `tkbox approve <id> --box`, or put the host on the allowlist |
| Signer approval wait (a command the signer's policy holds) | 300 s per wait call | The exec shows `waiting for approval <id>: tracekit approvals approve <id>`; Box waits in 300 s calls until the exec timeout <!-- TODO(lead): confirm Box re-polls approval_wait until the exec timeout, and what happens when the signer expires the approval --> | Answer with `tracekit approvals approve <id>` on the signer host |
| Command line size | 1 MiB (one signer frame) | `the command is too long to record (the signer's 1 MiB frame limit); put it in a script in /workspace and run that` <!-- TODO(lead): confirm the daemon checks this before deciding and prints this --> | Write long scripts or data to a file and run the file |
| Workspace patch (`tkbox diff`, `tkbox apply`) | 64 MiB | `too_large: the workspace patch is larger than 64 MiB` | Remove build output, dependencies and other generated files from `/workspace` before stopping the box (for example, install packages outside it) |
| One file read from the box | 64 MiB | `too_large: <path> is larger than 64 MiB` | Split the file, or read it through `tkbox diff` |
| Frame size (exec stream, guest protocol) | 1 MiB | Clients never see it: Box and the SDK split data into 1 MiB frames. A peer that sends a larger frame is disconnected with `frame larger than 1 MiB` | Nothing; if you see it, report a bug |

## Network

| Limit | Default | What Box says when hit | What to do |
|---|---|---|---|
| Ports | A `host` entry allows 80 and 443 only | The connection is refused with 403 and a notice `example.com:8443 is not on the allowlist` (it then waits for approval) | Add `host:port`, for example `--allow registry.example.com:8443` |
| Private and special addresses | Loopback, RFC 1918, CGNAT, ULA, link-local, multicast, unspecified, the metadata address 169.254.169.254 and the signer's address are refused, also when a name resolves to them | `refused: 169.254.169.254 is link-local (cloud metadata)`; no approval is offered | Nothing in v0: a box cannot reach services on the host's private network. Expose the service on a public address with its own authentication |
| Connect timeout | 10 s | `502: example.com:443 did not accept a connection within 10s` <!-- TODO(lead): confirm the status code and wording agent D uses --> | Check the host is up; not configurable in v0 |
| Idle connection | 5 min with no traffic either way | The connection is closed; the client sees a reset or an unexpected EOF | Use keepalives for long polls and streams; not configurable in v0 |
| Decision time per connection | 5 min | The connection is refused: `no decision within 5m0s` | Answer approvals sooner (they expire after 2 min anyway) |
| Concurrent connections per box | 256 | New connections are refused with 503 `the box has 256 open connections (the limit)` | Lower the agent's or the tool's parallelism |
| Request head | 64 KiB (request line plus headers) | Refused with 431 `request head larger than 64 KiB` | Send large data in the body |
| HTTP versions through inspection | HTTP/1.1 only on inspected connections (bound hosts, or every host with `inspect: all`) | Clients that require HTTP/2 (gRPC) fail the TLS handshake or the ALPN negotiation on those hosts | Let the client fall back to HTTP/1.1; for gRPC, do not bind a secret to that host and keep `inspect: bound` |
| Protocols | HTTP CONNECT (any TCP stream to an allowed host:port, such as TLS) and absolute-form HTTP only; no UDP, no DNS from the box, no SSH | `ssh: Could not resolve hostname github.com`, or a connection refused; UDP (DNS, QUIC, NTP) has no route | Use HTTPS: `git clone https://github.com/...` with a token bound to `github.com`; names are resolved by the proxy on the host |

## Behaviour

| Limit | Default | What Box says when hit | What to do |
|---|---|---|---|
| Writes outside `/workspace` live in RAM | The rootfs is read-only with a memory overlay: `apt-get install`, `/tmp`, `/root` and global `npm i -g` use the box's memory and vanish when it stops | Nothing; a full overlay fails with `No space left on device`, or the OOM killer ends a process | Raise `--memory`, or build an image with your tools already installed |
| Only `/workspace` changes come out | `tkbox diff` and `tkbox apply` see only `/workspace`. Changes elsewhere in the VM are lost at stop | Nothing | Have the agent write its results under `/workspace` |
| Workspace contents | Tracked files and untracked files that are not ignored, from a git work tree. Never `.git`, never ignored files such as `.env` or `node_modules` <!-- TODO(lead): confirm what happens with a workspace that is not a git work tree --> | Nothing: those files are simply absent in the box; `git` commands in `/workspace` fail with `not a git repository` | Install dependencies inside the box; run git on the host after `tkbox apply` |
| Secret inspection | Only hosts with a bound secret are opened (MITM) by default. On other HTTPS hosts the proxy sees only host and port, so it cannot see a placeholder there | Nothing: only the placeholder can leave, never the value | `--inspect all` opens every allowed HTTPS host and blocks placeholders everywhere; it breaks clients that pin certificates |
| Where placeholders are checked | The request line and headers of inspected requests. Request bodies are not scanned, and a secret is swapped only into headers (`#Header`, or any header) | A placeholder in a body leaves as-is (the placeholder, not the value); an API that needs the secret in the body gets the placeholder and rejects it | Use header authentication for bound secrets |
| Image layers | gzip and uncompressed layers; Docker Hub and GHCR, anonymous or with a bearer token from the registry <!-- TODO(lead): confirm registry and credential support with agent C --> | `image python:3.12: layer sha256:… uses zstd compression, which tkbox v0 cannot read; use an image with gzip layers` | Rebuild with gzip layers, for example `docker buildx build --output type=image,compression=gzip …` |
| Image architecture | The host's architecture (linux/amd64 or linux/arm64) | `image foo:1 has no linux/arm64 variant` | Use a multi-architecture image or one built for the host |
| User in the box | Commands run as root (uid 0) in the VM; the VM is the boundary | Nothing | Tools that refuse to run as root need their own switch (Claude Code: `IS_SANDBOX=1`) |
| Signer | A signer must answer, or Box starts no box and refuses every later decision | `unavailable: the Tracekit signer is not answering at <socket>` with hint `start it (tracekit up for a dev signer), or run the daemon with --unrecorded to record nothing` | Start the signer. `--unrecorded` is for debugging only: it records nothing and every box says so |
| Dev signer assurance | `tracekit init --dev` runs the signer as your user | `tracekit verify` prints dev assurance | Run the signer as another user or on another host for CI and production ([SECURITY.md](../SECURITY.md)) |

## Not in v0

These are not built yet. Box says `not_supported` where a request would need one.

| Not in v0 | Today |
|---|---|
| Firecracker jailer and seccomp hardening of the VMM process | Firecracker runs as the daemon's user without the jailer; the VMM interface takes a jailer config so it can be added without API changes |
| Snapshots and restore | Each box boots from its image; a stopped box cannot be resumed |
| Kubernetes RuntimeClass | Run `tkbox daemon` on the node or runner directly |
| gVisor fallback for hosts without KVM | No `/dev/kvm`, no box: `not_supported: this host has no usable /dev/kvm` |
| macOS hosts | The CLI builds on macOS; boxes need Linux. Use the Lima VM ([development.md](development.md)) |
| SSH egress | HTTPS only (see Network) |
| UDP egress | None |
| GPUs | None |
| Windows guests | Linux images only |
