# Tracekit Box: architecture

Tracekit Box gives every AI agent job on a Linux server or CI runner a locked room: a Firecracker micro-VM. The ways
out of the room (the network, secrets, model calls, code changes, and the commands started in it from the host) are
doors Box controls, and every door is decided and signed by a Tracekit signer the agent cannot reach. Each job ends
with one `.tkb` bundle anyone can verify offline with `tracekit verify`. What the agent does inside the room without
crossing a door, including the processes it starts itself, is not recorded.

## Trust domains

```
 runner / server host (trusted)                          micro-VM (untrusted: the agent lives here)
 ┌───────────────────────────────────────────┐          ┌───────────────────────────────────────────┐
 │ tkbox (one Go binary)                     │  vsock   │ tkbox-guest (PID 1, static Go)            │
 │  ├ daemon: boxes, limits, kill            │◀────────▶│  ├ agent RPC: exec, files, diff           │
 │  ├ vmm: Firecracker API client            │  :1024   │  ├ egress forwarder 127.0.0.1:3128 ──┐     │
 │  ├ egress proxy (per box) ◀───────────────┼──:1025───┼──────────────────────────────────────┘     │
 │  │   allowlist, private-IP block,         │          │  ├ boot config fetch ◀── :1026             │
 │  │   secret swap (MITM only bound hosts)  │          │  └ NO network card: the proxy is the only  │
 │  ├ tracekit client ──▶ Tracekit signer    │          │    way out                                 │
 │  ├ image builder (OCI → ext4)             │          │ rootfs: ext4 from an OCI image (ro) +      │
 │  └ HTTP API on a unix socket, CLI, MCP    │          │ overlay tmpfs; /workspace: overlay of a ro │
 └───────────────────────────────────────────┘          │ base ext4 and a rw upper ext4              │
                                                        └───────────────────────────────────────────┘
```

- **Host** (trusted): `tkbox daemon` and the Tracekit signer, on the same host (the daemon reaches the signer over its
  Unix socket only). The signer runs in another trust domain from the agent: the agent is inside a VM with no network
  card, so it can reach neither the signer's socket nor the daemon's. Firecracker runs as the daemon's user with its
  default seccomp filter and no jailer.
- **Guest** (untrusted): everything inside the VM, including `tkbox-guest`. The host never trusts what the guest says
  about itself; it only trusts what it mediates (the doors).

## Doors

Every door writes to the signer (one Tracekit run per box).

| Door | Mechanism | Tracekit record (1.4.2 RPC) |
|---|---|---|
| Commands | Only through the guest agent's `exec` over vsock, started from the host (`tkbox exec`, the SDK, the action, MCP) and decided before it starts. Processes that command starts inside the VM are not decided one by one | `decide` tool `Bash` with the shell-quoted command line, the working directory, the exec's environment (placeholders redacted) and whether stdin was given; the signer's packs apply (TK-D002, TK-A001, …); `complete` with the exit status |
| Network | No NIC. Guest forwarder → vsock 1025 → per-box host proxy (HTTP CONNECT and absolute-form HTTP) | `decide` tool `WebFetch`, args `{"url": "https://host:port"}` per connection; the allowlist decides, an unknown host waits for a person (`tkbox approve <id>`; refused at once with `inspect: all`), recorded as observe `tkbox.approval` |
| Secrets | The VM sees placeholders `tkbox_<NAME>_<32 hex>`. The proxy swaps the value into the bound header (default `Authorization`) only on requests to bound hosts. On requests it reads, a placeholder anywhere else (another header, the URL, the body, another host, any plain HTTP request) is blocked, and so is the real value where it is not being swapped in; the value is redacted from responses | observe `tkbox.secret.use {name, host}`, `tkbox.secret.leak {name, host, reason}` (never the value) |
| Model calls | Model hosts are egress with a bound key (`ANTHROPIC_API_KEY` → api.anthropic.com) | egress records plus observe `tkbox.model.call {host, path, status, bytes}` for requests the proxy reads |
| Changes out | Guest `diff` → git-format patch of /workspace (computed in the guest from the overlay's upper layer, so the image needs no git), without ignored paths and generated directories, saved as `diff.patch` at stop. `tkbox apply` (stopped box, before export) validates every path, refuses copy and rename sections and, without `--allow-sensitive`, sensitive files, and runs `git apply` isolated from the host's and the repository's git config | `decide` tool `Write` for every file before anything is written, carrying the file path, the patch digest, the file's content hash, its mode and whether it is a symlink |
| Stop | Box timeout, `tkbox stop`, Firecracker pause/kill; the daemon polls the signer's containment state and pauses/kills a held or quarantined run | `close_run` with the reason, at `tkbox export`, `tkbox rm`, daemon shutdown, quarantine or a failed box (a stopped box keeps its run open so that apply can record its decisions) |

Fail closed everywhere: no signer → no daemon (unless it runs with `--unrecorded`, which warns and records nothing); a
signer that stops answering refuses every later decision; an event Box must keep (secret use or leak, approval,
containment, lifecycle) that it cannot record stops the box.

## Protocols

### vsock

Firecracker exposes the guest's vsock as a Unix socket on the host (`boxes/<id>/vsock.sock`).

- **1024 agent RPC** (host → guest): connect to `vsock.sock`, write `CONNECT 1024\n`, read `OK <port>\n`, then frames.
- **1025 egress** (guest → host): the guest dials CID 2 port 1025; Firecracker connects to `vsock.sock_1025`, where
  the box's proxy listens. Raw bytes (HTTP proxy protocol), no framing.
- **1026 boot config** (guest → host): the guest dials CID 2 port 1026 (`vsock.sock_1026`), sends one
  `{"op":"boot_config"}` frame and receives the `BootConfig` frame.

One connection per request.

### Frames (internal/proto)

`[type u8][len u32 BE][payload]`, payload ≤ 1 MiB. Types: 0 JSON request/header, 1 stdin, 2 stdout, 3 stderr,
4 exit (JSON `{"code":n,"signal":"",…}`), 5 error (JSON), 6 stdin EOF, 7 signal (JSON). Ops: `ping`, `exec`,
`read_file`, `write_file`, `stat`, `diff`, `shutdown`; `boot_config` on port 1026. Exchanges are documented in
`internal/proto/ops.go`. The daemon API exposes `exec` and `diff`; it has no route for reading or writing single
files.

### Boot config

Box-specific state reaches the guest over vsock at boot, never baked into the image, so images stay cacheable by
digest: box id, env (image env + box env + secret placeholders + proxy and CA variables), proxy listen address, the
box's CA certificate, the workspace devices, limits and the host's clock.

### Daemon API (internal/api)

HTTP on `run/tkbox.sock` (0600 in a 0700 dir; the daemon also checks the peer uid is its own or root). `exec` upgrades
the connection (`Upgrade: tkbox-exec/1`) and then speaks the same frames as the guest protocol, plus JSON
`ExecEvent` frames for decision and approval states.

## Disks

| Disk | Device | Mode | Built from |
|---|---|---|---|
| rootfs | `/dev/vda` | ro | an OCI image (our own registry v2 puller, any HTTPS registry, public images: anonymous or with an anonymous bearer token), layers flattened with whiteouts, `/sbin/tkbox-guest` added, `mkfs.ext4 -d`; cached by manifest digest + guest binary digest |
| workspace base | `/dev/vdb` | ro | the host directory: tracked + untracked-not-ignored files in a git work tree, every file outside git; never `.git`, never credential files (`.env*`, `*.pem`, `*.key`, `.netrc`, `.ssh/`, … even when not ignored); an empty directory without a workspace |
| workspace upper | `/dev/vdc` | rw | empty ext4 sized by `limits.disk` |

The guest mounts the rootfs read-only with a tmpfs overlay on top (writes to `/usr`, `/tmp`, … live in RAM, up to half
the box's memory per tmpfs, and vanish with the box), and `/workspace` as an overlay of the base and the upper disk.
`diff` walks the upper layer, so it is exact and cheap.

## Egress safety

- DNS is resolved once on the host; loopback, private (RFC 1918, CGNAT, ULA), link-local, metadata (169.254.169.254
  and the other clouds' metadata addresses), multicast, documentation and other special ranges, unspecified and this
  host's own interface addresses are refused; the proxy dials the resolved IP, so a name cannot rebind between the
  check and the dial. IPv4-mapped and NAT64 addresses are unwrapped first.
- An allowlist entry `host` allows HTTPS on 443 (CONNECT) and plain HTTP on 80 (absolute-form requests, which the
  proxy reads); `host:port` allows that port only. `CONNECT` to port 80 is refused.
- Every HTTPS tunnel's TLS server name (SNI) must equal the CONNECT host, and ECH ClientHellos are refused, so an
  allowed host cannot front for another. A tunnel that is not TLS is allowed only to a `host:port` the allowlist names
  explicitly.
- MITM only for hosts with a bound secret (or every allowed host with `inspect: all`, which then refuses hosts off the
  allowlist at once), with a per-box ECDSA P-256 CA, name-constrained to those hosts, whose certificate reaches the
  guest through the boot config. The guest exports `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`,
  `GIT_SSL_CAINFO` and `CURL_CA_BUNDLE`. The MITM leaf offers HTTP/1.1 only; upstream TLS is verified against the
  host's roots. Requests to bound hosts go upstream without `Accept-Encoding`, so the proxy can redact the secret's
  value from responses.
- Bursts of refusals are rate-limited and summarised in the box's events.
- Presets: `github`, `pypi`, `npm`, `anthropic`, `openai`, `claude-code`, `apt-ubuntu`, `debian`, `go-proxy`; the host
  lists are in [config.md](config.md#allow-entries).

## Tracekit

`internal/tracekit` speaks the released 1.4.2 signer RPC directly (newline-delimited JSON over the signer's Unix
socket, identity from peer credentials; the signer must be on the daemon's host). One run per box: `register_run` at
create, `decide`/`approval_*`/`complete` for every command started from the host, connection and file write,
`observe` for lifecycle, secrets, model calls and Box approvals, `close_run` at export or removal. `tkbox export` runs
`tracekit signer trust` and `tracekit export --v2` to produce the bundle and its trust file (`run.tkb` →
`run.trust.json`).

Box approvals: 1.4.2 cannot open an approval without a policy `ask`, so for hosts off the allowlist Box holds the
connection itself until a person runs `tkbox approve <id>` on the host (outside the VM), and records the approver and
the decision as observe `tkbox.approval`.

## Packages

| Package | Role |
|---|---|
| `internal/proto`, `internal/api` | The contracts: frame format and guest operations, daemon API types |
| `internal/vmm`, `internal/assets` | Firecracker client, VM lifecycle, vsock dial/listen; the pinned kernel and Firecracker downloads |
| `cmd/tkbox-guest`, `internal/guest`, `internal/agentrpc` | PID 1 init, agent RPC server, exec, files, diff, egress forwarder, boot config; the host-side RPC client |
| `internal/image` | OCI pull and cache, layer flattening, ext4 builds, the workspace image |
| `internal/egress` | The proxy: allowlist and presets, address checks, per-box CA, secret swap and leak blocking, events |
| `internal/tracekit` | Signer RPC client, run lifecycle, the decision gate, export |
| `internal/daemon`, `internal/config`, `cmd/tkbox` | Box manager, HTTP API, CLI, tkbox.yaml, limits, kill switch, MCP server |
| `action/`, `sdk/python` | The GitHub Action and the Python SDK |

Every boundary has an interface and a fake (`vmm.Launcher`, `agentrpc.Guest`, `image.Builder`, `egress.Decider`,
`tracekit.Client`/`Run`), so packages test without KVM; `e2e/` runs everything on a host with KVM.

## State

`/var/lib/tkbox` as root, else `$XDG_STATE_HOME/tkbox` (default `~/.local/state/tkbox`):

```
images/                 rootfs ext4 files by digest, assets/ (kernel, firecracker)
boxes/<id>/             box.json, fc.sock, vsock.sock, console.log, events.ndjson,
                        workspace-base.ext4, workspace-upper.ext4,
                        diff.patch and diff.json (the patch and its file summary, saved at stop)
run/tkbox.sock          the API (0600; run/ is 0700)
```
