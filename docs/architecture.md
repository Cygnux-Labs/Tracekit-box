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
| Commands | Only through the guest agent's `exec` over vsock, started from the host (`tkbox exec`, the SDK, the action, MCP) and decided before it starts. Processes that command starts inside the VM are not decided one by one | `decide` tool `Bash`, args `{command, cwd, env, stdin}`: the shell-quoted command line (a first word with `=` or that is a shell reserved word is quoted, so the signer's parser sees the program that runs), the working directory, the exec's environment (a placeholder shown as `tkbox_NAME_…`; a value holding a secret's value is refused) and `stdin` (true when the exec has stdin). Stdin known up front (the API's `stdin_data`, at most 1 MiB: MCP's `tkbox_exec`, the SDK's bytes or str up to 1 MiB) is decided with the command as `stdin_sha256` and `stdin_bytes`, plus `stdin_text` when it is UTF-8 of at most 4 KiB (secrets redacted), and exactly that data is the process's stdin; more than 1 MiB, or `stdin_data` and streamed stdin together, is refused. Per-exec env is also in `command` as a leading `env K=V …`, and may not set names that change what runs (any `LD_`, `DYLD_`, `GIT_`, `XDG_`, `PYTHON`, `PERL`, `RUBY`, `NODE_`, `JAVA_`, `JDK_`, `_JAVA_`, `LUA_`, `BASH_` or `NPM_CONFIG_` name bar a few harmless ones, and `PATH`, `HOME`, `SHELLOPTS`, `PS4`, `CLASSPATH`, `MAKEFILES`, `GOFLAGS`, … : the list is in [limits](limits.md)), and the box env is recorded once in the `tkbox.box` created observe (scrubbed, and refused when a value holds a secret's value); the signer's packs apply (TK-D002, TK-A001, …); `complete` with the exit status (and, for streamed stdin (`-i`, larger SDK input, file objects), its `stdin_sha256` and `stdin_bytes`); a completion that can't be recorded is counted in `tkbox.gap` with kind `complete` |
| Network | No NIC. Guest forwarder → vsock 1025 → per-box host proxy (HTTP CONNECT and absolute-form HTTP) | `decide` tool `WebFetch`, args `{"url": "https://host:443"}` per connection (`tcp://host:port` for a tunnel to any other port, since the decision comes before the first byte and an entry that names the port lets any protocol through; `http://host:port` for plain HTTP); the allowlist decides, an unknown host waits for a person (`tkbox approve <id>`; refused at once with `inspect: all`), recorded as observe `tkbox.approval` |
| Secrets | The VM sees placeholders `tkbox_<NAME>_<32 hex>`. The proxy swaps the value into the bound header (default `Authorization`) only on requests to bound hosts. On requests it reads, a placeholder anywhere else (another header, the URL, the body, another host, any plain HTTP request) is blocked, and so is the real value (raw, percent-encoded, JSON-escaped, hex or base64, in any case) where it is not being swapped in; those forms are redacted from response headers, bodies and trailers (other encodings are not: see limits.md) | observe `tkbox.secret.use {name, host}`, `tkbox.secret.leak {name, host, reason}` (never the value) |
| Model calls | Model hosts are egress hosts named by an allow preset or entry (`--allow anthropic`), with the key bound to them as a secret (`ANTHROPIC_API_KEY` → api.anthropic.com); a secret's bound host alone is not a model host | egress records plus observe `tkbox.model.call {host, path, status, bytes}` for requests to a model host the proxy reads |
| Changes out | Guest `diff` → git-format patch of /workspace (computed in the guest from the overlay's upper layer, so the image needs no git), without the fixed list of generated directories (`node_modules`, `.venv`, … ; new files `.gitignore` ignores are in it, and only apply leaves them out), saved as `diff.patch` at stop; the file summary is built on the host from the patch (`GET /v1/boxes/{box}/diff/summary`). `tkbox apply` works only on a stopped box, from that saved patch, before export (a daemon with a signer refuses an unrecorded box's patch; apply it by hand after review). `git apply` never runs on the checkout. Apply parses the patch strictly (binary sections exactly as git reads them), validates every path, refuses copy and rename sections, changes to git-ignored files and writes under the checkout's hooks dir, leaves out new files the checkout ignores and refuses sensitive files without `--allow-sensitive`. Git must read the filtered patch as the parser does (`git apply --numstat -z` and `--summary -z` with an empty git dir and an empty work tree: same paths, binary flags, creations, deletions and modes, nothing on stderr). The result is built in a scratch copy (`git apply` with an empty bare git dir, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_ATTR_NOSYSTEM=1`); after the decisions each path is re-checked against what the signer decided and the checkout must be unchanged since them; then Box writes the files itself (temp file in the same dir with `O_EXCL`/`O_NOFOLLOW`, chmod, rename; symlinks via a temp name; parents checked with lstat, never a symlink; deletions remove only a file or symlink) and names exactly which paths were written if it fails (no rollback; the completions carry `written_paths`). The scratch git also gets an empty `HOME` and `core.attributesFile=/dev/null`, so no user git file changes what it writes. Git commands in the real checkout (`rev-parse`, `check-ignore`, the work-tree check at box create, the workspace build's `ls-files`) run without the caller's `GIT_*` variables, with no global or system config and no system attributes, no pager, and `-c` settings that turn off fsmonitor, the pager, external diff and the untracked cache; `core.excludesFile`, `core.hooksPath` and the system and global `safe.directory` values are read first with `git config -z --get-all` (which runs nothing) and passed back with `-c` | `decide` tool `Write` for every file before anything is written, args `{file_path, sha256, mode, symlink, deleted, patch_sha256}` plus `sensitive: true` for sensitive files |
| Stop | Box timeout, `tkbox stop`, Firecracker pause/kill; the daemon polls the signer's containment state (every 2 s for a box's first minute, then every 15 s, since each poll makes the signer read the run, and at once after a decision that names an incident) and pauses/kills a held or quarantined run, so a hold on a long-running box can take up to about 15 s; egress (the proxy, its open sessions and the vsock egress listener) closes the moment a stop starts, whatever started it (`tkbox stop`, the box timeout, a fail-closed stop, the events log's hard cap, containment), and egress decisions are refused from then on | `close_run` with the reason, at `tkbox export`, `tkbox rm`, daemon shutdown, quarantine or a failed box (a stopped box keeps its run open so that apply can record its decisions) |

Fail closed everywhere: no signer → no daemon (unless it runs with `--unrecorded`, which warns and records nothing); a
signer that stops answering refuses every later decision. Observes Box must keep (secret use and leaks, model calls,
Box rejections and expiries, containment) go through a queue of 4096 and are never dropped silently: if one cannot be
queued or the signer refuses it, the box is stopped and the loss is recorded as observe `tkbox.gap {kind, dropped,
reason}`. A Box approval that allows a connection is recorded synchronously, before the connection uses it; if the
signer refuses it, the connection is refused, the box is stopped and the loss goes into `tkbox.gap` the same way, or, if
even that fails, the run is closed with the loss as its reason. A `complete` the signer refuses or never answers is
counted into `tkbox.gap` too, with kind `complete` (it does not stop the box). Lifecycle observes are sent synchronously, and a Box approval is
recorded before any connection uses it. Box's own egress refusal observes are limited to 20 a second per
box, with a summary of the rest.

### Run lifecycle

`register_run` at create. `tkbox stop` keeps the run open so that `tkbox apply` records its `Write` decisions in the
same run; `tkbox export` and `tkbox rm` close it, as do daemon shutdown (every open run), quarantine and a failed box.
Before closing, the daemon waits up to 15 s for the box's in-flight decisions. The run token is held only in the
daemon's memory and never persisted: after a daemon crash the run stays open in the signer, and that box can be
neither applied nor exported (export refuses at once). After a clean restart, boxes whose runs were closed still
export, but apply is refused for recorded boxes without a live run.

## Protocols

### vsock

Firecracker exposes the guest's vsock as a Unix socket on the host (`boxes/<id>/vsock.sock`).

- **1024 agent RPC** (host → guest): connect to `vsock.sock`, write `CONNECT 1024\n`, read `OK <port>\n`, then frames.
- **1025 egress** (guest → host): the guest dials CID 2 port 1025; Firecracker connects to `vsock.sock_1025`, where
  the box's proxy listens. Raw bytes (HTTP proxy protocol), no framing.
- **1026 boot config** (guest → host): the guest dials CID 2 port 1026 (`vsock.sock_1026`), sends one
  `{"op":"boot_config"}` frame and receives the `BootConfig` frame. The port is served once: after the guest has
  read its config, the listener is closed.

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
`ExecEvent` frames for decision and approval states; stdin known up front travels in the request as `stdin_data`
(base64, at most 1 MiB) instead of stdin frames. `GET /v1/boxes/{box}/diff` returns the patch, with the file summary
in `X-Tkbox-Diff-Summary` only when that JSON is at most 8 KiB (else `X-Tkbox-Diff-Summary-Omitted: 1`) and the
patch's sha256 in `X-Tkbox-Diff-Sha256`; `GET /v1/boxes/{box}/diff/summary` always returns the summary as JSON. A
summary's `patch_sha256` is the sha256 of the patch it describes; clients compare it with the patch they hold (for a
running box the two reads are two guest diffs), read both once more on a mismatch, then fail.

## Disks

| Disk | Device | Mode | Built from |
|---|---|---|---|
| rootfs | `/dev/vda` | ro | an OCI image (our own registry v2 puller, any HTTPS registry, public images: anonymous or with an anonymous bearer token), layers flattened with whiteouts, `/sbin/tkbox-guest` added, `mkfs.ext4 -d`; cached by manifest digest + guest binary digest |
| workspace base | `/dev/vdb` | ro | the host directory: tracked + untracked-not-ignored files in a git work tree, every file outside git; never `.git`, never credential files (`.env` and `.env.*` other than `.env.example`, `.env.sample`, `.env.template` and `.env.dist`; `*.pem`, `*.key`, `.netrc`, `.ssh/`, … even when not ignored; `.envrc` is copied); an empty directory without a workspace |
| workspace upper | `/dev/vdc` | rw | empty ext4 sized by `limits.disk` |

The guest mounts the rootfs read-only with a tmpfs overlay on top (writes to `/usr`, `/tmp`, … live in RAM, up to half
the box's memory per tmpfs, and vanish with the box), and `/workspace` as an overlay of the base and the upper disk.
`diff` walks the upper layer, so it is exact and cheap.

## Egress safety

- DNS is resolved once on the host; loopback, private (RFC 1918, CGNAT, ULA), link-local, metadata (169.254.169.254
  and the other clouds' metadata addresses), multicast, documentation and other special ranges, unspecified, this
  host's own interface addresses and the ranges given with `tkbox daemon --egress-block` are refused; the proxy dials
  the resolved IP, so a name cannot rebind between the check and the dial. IPv4-mapped and NAT64 addresses are
  unwrapped first. On EC2, GCE, Azure and GitHub-hosted runners the host's NAT'd public IP is on no interface, so it is
  refused only when it is passed with `--egress-block`.
- This host's own addresses are read live (at most 5 s old) on every dial, so an address gained after a box started is
  refused too.
- An allowlist entry `host` allows HTTPS on 443 (CONNECT) and plain HTTP on 80 (absolute-form requests, which the
  proxy reads); `host:port` allows that port only. `CONNECT` to port 80 is refused: plain HTTP must use the absolute
  form (`http_proxy`), where Box writes the Host header.
- Every HTTPS tunnel must start with a TLS ClientHello whose server name (SNI) equals the CONNECT host (a CONNECT to an
  IP literal may omit SNI), with exactly one host name in its server_name list, checked again after a HelloRetryRequest;
  ECH ClientHellos are refused. That stops fronting by SNI. Inside an uninspected tunnel the `Host` header or HTTP/2
  `:authority` can still name another site on the same server or CDN; on inspected hosts Box refuses any request that
  does not name the tunnel's host. A tunnel
  that is not TLS is allowed only to an allow entry that names the port (`host:port`), and such an entry lets any
  protocol through to that port.
- MITM only for hosts with a bound secret (or every allowed host with `inspect: all`, which then refuses hosts and ports off the
  allowlist at once), with a per-box ECDSA P-256 CA, name-constrained to those hosts, whose certificate reaches the
  guest through the boot config. A box with `inspect: all`, no allow entries and no secrets gets a CA that may
  impersonate no host: its only DNS name constraint is the reserved `invalid`, and every IP address is excluded. The guest exports `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`,
  `GIT_SSL_CAINFO` and `CURL_CA_BUNDLE`. The MITM leaf offers HTTP/1.1 only; upstream TLS is verified against the
  host's roots. Requests to bound hosts go upstream with `Accept-Encoding: identity`, so the proxy can redact secret
  values from responses (an encoded body a bound host sends anyway is decoded and redacted, or refused with 502).
- Box's own refusals are recorded in the signer at most 20 a second per box, with a summary observe for the rest.
- At most 16 Box approvals may be pending per box; a connection that would need another is refused at once. An
  approval is withdrawn when the last connection waiting on it leaves (`Approval.Waiters` counts them).
- Presets: `github`, `pypi`, `npm`, `anthropic`, `openai`, `claude-code`, `apt-ubuntu`, `debian`, `go-proxy`; the host
  lists are in [config.md](config.md#allow-entries).

## Tracekit

`internal/tracekit` speaks the released 1.4.2 signer RPC directly (newline-delimited JSON over the signer's Unix
socket, identity from peer credentials; the signer must be on the daemon's host). One run per box: `register_run` at
create, `decide`/`approval_*`/`complete` for every command started from the host, connection and file write,
`observe` for lifecycle, secrets, model calls, Box approvals, containment and lost records (`tkbox.gap`), `close_run`
at export, removal, daemon shutdown, quarantine or failure. `tkbox export` runs
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
boxes/<id>/             box.json (never a secret value or the run token), fc.sock, vsock.sock, console.log,
                        events.ndjson (egress lines to 64 MiB, all lines to 256 MiB),
                        workspace-base.ext4, workspace-upper.ext4,
                        diff.patch and diff.json (the patch and its file summary, saved at stop)
run/tkbox.sock          the API (0600; run/ is 0700)
```
