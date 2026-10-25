# Limits

Every limit of Tracekit Box v0 is on this page, with its default, what Box says when you hit it, and what to do. When
Box refuses something, the CLI prints the message as `tkbox: <message>` and, when there is one, a hint that says what to
do on a second `tkbox:` line; the [Python SDK](../sdk/python) raises `LimitError` (or `TimedOut`, `Denied`,
`Unavailable`) with `.hint` set. Messages below show example values where the real message has the box's own.

Defaults apply when neither `tkbox run` flags nor [tkbox.yaml](config.md) set a value. Sizes on the command line need a
unit (`--memory 4GiB`, `--disk 16GiB`) and durations always do (`90m`, `2h`).

## Box resources

| Limit | Default | What Box says when hit | What to do |
|---|---|---|---|
| vCPUs per box | 2 (1 to 32) | Out of range at create: `limits.cpus 40: use 1..32`. Inside the box, processes just get N CPUs | `--cpus N` or `limits.cpus` |
| Memory per box | 2GiB (128MiB to 64GiB) | Out of range at create: `limits.memory 64MiB: use 128MiB..64GiB`. When the box runs out, the guest kernel's OOM killer ends a process: the exec exits 137 (SIGKILL) and Box adds no message of its own; the kernel's OOM lines are in `boxes/<id>/console.log` | `--memory 4GiB` or `limits.memory`. Files written outside `/workspace` count against memory (see the next row) |
| Writes outside `/workspace` | Each of the rootfs overlay, `/tmp`, `/run` and `/dev/shm` is a tmpfs that can grow to half the box's memory | `No space left on device`, or the OOM killer ends a process | Raise `--memory`, or use an image with your tools already installed |
| Workspace disk (writes to `/workspace`) | 4GiB (64MiB to 1TiB) | Out of range: `limits.disk 32MiB: use 64MiB..1TiB`. When full, the write fails inside the box with `No space left on device` | `--disk 16GiB` or `limits.disk`; keep build output and caches out of `/workspace` |
| Box lifetime | 1h (10s to 168h) | The box is stopped with the reason `timeout: the box reached its 1h0m0s limit (raise it with --timeout)`, and its patch is saved as with `tkbox stop`. A command still running ends with `the box stopped while the command ran` (exit 125) | `--timeout 2h` or `limits.timeout` |
| Time per exec | 30m (1s to 24h) | `the command timed out and was killed`: the process group is killed with SIGKILL and `tkbox exec` exits 124 | `tkbox exec --timeout 2h`, or `limits.exec_timeout` in tkbox.yaml for every exec |
| Boxes alive per daemon | 8. Boxes that are creating, running, paused or stopping count; stopped and failed boxes do not | `8 boxes are alive and the daemon's limit is 8`, hint ``stop one with `tkbox stop <box>`, or restart the daemon with a higher --max-boxes`` | `tkbox stop` a box you are done with, or `tkbox daemon --max-boxes N` (1 to 1024) |
| Concurrent execs per box | 64 | `64 execs already running (limits.max_procs)`, hint `at most 64 commands run at once in a box; wait for one to finish` | Wait for one to finish; run fewer background processes per exec |
| Output per exec (stdout and stderr together) | 256 MiB | The rest is dropped. v0 prints no message about it | Write large output to a file in the box and read the part you need |
| Console log | The first 8 MiB per box (`boxes/<id>/console.log`) | The log ends with `[tkbox: console output reached the 8388608 byte cap; the rest is dropped]` | The console log is for boot problems; what happened at the doors is in `tkbox events <box>` |
| Guest boot | 60 s for the guest agent to answer | `the guest did not come up within 1m0s (…): read <state dir>/boxes/<id>/console.log`, or `the VM exited while booting (…)` | Read the console log; it is usually the image (no usable `/bin/sh`, wrong architecture) or the host (KVM) |

## Commands, approvals and changes

| Limit | Default | What Box says when hit | What to do |
|---|---|---|---|
| Approval wait (a host off the allowlist) | 2 min (`tkbox daemon --approval-timeout`, 1s to 4m) | While it waits: ``egress to https://example.com:443 is waiting for approval: run `tkbox approve apr-1a2b3c4d` on the host, or add `--allow example.com` ``. Unanswered: `approval apr-1a2b3c4d for https://example.com:443 expired after 2m0s`, and the connection is refused with 403 | Answer sooner with `tkbox approve <id>`, approve for the whole box with `tkbox approve <id> --box`, or put the host on the allowlist. In CI nobody answers: allow what the job needs |
| Pending approvals per box | 16 | Further connections that would need an approval are refused at once until one is answered or expires | Answer or reject the pending ones (`tkbox approvals`); put the hosts the job needs on the allowlist |
| Decision time per connection | The approval wait plus 30 s (2m30s) | 403 `no decision within 2m30s` | Answer approvals sooner |
| Signer approval (a command the signer's policy holds) | No limit of its own: Box asks the signer in 300 s calls until it answers, or until the exec is abandoned or the box stops | `tkbox: waiting for approval <id>: approve with: tracekit approvals approve <id>`. If it is rejected or expires: `denied: held by Tracekit policy (…) and not approved: expired`, exit 126 | Answer with `tracekit approvals approve <id>` on the signer's host |
| Command line size | 1 MiB: the daemon's request body and the signer's request both stop there | A command line near 1 MiB is refused; v0 reports it as the signer not answering: `the Tracekit signer did not answer, so nothing runs (fail closed): tracekit signer: quota_exceeded: the decide request is … bytes, over the signer's limit of 1048576 bytes per request; it was not sent` | Write long scripts or data to a file in `/workspace` and run the file |
| Task text | 64 KiB | `task is over 64 KiB`, hint `shorten the task text` | Put the details in a file in the workspace and refer to it |
| Box names | `[a-z0-9][a-z0-9-]{0,62}`, not starting with `tkb-`, unique among the daemon's boxes in any state | `name "Demo" is not valid`, hint `use lower case letters, digits and -, starting with a letter or digit (at most 63)`; `a box named "demo" already exists (tkb-…)` | Pick another name, or `tkbox rm` the old box |
| Workspace patch (`tkbox diff`, `tkbox apply`) | 64 MiB. Paths `.gitignore` ignores and generated directories (`node_modules`, `__pycache__`, `.venv`, `venv`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.gradle`, `.next`, `.cache`) are left out and do not count | On a running box: `the workspace diff is over 64 MiB`, hint `keep build output and large files out of /workspace (write them under /tmp)`. At stop the patch is not saved and `tkbox stop` says so; later `tkbox diff` and `tkbox apply` say `box demo (stopped) has no saved diff` | Remove build output and other large generated files from `/workspace` before stopping the box |
| Text diffs | Files over 16 MiB | They appear in the patch as binary changes | Nothing |
| When `tkbox apply` works | On a stopped box, from the patch saved at stop, and before `tkbox export`; not on a box from before a daemon restart | Refused, with a hint to stop the box first, or (after export or a restart) to review and apply the saved patch `<state dir>/boxes/<id>/diff.patch` by hand | `tkbox stop`, then `tkbox apply`, then `tkbox export` |
| What `tkbox apply` writes | Every file the signer allows, or nothing. Copy and rename sections are refused. Changes to `.gitignore`, `.gitattributes`, `.gitmodules`, `tkbox.yaml`, `.husky/**` and `.github/workflows/**` need `--allow-sensitive` | `tkbox: denied by the signer: <path>` for each denied file, then `2 files were refused, so nothing was applied`; unsafe paths: `unsafe paths in the patch: …` | Review the patch (`tkbox diff`); pass `--allow-sensitive` only after reading those files' changes |
| Events (`tkbox events`, `boxes/<id>/events.ndjson`) | 64 MiB per box. Bursts of egress refusals are summarised | Events Box must keep (secret use and leaks, approvals, containment, lifecycle) are never dropped: if Box cannot record one, it stops the box | Nothing; a box stopped this way says why in `tkbox ls` |
| Export | 60 s for the run to be final and verified in the signer | `tracekit export of run …: not final and verified within 1m0s: …` | Check the signer (`tracekit status`) and run `tkbox export` again |
| Frame size (exec stream, guest protocol) | 1 MiB | Clients never see it: Box and the SDK split data into 1 MiB frames. A peer that sends a larger frame is disconnected with `proto: frame larger than 1 MiB` | Nothing; if you see it, report a bug |

## Network

| Limit | Default | What Box says when hit | What to do |
|---|---|---|---|
| Ports | A `host` entry allows HTTPS on 443 and plain HTTP on 80; `host:port` allows that port only | A port that is not allowed is treated like a host off the allowlist: it waits for approval, and the notice suggests `--allow host:port` | Add `host:port`, for example `--allow registry.example.com:8443` |
| HTTPS tunnels | The TLS server name (SNI) must equal the host the tunnel was opened for; encrypted ClientHellos (ECH) are refused; `CONNECT` to port 80 is refused | The connection fails during the TLS handshake, and the box's events record the refusal | Use the real host name; plain `http://` goes through the proxy as a normal proxy request, which `http_proxy` already does |
| Tunnels that are not TLS | Only to a `host:port` the allowlist names explicitly (not a bare host, a wildcard or a preset) | The tunnel is refused, and the box's events record it | Add the exact `host:port` |
| Private and special addresses | Loopback, RFC 1918, CGNAT, ULA, link-local, multicast, documentation and other special ranges, the cloud metadata addresses (169.254.169.254, fd00:ec2::254, 169.254.170.2, 100.100.100.200, 168.63.129.16 and others) and this host's own addresses are refused, also when a name resolves to them | 403 `it resolves to a link-local address, which Box never connects to`, hint `Box connects only to public addresses; use a public host.` For an allowlisted name or an IP literal this comes at once, with no approval offered; for a name off the allowlist, the address is checked after a person approves it | Nothing in v0: a box cannot reach services on the host or its private network. Expose the service on a public address with its own authentication |
| Connect timeout | 10 s (name resolution and TLS handshakes also 10 s each) | 502 `could not connect: …`, hint `The host did not accept the connection; try again later.`; a name that does not resolve: `could not resolve the host name` | Check the host is up; not configurable in v0 |
| Idle connection | 5 min with no traffic either way (paused while a decision is pending) | The connection is closed; the client sees a reset or an unexpected EOF | Use keepalives for long polls and streams; not configurable in v0 |
| Concurrent connections per box | 256 (no setting in v0) | 503 `the box already has 256 open connections (MaxConns)` | Lower the agent's or the tool's parallelism; reuse keep-alive connections |
| Request head | 64 KiB (request line plus headers) | 431 `the request head is larger than 65536 bytes (MaxHeaderBytes)`, hint `Send fewer or smaller headers (large cookies are the usual cause).` | Send large data in the body |
| Upstream response head | 1 MiB, on connections the proxy reads | 502 `the host sent no valid response: its response head is larger than 1048576 bytes` | Nothing; the host is misbehaving |
| HTTP versions through inspection | HTTP/1.1 only on inspected connections (bound hosts, or every allowed host with `inspect: all`) | Clients that require HTTP/2 (gRPC) fail the ALPN negotiation on those hosts | Let the client fall back to HTTP/1.1; for gRPC, do not bind a secret to that host and keep `inspect: bound` |
| `inspect: all` and hosts off the allowlist | Refused at once, with no approval: the box's CA may impersonate only allowed hosts | 403 `Box must inspect this host but the box CA may not impersonate it`, hint `Add the host to the box's allow list so the CA covers it.` | Put the host on the allowlist, or use `inspect: bound` |
| Protocols | HTTP `CONNECT` and absolute-form HTTP only; no UDP, no DNS from the box, no SSH | `ssh: Could not resolve hostname github.com`, or a connection refused; UDP (DNS, QUIC, NTP) has no route | Use HTTPS: `git clone https://github.com/...` with a token bound to `github.com`; names are resolved by the proxy on the host |

## Secrets

| Limit | Default | What Box says when hit | What to do |
|---|---|---|---|
| Secret names | `[A-Z_][A-Z0-9_]*`, and not one of the proxy and CA variables Box sets (`HTTP_PROXY`, `SSL_CERT_FILE`, …) | `secret "gh": the name is the env var the box sees; use upper case, digits and _ (e.g. GITHUB_TOKEN)` | Use an upper-case name |
| Secret values | Not empty, at most 64 KiB, one line (no line break or NUL) | `secret GH: the value is over 64 KiB`; `secret GH: the value has a line break or NUL; a header value can't carry one` | Secrets are header values; for a file with a trailing newline, `from_file` drops it |
| Secret hosts | Exact host names: no ports, no wildcards | Refused when the box is created, naming the host | List each host the secret is for |
| Where a secret is swapped in | Only into its bound header (default `Authorization`), only on requests to its hosts that the proxy reads | A placeholder in the body: 403 `a placeholder for secret GH is in the request body; Box swaps secrets only into request headers`, hint `Send the secret in its bound header.` A placeholder in another header or to another host: blocked, `tkbox.secret.leak` | Use header authentication for bound secrets, and name the header with `#Header` or `header:` |
| Which requests are checked for placeholders | Requests to bound hosts and plain HTTP requests (request line, headers and body); with `inspect: all`, every allowed HTTPS host too | On other HTTPS hosts the proxy sees only the host, port and TLS server name: nothing is detected, and only the placeholder can leave, never the value | `--inspect all` checks every allowed HTTPS host; it breaks clients that pin certificates |
| Responses from bound hosts | The real value is redacted from responses (headers, body, trailers); requests to bound hosts are sent upstream without `Accept-Encoding`, so responses arrive uncompressed | Nothing | Nothing |

## Images

| Limit | Default | What Box says when hit | What to do |
|---|---|---|---|
| Registries | Any registry over HTTPS (Docker Hub, GHCR, …), public images only: anonymous pulls, including the anonymous bearer-token flow | `registry ghcr.io wants "Basic" credentials for org/img: Box pulls public images anonymously (private registries are not supported in v0)` | Use a public image, or push the image to a public repository |
| Layer format | tar and tar+gzip layers (OCI and Docker media types) | `zstd-compressed layers are not supported in v0; use an image pushed with gzip layers (docker buildx build --output type=registry,compression=gzip,force-compression=true)` | Rebuild with gzip layers |
| Image size | Manifest 4 MiB, config 8 MiB, 128 layers, 4 GiB per layer, 16 GiB for all layers, 1,000,000 files and directories | For example `python:3.12 has 140 layers, over the limit of 128 (Layers); squash the image` | Use a smaller image, or squash it |
| Image architecture | The host's: linux/amd64 or linux/arm64 | `foo:1 has no linux/arm64 image (it has: linux/amd64); pick an image that publishes linux/arm64` | Use a multi-architecture image or one built for the host |

## Behaviour

| Limit | Default | What Box says when hit | What to do |
|---|---|---|---|
| Only `/workspace` changes come out | `tkbox diff` and `tkbox apply` see only `/workspace`. Changes elsewhere in the VM are lost at stop | Nothing | Have the agent write its results under `/workspace` |
| Workspace contents | In a git work tree: tracked files and untracked files that are not ignored, never `.git`. Outside git: every file except `.git`. Without `--workspace`: an empty `/workspace` | Nothing: other files are simply absent; `git` commands in `/workspace` fail with `not a git repository` | Install dependencies inside the box; run git on the host after `tkbox apply` |
| Credential files | Never copied into the box, git or not, ignored or not: `.env` and `.env.*` (except `.env.example`, `.env.sample`, `.env.template`, `.env.dist`), `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.tfstate`, `*.tfstate.backup`, `*.tfvars`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.pgpass`, `.htpasswd`, `.dockercfg`, and the directories `.ssh`, `.aws`, `.gnupg`, `.kube`, `.docker`, `.azure`, `.config/gcloud` | Only the daemon's log says so: `workspace …: left out 2 credential file(s) the box must not see: …` | Give the box what it needs as a bound secret instead |
| Workspace size | 100,000 files and 4 GiB | `workspace … has more than 100000 files (WorkspaceFiles); add generated or vendored dirs to .gitignore, or point the box at a smaller directory` | Ignore generated and vendored directories, or use a smaller directory |
| User in the box | Commands run as root (uid 0) in the VM; the VM is the boundary | Nothing | Tools that refuse to run as root need their own switch (Claude Code: `IS_SANDBOX=1`) |
| Signer | A Tracekit 1.4.2 signer on the same host, reached over a Unix socket only. It must answer, or Box starts no daemon and refuses every later decision | `Tracekit Box reaches its signer over a Unix socket only; … is not one`. At daemon start: ``no Tracekit signer answering at …: start one with `tracekit up`, or pass --unrecorded to run boxes that record nothing``. Later: `the Tracekit signer did not answer, so nothing runs (fail closed): …` | Start the signer on this host. `--unrecorded` is for debugging only: it records nothing and every box says so |
| Dev signer assurance | `tracekit init --dev` runs the signer as your user | `tracekit verify` prints dev assurance | For CI and production, run the signer as another user on the daemon's host ([SECURITY.md](../SECURITY.md)) |
| GitHub Action assurance | The action creates a dev signer and its trust file in the same job | `tracekit verify` prints dev assurance, and the trust file proves only that the bundle was not changed after the job | For stronger assurance, run `tkbox` on a host you control with a system-mode signer, and keep its trust file outside that host |
| Firecracker and the guest kernel | The daemon downloads Firecracker v1.17.0 and kernel 6.1.155 on its first start, checks them by SHA-256 and caches them in `<state dir>/images/assets` | ``fetch firecracker v1.17.0: … (pass --firecracker/--kernel to use local files)``; a checksum mismatch installs nothing | Give the host HTTPS access to GitHub and S3, or pass `--firecracker FILE --kernel FILE` |
| KVM | `/dev/kvm`, readable and writable by the daemon's user | The daemon does not start: `this host can't run boxes: vmm: /dev/kvm does not exist: …` or `vmm: cannot open /dev/kvm read-write as uid 1000: add the user to the kvm group …` | Use a host with KVM, or add the user to the `kvm` group |

## Not in v0

These are not built yet.

| Not in v0 | Today |
|---|---|
| The Firecracker jailer | Firecracker runs as the daemon's user with its default seccomp filter, but without the jailer's chroot, namespaces and cgroups; the VMM interface takes a jailer config so it can be added without API changes |
| A remote signer | The signer must be on the daemon's host (Unix socket only) |
| Private registries | Public images only |
| Snapshots and restore | Each box boots from its image; a stopped box cannot be resumed |
| Kubernetes RuntimeClass | Run `tkbox daemon` on the node or runner directly |
| gVisor fallback for hosts without KVM | No `/dev/kvm`, no daemon |
| macOS hosts | The CLI builds on macOS; boxes need Linux. Use the Lima VM ([development.md](development.md)) |
| SSH egress | HTTPS only (see Network) |
| UDP egress | None |
| GPUs | None |
| Windows guests | Linux images only |
