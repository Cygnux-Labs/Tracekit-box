# Developing Tracekit Box

Box is Go (the host binary `tkbox` and the guest agent `tkbox-guest`) plus a standard-library Python SDK. Unit tests
run anywhere, macOS included, because every boundary (VMM, guest agent, image builder, egress decider, signer) has an
interface and a fake. Booting real boxes needs Linux with `/dev/kvm`; on a Mac that is the Lima VM below.

## Layout

| Path | What |
|---|---|
| `cmd/tkbox` | Host binary: daemon, CLI, MCP server |
| `cmd/tkbox-guest` | Guest agent, PID 1 in the VM (static, linux/amd64 and linux/arm64) |
| `internal/api` | Daemon HTTP API contract |
| `internal/proto` | Frame format and guest operations |
| `internal/vmm`, `internal/assets` | Firecracker client, VM lifecycle, pinned kernel and Firecracker downloads |
| `internal/guest`, `internal/agentrpc` | Guest side of the protocol; host-side client |
| `internal/image` | OCI pull, layer flattening, ext4 builds |
| `internal/egress` | Egress proxy, allowlist, presets, per-box CA, secret swap |
| `internal/tracekit` | Tracekit 1.4.2 signer RPC client |
| `internal/daemon`, `internal/config` | Box manager, API server, `tkbox.yaml` |
| `e2e/` | End-to-end tests on a host with KVM |
| `sdk/python` | Python SDK |
| `action/` | GitHub Action |
| `dev/lima.yaml` | Lima VM for development on a Mac |

Read [architecture.md](architecture.md) first; the contract files (`internal/api/api.go`, `internal/proto/*.go`, the
interfaces in each package) are the source of truth for the protocols.

## Build

You need Go at the version in `go.mod`.

```sh
make            # bin/tkbox for this machine, bin/tkbox-guest-linux-{arm64,amd64}
make linux      # also bin/tkbox-linux-{arm64,amd64}
make lint       # gofmt, go vet (also with GOOS=linux)
```

On macOS `bin/tkbox` is the CLI only: it can talk to a daemon over a socket but cannot run boxes. `tkbox` finds the
guest agent next to its own binary (or in `tkbox daemon --guest-dir DIR`), so keep `bin/tkbox-linux-<arch>` and
`bin/tkbox-guest-linux-<arch>` together.

## Unit tests

```sh
make test                                 # go test ./...
make race                                 # with the race detector
cd sdk/python && python3 -m pytest -q     # Python SDK, against a fake daemon
```

The SDK tests need only `pytest` (`python3 -m venv .venv && .venv/bin/pip install pytest`); they run on Python 3.9 and
newer and need no Linux host.

## A Linux VM with KVM on a Mac (Lima)

[`dev/lima.yaml`](../dev/lima.yaml) describes an Ubuntu 24.04 arm64 VM with nested virtualization, so Firecracker gets
`/dev/kvm` inside it. Nested virtualization in Lima's `vz` driver needs an Apple M3 or newer and macOS 15 or newer. The
VM mounts `~/tracekit-box` writable, so keep the checkout there. Inside the VM it appears at the same path as on the
Mac, `/Users/<you>/tracekit-box`, while your home directory in the VM is `/home/<you>.guest`.

```sh
brew install lima
limactl start --name tkbox-dev dev/lima.yaml
limactl shell tkbox-dev
```

Inside the VM (the provisioning step already installed `e2fsprogs`, `git`, `curl`, `jq` and Python, and gave your user
access to `/dev/kvm`):

```sh
ls -l /dev/kvm                                     # must exist; if not, the host lacks nested virtualization
# Go, at the version in go.mod
cd /Users/$USER/tracekit-box                       # the mounted checkout (HOME is /home/$USER.guest)
curl -fsSL "https://go.dev/dl/go$(sed -n 's/^go //p' go.mod).linux-arm64.tar.gz" | sudo tar -C /usr/local -xz
export PATH=/usr/local/go/bin:$PATH
make linux
```

### A dev signer

Box needs a Tracekit 1.4.2 signer. For development, a same-user dev signer is enough (it gives dev assurance only; see
[SECURITY.md](../SECURITY.md)):

```sh
python3 -m venv ~/.venv/tracekit && . ~/.venv/tracekit/bin/activate
pip install tracekit-ai==1.4.2 && tracekit init --dev --v2 --no-hooks && tracekit up --wait
tracekit status
```

`--no-hooks` leaves Claude Code's hooks alone: Box talks to the signer itself.

### Running boxes

```sh
bin/tkbox-linux-arm64 daemon > /tmp/tkbox-daemon.log 2>&1 &
until bin/tkbox-linux-arm64 ls >/dev/null 2>&1; do sleep 1; done   # the first start downloads Firecracker and the kernel
bin/tkbox-linux-arm64 run --image alpine:3.20 --name t
bin/tkbox-linux-arm64 exec t -- uname -a
bin/tkbox-linux-arm64 stop t && bin/tkbox-linux-arm64 export t -o /tmp/t.tkb && tracekit verify /tmp/t.tkb --trust /tmp/t.trust.json
```

`tkbox` looks for the guest agent next to its own binary, which `make linux` puts there (`bin/tkbox-guest-linux-arm64`).
The daemon keeps its state in `~/.local/state/tkbox` (images, boxes, `run/tkbox.sock`); each box's console output is
in `boxes/<id>/console.log` and what happened at its doors in `boxes/<id>/events.ndjson` (`tkbox events <box>` prints
it).

## End-to-end tests

On a Linux host with `/dev/kvm`, `mkfs.ext4` and a running Tracekit 1.4.2 signer (the Lima VM above, or CI):

```sh
make e2e        # builds, then go test -tags e2e ./e2e/... with TKBOX_BIN=bin/
```

They boot real VMs, pull small public images and check every door against the signer's record, so they need outbound
network access and take a few minutes. CI runs them on `ubuntu-latest` after enabling KVM for the runner user, and
also runs the GitHub Action from the checkout (`uses: ./action`) with a trivial command
([.github/workflows/ci.yml](../.github/workflows/ci.yml)).

## Commits

Sign off every commit (`git commit -s`). Keep commits small and run `make lint test` before pushing.
