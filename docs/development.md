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
make fuzz                                 # every fuzz target for FUZZTIME each (default 60s)
cd sdk/python && python3 -m pytest -q     # Python SDK, against a fake daemon
```

`go test ./...` runs each fuzz target's seeds and saved inputs (`testdata/fuzz/`). `make fuzz` searches for new ones,
one target at a time (`make fuzz FUZZTIME=10m` for longer). Every target runs even after one fails, and the run then
fails naming them; a failing input is saved under that package's `testdata/fuzz/<target>/`, so commit it with the fix.
The `fuzz` workflow runs `make -k fuzz` nightly and on demand, and uploads any new failing inputs as an artifact.

`make runs` verifies every signed run in [runs/](../runs/README.md) with the Tracekit 1.4.2 CLI
(`pip install tracekit-ai==1.4.2`) and rewrites the table in its README from the verified records. The `runs` workflow
checks the same on each pull request that touches `runs/`, and fails on a run that does not verify or a table that is
out of date.

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

Box needs a Tracekit signer that serves its protocol (RPC 19); Tracekit 1.4.2 to 1.5.3 are tested: CI tests 1.4.2,
and 1.5.3 has run the whole flow (run, exec, apply, export, verify) on a Mac in the colima VM below. For development, a same-user dev
signer is enough (it gives dev assurance only; see [SECURITY.md](../SECURITY.md)):

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

## The same on a Mac with colima

If you already use colima for Docker, a second colima profile is the same Lima VM with nested virtualization, with the
same needs: an Apple M3 or newer and macOS 15 or newer. Give Box a profile of its own; your default profile and its
Docker containers are left as they are. The profile runs a Docker engine of its own; containers you start there share
the VM with the signer and the daemon, so start none there.

Start it with `--activate=false` every time: colima otherwise makes the profile Docker's current context on each start.
With it, `docker context show` prints what it printed before (`colima` if you use colima's default profile). Mount
only the checkout, writable (`--mount ~/tracekit-box:w`), not your whole home, which colima mounts by default; a box's
`--workspace` must then be in the checkout or in the VM's own disk. Run the steps below from inside `~/tracekit-box`:
each `colima ssh` starts in the Mac's working directory, and that is the only folder the VM mounts.

```sh
colima start --profile tkbox --activate=false --vm-type vz --nested-virtualization --cpu 4 --memory 8 \
  --mount ~/tracekit-box:w
colima ssh --profile tkbox -- ls -l /dev/kvm                 # must exist
colima ssh --profile tkbox -- sudo usermod -aG kvm "$USER"
colima stop --profile tkbox && colima start --profile tkbox --activate=false   # so new sessions are in the kvm group
colima ssh --profile tkbox -- sudo apt-get update -q
colima ssh --profile tkbox -- sudo apt-get install -y -q e2fsprogs git python3-venv
```

Build on the Mac with Go (`make linux`, the version in go.mod), then run the signer and the daemon in the VM. Each
`colima ssh` is a new session that starts in the Mac's working directory, and `~` on the command line is the Mac's
home, so name the VM's home (`/home/$USER.guest`) for the venv, and give the daemon the venv's `tracekit` for
`tkbox export` with `--tracekit-bin` rather than relying on `PATH`:

```sh
v=/home/$USER.guest/.venv-tracekit                                              # in the VM's home
tkbox=~/tracekit-box/bin/tkbox-linux-arm64                                       # the mounted checkout's build
colima ssh --profile tkbox -- python3 -m venv $v
colima ssh --profile tkbox -- $v/bin/pip install -q tracekit-ai==1.5.3
colima ssh --profile tkbox -- $v/bin/tracekit up --wait                         # the dev signer
colima ssh --profile tkbox -- $tkbox daemon --tracekit-bin $v/bin/tracekit &
until colima ssh --profile tkbox -- $tkbox ls >/dev/null 2>&1; do sleep 1; done  # the first start downloads Firecracker and the kernel
colima ssh --profile tkbox -- $tkbox run --image python:3.12-slim --name t
```

On an M4 Pro with macOS 26.3, the first `tkbox run` of `python:3.12-slim` took 115 s (pulling the image and building
its root file system), a later one 6 s; `tkbox export` and `tracekit verify` gave `Integrity: VERIFIED`.

What this setup protects, honestly: the boxed agent, inside its micro-VM, can reach neither the signer nor the colima
VM. It doesn't separate the signer from you. Your Mac account controls the colima VM (`colima ssh`, its passwordless
sudo, the VM's disk under `~/.colima`), so running the signer as another user inside the VM adds nothing here: bundles
read `isolation: same-user`, and that is the truth on a Mac. On a Linux host, a signer of its own user does add a
boundary ([SECURITY.md](../SECURITY.md)).

## End-to-end tests

On a Linux host with `/dev/kvm`, `mkfs.ext4` and a running Tracekit signer (1.4.2 to 1.5.3 tested; the Lima or colima VM above, or CI):

```sh
make e2e        # builds, then go test -tags e2e ./e2e/... with TKBOX_BIN=bin/
```

`TestAgentChannel` ([agent-channel.md](agent-channel.md)) also needs `TKBOX_TRACEKIT21`: a `tracekit` CLI that serves
RPC protocol 21 (Tracekit 1.6.0 or later). It starts a signer of its own from it, since a dev signer can't take
`box_daemons`, and skips without it. In the colima VM, which has no Go, build the test on the Mac and run it there:

```sh
make linux && mkdir -p bin/linux && cp bin/tkbox-linux-arm64 bin/linux/tkbox && cp bin/tkbox-guest-linux-arm64 bin/linux/
GOOS=linux GOARCH=arm64 go test -c -tags e2e -o bin/linux/e2e.test ./e2e
colima ssh --profile tkbox -- env TKBOX_BIN=$PWD/bin/linux TKBOX_TRACEKIT21=$v/bin/tracekit \
  bin/linux/e2e.test -test.v -test.count=1 -test.timeout 30m -test.run TestAgentChannel
```

Here `$v` is a venv in the VM with Tracekit 1.6.0 or later, not the 1.5.3 one above.

They boot real VMs, pull small public images and check every door against the signer's record, so they need outbound
network access and take a few minutes. CI runs them on `ubuntu-latest` after enabling KVM for the runner user, and
also runs the GitHub Action from the checkout (`uses: ./action`) with a trivial command
([.github/workflows/ci.yml](../.github/workflows/ci.yml)).

## Releasing

A maintainer pushes a `v*` tag (`git tag -s v0.1.0 && git push origin v0.1.0`); a tag that isn't `vX.Y.Z` or
`vX.Y.Z-pre` stops the build. The [release workflow](../.github/workflows/release.yml) then builds the four Linux
binaries from the tag with the Go toolchain `go.mod` pins (its `toolchain` line), after `make lint`, the unit tests and
a `govulncheck` that fails on any finding, and passes their `SHA256SUMS` to the publish job as a job output. The
publish job runs in the `release` environment, so a person approves it; it runs none of the repository's code: it
checks the downloaded binaries against those checksums, attests each one's build provenance and publishes them as the
tag's GitHub Release. The build job also runs on every pull request that changes the workflow, the Makefile or the Go
module files, with no artifact. Keep the `toolchain` line on the latest patch of the Go release in `go`: patches carry
the standard library's security fixes.

## Commits

Sign off every commit (`git commit -s`). Keep commits small and run `make lint test` before pushing.
