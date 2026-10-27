#!/usr/bin/env bash
# The numbers in the README, measured on a real host. Prints every sample, then the results and the conditions.
#
# What it measures:
#   1. Box start: from `tkbox run` to the box being ready (the guest agent answered, `tkbox run` returned) and to its
#      first command done (`tkbox exec <box> -- true` returned). Box has no warm path (no snapshots or pool, see
#      docs/limits.md), so every box is a cold Firecracker boot from a cached rootfs: the run opened in the signer, the
#      workspace and scratch disks built, the egress proxy, the VM boot. Two series: the image pinned by digest (no
#      registry round trip) and by tag (one registry HEAD per start). One more box per series warms the caches and is
#      not counted. Box defaults: 2 vCPUs, 2 GiB, no workspace. The first use of the image (pull and rootfs build) is
#      timed once.
#   2. Per-command overhead: `tkbox exec <box> -- true` minus `/usr/bin/true` run directly on the host, paired and
#      interleaved so load from other work hits both alike. It includes the tkbox CLI's own start, the API call to the
#      daemon, the signer's decision before the command and its signed completion record after it (tkbox exec returns
#      only after both), the vsock round trip and the guest starting `true`. It is split into the CLI's start
#      (`tkbox version`), the daemon and guest path (the same exec on a second daemon started with --unrecorded) and
#      the signer's part (recorded minus unrecorded).
#   3. One fuzz pass: every Go fuzz target in the repo (`go test -list`) for FUZZTIME each, with its executions and
#      crashes.
#   It also prints the conditions: CPU, OS, VM size, kernels, Firecracker, Go, Tracekit, the Box commit, and the load
#   averages before and after.
#
# Needs what `make e2e` needs (docs/development.md): Linux with /dev/kvm, e2fsprogs, git, Go at go.mod's version,
# Tracekit 1.4.2 (`pip install tracekit-ai==1.4.2`; if no dev signer runs, the script starts one and stops it after)
# and internet access (the daemon downloads Firecracker and the kernel; the image is pulled). On a Mac it prints the
# Mac's details and runs itself in the Lima VM from docs/development.md (LIMA_VM, default tkbox-dev), which mounts the
# checkout at the same path, so keep it under ~/tracekit-box.
#
# Run from anywhere: dev/bench.sh (or make bench), optionally with BOOT_N=30 EXEC_N=200 FUZZTIME=60s IMAGE=alpine:3.20.
# It builds its own binaries and keeps its daemons' state under /tmp, so a running tkbox daemon is left alone.
# Takes about 45 minutes with the defaults in the Lima VM: about 25 for the 62 boxes (a box takes about 20 s to start
# there, under nested virtualization) and about 18 for the fuzz pass (15 targets for FUZZTIME each, plus builds).
set -euo pipefail
export LC_ALL=C

repo=$(cd "$(dirname "$0")/.." && pwd)
BOOT_N=${BOOT_N:-30} EXEC_N=${EXEC_N:-200} FUZZTIME=${FUZZTIME:-60s} IMAGE=${IMAGE:-alpine:3.20}

if [ "$(uname -s)" = Darwin ]; then
  vm=${LIMA_VM:-tkbox-dev}
  echo "== Mac host ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  echo "CPU: $(sysctl -n machdep.cpu.brand_string), $(sysctl -n hw.ncpu) cores, $(($(sysctl -n hw.memsize) >> 30)) GiB"
  echo "macOS: $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
  echo "Lima: $(limactl --version)"
  limactl list "$vm"
  echo "Mac load before: $(uptime)"
  status=0
  limactl shell "$vm" -- env BOOT_N="$BOOT_N" EXEC_N="$EXEC_N" FUZZTIME="$FUZZTIME" IMAGE="$IMAGE" \
    bash "$repo/dev/bench.sh" || status=$?
  echo "Mac load after: $(uptime)"
  exit "$status"
fi

export PATH="/usr/local/go/bin:$HOME/.venv/tracekit/bin:$PATH"
work=$(mktemp -d /tmp/tkbox-bench.XXXXXX)
pids="" started_signer=""
stop_daemons() {
  for p in $pids; do kill -INT "$p" 2>/dev/null || true; done
  for p in $pids; do wait "$p" 2>/dev/null || true; done
  pids=""
}
cleanup() {
  local status=$?
  stop_daemons
  if [ -n "$started_signer" ]; then tracekit down >/dev/null 2>&1 || true; fi
  if [ "$status" = 0 ]; then rm -rf "$work"; else echo "bench: failed; logs are in $work" >&2; fi
}
trap cleanup EXIT

# stats LABEL FILE EXPR: n, median, p95 (nearest rank), min and max of EXPR, an awk expression over a row's µs columns
stats() {
  awk "{ print $3 }" "$2" | sort -n | awk -v label="$1" '
    { v[NR] = $1 }
    END {
      n = NR; k = int((95 * n + 99) / 100)
      med = n % 2 ? v[(n + 1) / 2] : (v[n / 2] + v[n / 2 + 1]) / 2
      printf "  %-62s n=%d  median %8.2f ms  p95 %8.2f ms  (min %.2f, max %.2f)\n", label, n, med / 1000, v[k] / 1000, v[1] / 1000, v[n] / 1000
    }'
}

echo "== Linux host ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
echo "OS: $(. /etc/os-release && echo "$PRETTY_NAME"), kernel $(uname -r) $(uname -m)"
echo "virtualization: $(systemd-detect-virt 2>/dev/null || true) (boxes boot nested when this is not none)"
echo "CPU: $(lscpu | awk -F': *' '/^(Vendor ID|Model name)/ { printf "%s ", $2 }')/ $(nproc) CPUs, $(awk '/^MemTotal/ { printf "%.1f GiB", $2 / 1048576 }' /proc/meminfo)"
echo "Go: $(go version)"
echo "Tracekit: $(tracekit --version)"
echo "Box: $(git -C "$repo" describe --always --dirty --abbrev=12) ($(git -C "$repo" log -1 --format='%cd %s' --date=short))"
echo "load before: $(uptime)"

echo "== Build"
make -C "$repo" -s build BIN="$work/bin"
tk=$work/bin/tkbox
echo "tkbox: $("$tk" version)"

echo "== Signer"
tracekit status 2>/dev/null | python3 -c 'import json,sys; sys.exit(not json.load(sys.stdin)["signer_v2"]["running"])' ||
  started_signer=1
tracekit up --wait || { tracekit init --dev --v2 --no-hooks && tracekit up --wait; }

# daemon NAME FLAGS...: start a daemon with its own state dir and wait for it
daemon() {
  local name=$1
  shift
  "$tk" daemon --state-dir "$work/$name" "$@" >"$work/$name.log" 2>&1 &
  pids="$pids $!"
  for _ in $(seq 1 600); do TKBOX_SOCKET="$work/$name/run/tkbox.sock" "$tk" ls >/dev/null 2>&1 && return; sleep 0.2; done
  tail -n 20 "$work/$name.log" >&2
  return 1
}
rec() { TKBOX_SOCKET="$work/rec/run/tkbox.sock" "$tk" "$@"; }
unrec() { TKBOX_SOCKET="$work/unrec/run/tkbox.sock" "$tk" "$@"; }

echo "== Daemon (recorded; its first start downloads Firecracker and the kernel)"
daemon rec
fc=$(ls "$work"/rec/images/assets/firecracker-*)
kernel=$(ls "$work"/rec/images/assets/vmlinux-*)
echo "Firecracker: $("$fc" --version | head -n 1)"
echo "guest kernel: $(basename "$kernel")"

echo "== First use of $IMAGE (pull and rootfs build; 1 sample, depends on the network)"
t0=${EPOCHREALTIME/./}
built=$(rec image build "$IMAGE")
t1=${EPOCHREALTIME/./}
echo "$built"
echo "image build: $(((t1 - t0) / 1000)) ms"
pinned="$IMAGE@$(echo "$built" | awk '{ print $2 }')"

# boot SERIES REF: BOOT_N boxes after one warm-up, one row per box: µs to ready, µs to first command done
boot() {
  echo "== Box start, $1 ($2): ready_us first_command_us"
  local i t0 t1 t2
  for i in $(seq 0 "$BOOT_N"); do
    t0=${EPOCHREALTIME/./}
    rec run --no-config --image "$2" --name "boot-$1-$i" >>"$work/run.log" 2>&1
    t1=${EPOCHREALTIME/./}
    rec exec "boot-$1-$i" -- true
    t2=${EPOCHREALTIME/./}
    rec rm "boot-$1-$i" >>"$work/run.log" 2>&1
    if [ "$i" = 0 ]; then echo "warm-up (not counted): $((t1 - t0)) $((t2 - t0))"; continue; fi
    echo "$((t1 - t0)) $((t2 - t0))" | tee -a "$work/boot-$1"
  done
}
boot pinned "$pinned"
boot tag "$IMAGE"

echo "== Per-command overhead: direct_us tkbox_version_us exec_unrecorded_us exec_recorded_us"
daemon unrec --unrecorded --firecracker "$fc" --kernel "$kernel"
rec run --no-config --image "$pinned" --name cmd >>"$work/run.log" 2>&1
unrec run --no-config --image "$pinned" --name cmd >>"$work/run.log" 2>&1
echo "box kernel: $(rec exec cmd -- uname -r)"
for i in $(seq -9 "$EXEC_N"); do
  a=${EPOCHREALTIME/./}
  /usr/bin/true >/dev/null 2>>"$work/exec.err"
  b=${EPOCHREALTIME/./}
  "$tk" version >/dev/null 2>>"$work/exec.err"
  c=${EPOCHREALTIME/./}
  unrec exec cmd -- true >/dev/null 2>>"$work/exec.err"
  d=${EPOCHREALTIME/./}
  rec exec cmd -- true >/dev/null 2>>"$work/exec.err"
  e=${EPOCHREALTIME/./}
  if [ "$i" -lt 1 ]; then continue; fi # 10 warm-up rounds
  echo "$((b - a)) $((c - b)) $((d - c)) $((e - d))" | tee -a "$work/exec"
done
rec rm cmd >>"$work/run.log" 2>&1
unrec rm cmd >>"$work/run.log" 2>&1
stop_daemons

echo "== Fuzz pass: each target for $FUZZTIME, GOMAXPROCS $(nproc)"
cd "$repo"
targets=$(go test -list '^Fuzz' ./... | awk '/^Fuzz/ { f[++n] = $1 } /^ok / { for (i = 1; i <= n; i++) print $2, f[i]; n = 0 }')
: >"$work/fuzz"
while read -r pkg name; do
  echo "-- $name ($pkg)"
  st=0
  go test -run='^$' -fuzz="^$name\$" -fuzztime="$FUZZTIME" "$pkg" </dev/null 2>&1 | tee "$work/fuzz.out" || st=$?
  execs=$(sed -n 's/.*, execs: \([0-9]*\) .*/\1/p' "$work/fuzz.out" | tail -n 1)
  verdict=ok crash=0
  if grep -q 'Failing input written to' "$work/fuzz.out"; then
    verdict="CRASH (input saved under $(go list -f '{{.Dir}}' "$pkg")/testdata/fuzz/$name)" crash=1
  elif [ "$st" != 0 ]; then
    verdict="ERROR (exit $st)"
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "${pkg#github.com/Cygnux-Labs/tracekit-box/}" "$name" "${execs:-0}" "$crash" "$verdict" >>"$work/fuzz"
done <<<"$targets"

echo "load after: $(uptime)"

echo
echo "== Results"
echo "Box start, $IMAGE, 2 vCPUs, 2 GiB, no workspace, cold boot (Box has no warm path):"
stats "pinned by digest: start -> ready (tkbox run returned)" "$work/boot-pinned" '$1'
stats "pinned by digest: start -> first command done" "$work/boot-pinned" '$2'
stats "by tag (+1 registry HEAD): start -> ready" "$work/boot-tag" '$1'
stats "by tag (+1 registry HEAD): start -> first command done" "$work/boot-tag" '$2'
echo "Per command, tkbox exec <box> -- true, paired with /usr/bin/true run directly on the host:"
stats "/usr/bin/true run directly" "$work/exec" '$1'
stats "tkbox exec -- true (signer decision and record included)" "$work/exec" '$4'
stats "OVERHEAD per command: tkbox exec -- true minus direct" "$work/exec" '$4 - $1'
stats "  of which tkbox CLI start (tkbox version minus direct)" "$work/exec" '$2 - $1'
stats "  of which daemon, vsock, guest (unrecorded minus version)" "$work/exec" '$3 - $2'
stats "  of which signer decision + record (recorded minus unrecorded)" "$work/exec" '$4 - $3'
echo "  (medians of paired differences: the parts need not add up to the total exactly)"
echo "Fuzz pass, $FUZZTIME per target:"
awk -F'\t' '{ printf "  %-20s %-22s %12s execs  %s\n", $1, $2, $3, $5; e += $3; c += $4 }
  END { printf "  total: %d targets, %d execs, %d crashes\n", NR, e, c }' "$work/fuzz"
