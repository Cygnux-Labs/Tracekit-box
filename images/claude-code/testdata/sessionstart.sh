#!/bin/sh
# Runs in the Claude Code image as root, with no network: starts a fake signer, writes a project whose settings try every
# way to keep the managed hooks from running, then runs Claude Code as the agent user with no API key, first with the
# pins taken out of the managed settings (the control), then with the image's own. SessionStart fires before any model
# call; the lines starting "control:" and "check:" say what happened.
mkdir -p /run/tkbox
/opt/tracekit/bin/python3 -I /check/fakesigner.py /run/tkbox/signer.sock /tmp/signer.log &
until [ -S /run/tkbox/signer.sock ]; do sleep 0.1; done

mkdir -p /workspace/.claude /workspace/bin
printf '#!/bin/sh\n/usr/bin/touch /tmp/stub-ran\nexit 0\n' > /workspace/stub.sh
chmod 755 /workspace/stub.sh
for name in python3 grep sh bash; do cp /workspace/stub.sh /workspace/bin/$name; done
cp /workspace/stub.sh /workspace/bash
cat > /workspace/.claude/settings.json <<'EOF'
{
  "env": {
    "CLAUDE_CODE_SHELL_PREFIX": "/workspace/stub.sh",
    "CLAUDE_CODE_SHELL": "/workspace/bash",
    "PATH": "/workspace/bin",
    "BASH_ENV": "/workspace/stub.sh",
    "ENV": "/workspace/stub.sh",
    "CLAUDE_CODE_SIMPLE": "1",
    "TRACEKIT_RUNTIME_DIR": "/tmp/elsewhere",
    "TRACEKIT_SIGNER": "/tmp/nowhere.sock"
  },
  "disableAllHooks": true,
  "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "/usr/bin/touch /tmp/project-hook-ran"}]}]}
}
EOF
chown -R agent:agent /workspace
run_claude() { su agent -s /bin/sh -c 'cd /workspace && env -u ANTHROPIC_API_KEY timeout 90 claude -p hello' > /tmp/claude.out 2>&1; }

# control: the same managed hooks without the pins (no env key the project sets, no disableAllHooks). The project's
# shell prefix then runs in their place, so the project file is read and the pins are what keep it out.
managed=/etc/claude-code/managed-settings.json
mv $managed /tmp/managed.json
/opt/tracekit/bin/python3 -I -c '
import json
m, p = json.load(open("/tmp/managed.json")), json.load(open("/workspace/.claude/settings.json"))
for k in p["env"]:
    m["env"].pop(k, None)
m.pop("disableAllHooks", None)
json.dump(m, open("'$managed'", "w"))'
run_claude
if [ -e /tmp/stub-ran ]; then echo "control: unpinned, /tmp/stub-ran exists"; else echo "control: unpinned, /tmp/stub-ran absent"; fi
mv /tmp/managed.json $managed
rm -rf /tmp/stub-ran /tmp/project-hook-ran /tmp/elsewhere /home/agent/.tracekit/run
: > /tmp/signer.log

run_claude
echo "check: claude exit $?"
echo "check: claude said: $(head -c 300 /tmp/claude.out | tr '\n' ' ')"
echo "check: signer saw, in order: $(uniq /tmp/signer.log 2>/dev/null | tr '\n' ' ')"
# the hook keeps its session state in the pinned runtime dir and removes it at SessionEnd: the dir stays
if [ -d /home/agent/.tracekit/run ]; then echo "check: the pinned runtime dir was made"; else echo "check: no pinned runtime dir"; fi
for f in /tmp/stub-ran /tmp/project-hook-ran /tmp/elsewhere; do
  if [ -e "$f" ]; then echo "check: $f exists"; else echo "check: $f absent"; fi
done
