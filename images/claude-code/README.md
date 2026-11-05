# Claude Code box image

This repository does not publish the image. Build and push it to a public OCI registry that your
tkbox daemon can pull from (Box does not load Docker's local image store):

```sh
docker buildx build --tag <public-registry>/<name>:<tag> --push -f images/claude-code/Dockerfile images/claude-code
```

`tkbox run` creates the box; `tkbox exec` starts the command in the running box:

```sh
tkbox run --image <public-registry>/<name>:<tag> --agent-channel --secret ANTHROPIC_API_KEY=env:ANTHROPIC_API_KEY@api.anthropic.com#X-Api-Key --allow claude-code,anthropic --name claude
tkbox exec claude -- claude -p '<task>'
```

The channel needs a signer whose `signer.yaml` names the daemon's uid in `box_daemons`, so start the daemon with
that file as `--tracekit-config` (beside `--signer` and `--tracekit-bin`): `tkbox export` reads the box's run from
that signer's store.

Tracekit `tracekit-ai==1.5.3` supplies the hook client. The managed hook entries in
`managed-settings.json` follow the v2 Claude Code settings written by Tracekit 1.5.3's
`tracekit/install.py` (`_install_hooks_at`, using `tracekit.integrations.claude_code`): all nine
registered Claude Code hook events, the `*` matcher for tool events, event-specific timeouts,
isolated Python module invocation and Tracekit's fail-closed shell wrappers. The signer path is fixed in the settings environment.
`allowManagedHooksOnly` prevents user and project hooks. The hooks call `/opt/tracekit/bin/python3` and `/bin/grep` by
path, and the managed `env` pins `PATH`, `TRACEKIT_RUNTIME_DIR` and `TRACEKIT_APPROVAL_WAIT` and empties `LD_PRELOAD`,
`LD_LIBRARY_PATH`, `LD_AUDIT`, `GCONV_PATH`, `LOCPATH` and `NLSPATH`, so a project's or the user's settings can't swap
what they run (`go test ./images/claude-code` checks it).

What the image installs is pinned: Claude Code and its platform binaries by `package-lock.json` (`npm ci` checks each
package's integrity hash), and the hook client and its dependencies by `requirements.txt` (`pip install
--require-hashes`, wheels for Debian bookworm's Python 3.11 on arm64 and amd64). To move to new versions, regenerate
both:

```sh
npm install --package-lock-only --ignore-scripts      # after editing package.json
# for each of aarch64 and x86_64, with a Python 3.11:
pip download --only-binary=:all: --python-version 3.11 --implementation cp --abi cp311 --abi abi3 --abi none \
  --platform manylinux_2_36_<arch> --platform manylinux_2_28_<arch> --platform manylinux2014_<arch> --platform any \
  -d wheels-<arch> tracekit-ai==<version>
# then write each wheel's sha256 into requirements.txt
```

The base image, NodeSource's key and the nodejs package are not yet pinned by digest, fingerprint and exact version
(the Dockerfile's `lean:` note).
