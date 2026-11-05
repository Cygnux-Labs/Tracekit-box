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

Tracekit `tracekit-ai==1.5.3` supplies the hook client. The managed hook entries in
`managed-settings.json` follow the v2 Claude Code settings written by Tracekit 1.5.3's
`tracekit/install.py` (`_install_hooks_at`, using `tracekit.integrations.claude_code`): all nine
registered Claude Code hook events, the `*` matcher for tool events, event-specific timeouts,
isolated Python module invocation and Tracekit's fail-closed shell wrappers. The signer path is fixed in the settings environment.
`allowManagedHooksOnly` prevents user and project hooks.
