# tkbox.yaml

`tkbox run --config tkbox.yaml` reads a box's settings from a file, so a repository can carry the box its agents run
in. Every key is optional except `image`. Flags given to `tkbox run` override the file: a scalar flag (`--image`,
`--cpus`, …) replaces the file's value, and the repeatable flags (`--allow`, `--secret`, `--env`) add to the file's
lists, a flag winning over a file entry with the same name.
<!-- TODO(lead): confirm the override and merge rules, and whether relative paths resolve against the file's directory (assumed below) or the current directory, with agent F. -->

A complete example is in [examples/tkbox.yaml](../examples/tkbox.yaml).

```yaml
image: python:3.12-slim
name: fix-tests
workspace: .
allow:
  - pypi
  - github
  - api.example.com:8443
secrets:
  GH:
    from_env: GH_TOKEN
    hosts: [api.github.com, github.com]
    header: Authorization
  INTERNAL_KEY:
    from_file: ~/.config/example/key
    hosts: ["*.example.com"]
    header: X-Api-Key
env:
  CI: "1"
  PIP_DISABLE_PIP_VERSION_CHECK: "1"
limits:
  cpus: 2
  memory: 2048
  disk: 4096
  timeout: 1h
  exec_timeout: 30m
inspect: bound
task: Make the failing tests pass without changing them.
```

## Keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `image` | string | required | An OCI image reference from Docker Hub or GHCR, such as `python:3.12-slim`, `node:22-slim` or `ghcr.io/org/img:tag`. Its gzip or uncompressed layers are flattened into a read-only ext4 rootfs, cached by digest |
| `name` | string | the box id | A name unique among the daemon's boxes; every command takes the name or the id |
| `workspace` | path | none | A git work tree on the host, copied into `/workspace` (tracked files plus untracked files that are not ignored; never `.git`). Relative to the file's directory. Without it the box has no `/workspace` |
| `allow` | list of strings | empty: nothing leaves | Presets and hosts the box may connect to without asking. See [Allow entries](#allow-entries) |
| `secrets` | map | none | Environment variable name → secret. See [Secrets](#secrets) |
| `env` | map of strings | none | Plain environment variables for every exec. Values are visible in the box and in the box's API record; never put secrets here |
| `limits` | map | see below | Resource and time limits |
| `inspect` | `bound` or `all` | `bound` | `bound`: the proxy opens (MITM) only hosts with a bound secret. `all`: every allowed HTTPS host, so placeholders are blocked everywhere; breaks clients that pin certificates |
| `task` | string | none | The task the box was given, recorded in the run as trusted content (`tkbox.task`) |
<!-- TODO(lead): confirm with agent F that `name`, `task` and `agent` are tkbox.yaml keys; the brief lists image, allow, secrets, env, limits, workspace, inspect. -->

### Allow entries

| Entry | Allows |
|---|---|
| `example.com` | `example.com` on ports 80 and 443 |
| `example.com:8443` | that port only |
| `*.example.com` | any subdomain of `example.com` (not `example.com` itself), ports 80 and 443 |
| `203.0.113.7`, `[2001:db8::1]:8443` | an IP literal, with the same port rules; private and special addresses stay refused |
| a preset name | the preset's hosts |

Presets:

| Preset | For |
|---|---|
| `github` | GitHub: git over HTTPS, the API, release and raw downloads |
| `pypi` | `pip install` from PyPI |
| `npm` | `npm install` from the npm registry |
| `anthropic` | The Anthropic API (requests are recorded as model calls) |
| `openai` | The OpenAI API (requests are recorded as model calls) |
| `apt-ubuntu` | `apt-get` on Ubuntu images (Debian images need `deb.debian.org`) |
| `go-proxy` | Go modules through `proxy.golang.org` and `sum.golang.org` |

<!-- TODO(lead): paste the exact host lists from internal/egress Presets() once agent D lands them. -->

A host that is not allowed is not refused outright: the connection waits up to 2 minutes for a person on the host to
run `tkbox approve <id>`. Private, loopback, link-local and metadata addresses are refused whatever the allowlist says.

### Secrets

```yaml
secrets:
  NAME:
    from_env: VAR        # or from_file: PATH (exactly one of the two)
    hosts: [host, ...]   # required: the only hosts the value may be sent to
    header: Header-Name  # optional: the only request header it is swapped into
```

| Field | Meaning |
|---|---|
| `from_env` | Read the value from this environment variable of the `tkbox run` process |
| `from_file` | Read the value from this file (one trailing newline is dropped). `~` is expanded <!-- TODO(lead): confirm newline trimming with agent F --> |
| `hosts` | Exact host names or `*.example.com`. Required. A secret's hosts are added to the allowlist <!-- TODO(lead): confirm; the README demo relies on it --> |
| `header` | The request header the placeholder is replaced in, for example `Authorization` or `X-Api-Key`. Empty: any request header |

Inside the box, `$NAME` holds a placeholder such as `tkbox_GH_3f9c…`, never the value. The agent uses it as if it were
the value (`Authorization: Bearer $GH`); on a request to one of `hosts`, the host proxy replaces the placeholder in the
bound header with the real value. A request that carries the placeholder to any other host the proxy inspects is
blocked and recorded as `tkbox.secret.leak`. The value is resolved by the CLI, sent to the daemon over its socket and
never written to the box, its disks, its events or the record.

The same secret on the command line: `--secret GH=env:GH_TOKEN@api.github.com,github.com#Authorization` or
`--secret KEY=file:/path/to/key@*.example.com#X-Api-Key`.

### Limits

| Key | Unit | Default | Range |
|---|---|---|---|
| `cpus` | vCPUs | 2 | 1 to 32 |
| `memory` | MiB | 2048 | 128 to 65536 |
| `disk` | MiB, for writes to `/workspace` | 4096 | 64 to 1048576 |
| `timeout` | duration (`90m`, `2h`) or seconds | `1h` | the box is stopped when it expires |
| `exec_timeout` | duration or seconds | `30m` | per exec; `tkbox exec --timeout` overrides it |

<!-- TODO(lead): confirm memory/disk are plain MiB integers in the file and on the CLI, or whether suffixes (2G) are accepted. -->

What happens when a limit is hit, and what to do: [limits.md](limits.md).
