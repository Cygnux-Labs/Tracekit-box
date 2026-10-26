# tkbox.yaml

A `tkbox.yaml` holds a box's settings, so a repository can carry the box its agents run in. `tkbox run` reads
`./tkbox.yaml` when it exists and `--config` is not given (and says so); `--config FILE` reads another file;
`--no-config` reads none. Only the current directory is looked at, not its parents. `tkbox mcp --config FILE` uses a
file the same way, as the operator's settings for every box it starts (see [cli.md](cli.md#tkbox-mcp)).

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
    hosts: [api.example.com]
    header: X-Api-Key
env:
  CI: "1"
  PIP_DISABLE_PIP_VERSION_CHECK: "1"
limits:
  cpus: 2
  memory: 2GiB
  disk: 4GiB
  timeout: 1h
  exec_timeout: 30m
inspect: bound
agent: my-agent
task: Make the failing tests pass without changing them.
```

The file is read strictly: an unknown key, a key given twice, a value of the wrong type or a second YAML document is an
error that names the line (`tkbox.yaml: line 2: unknown key imagee`). An empty file is allowed.

## Flags and the file

Flags given to `tkbox run` override the file:

- A scalar flag (`--image`, `--name`, `--workspace`, `--inspect`, `--agent`, `--task`, `--cpus`, `--memory`, `--disk`,
  `--timeout`) replaces the file's value.
- `--allow` adds to the file's list.
- `--env` and `--secret` add to the file's maps; for the same name, the flag wins.
- A name that is both in `env` and in `secrets` is an error: `env: GH is also a secret; keep it in secrets only`.

`image` is required, from the file or from `--image`: `no image: pass --image (e.g. --image python:3.12-slim) or set
image: in tkbox.yaml`.

Relative paths in the file (`workspace`, `from_file`) resolve against the file's directory; `--workspace` and
`--secret NAME=file:PATH` resolve against the current directory. A `workspace` or `from_file` path that starts with
`~/` (or a `workspace` that is just `~`) is expanded to your home directory.

## Keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `image` | string | required | An OCI image reference from Docker Hub or GHCR, such as `python:3.12-slim`, `node:22-slim` or `ghcr.io/org/img:tag`. Its gzip or uncompressed layers are flattened into a read-only ext4 rootfs, cached by digest |
| `name` | string | the box id (`tkb-` and 12 hex digits) | A name unique among the daemon's boxes: lower-case letters, digits and `-`, starting with a letter or digit, at most 63 characters, not starting with `tkb-`. Every command takes the name or the id |
| `workspace` | path | none: `/workspace` is empty | A host directory copied into `/workspace`. In a git work tree: tracked files and untracked files that are not ignored, never `.git`. Outside git: every file except `.git`. Credential files are never copied, git or not (see [limits.md](limits.md#behaviour)). Without a workspace, `/workspace` is an empty writable directory and `tkbox apply` needs `--dir` |
| `allow` | list of strings | empty: nothing leaves without approval | Presets and hosts the box may connect to without asking. See [Allow entries](#allow-entries) |
| `secrets` | map | none | Environment variable name → secret. See [Secrets](#secrets) |
| `env` | map of strings | none | Plain environment variables for every exec. Names are letters, digits and `_`. Values are visible in the box and recorded in the box's run when it is created; never put secrets here. Unlike `tkbox exec --env`, the box env may set `LD_PRELOAD`, `BASH_ENV` and the like. Box sets the proxy and CA variables itself (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY` in either case, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`, `CURL_CA_BUNDLE`), so `env` and `secrets` cannot use those names |
| `limits` | map | see [Limits](#limits) | Resource and time limits |
| `inspect` | `bound` or `all` | `bound` | `bound`: the proxy opens (MITM) only hosts with a bound secret. `all`: every allowed HTTPS host, so placeholders are caught everywhere, and a host off the allowlist is refused at once instead of waiting for approval; breaks clients that pin certificates |
| `agent` | string | `tkbox` | The agent's name, recorded in the Tracekit run (the action uses `claude-code` or `codex`; boxes made over MCP use `mcp`) |
| `task` | string, at most 64 KiB | none | The task the box was given, recorded in the run as trusted content |

### Allow entries

| Entry | Allows |
|---|---|
| `example.com` | HTTPS to `example.com:443` (a TLS tunnel whose SNI is `example.com`; ECH is refused), and plain HTTP to port 80 as absolute-form requests the proxy reads, which is what `http_proxy` does (a `CONNECT` tunnel to port 80 is refused) |
| `example.com:8443` | that port only. A tunnel that is not TLS is allowed only to an entry that names its port like this, and such an entry lets any protocol through to that port (SSH, SMTP, a database protocol), uninspected. A TLS tunnel must still send the host's name as its SNI |
| `*.example.com` | any subdomain of `example.com` (not `example.com` itself), with the same port rules |
| `203.0.113.7`, `[2001:db8::1]:8443` | an IP literal, with the same port rules; private and special addresses stay refused |
| a preset name | the preset's hosts |

Presets:

| Preset | Hosts | For |
|---|---|---|
| `github` | `github.com`, `api.github.com`, `codeload.github.com`, `uploads.github.com`, `raw.githubusercontent.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`, `github-releases.githubusercontent.com`, `media.githubusercontent.com`, `gist.githubusercontent.com` | git over HTTPS, the API, archives, raw files, release assets, LFS objects |
| `pypi` | `pypi.org`, `files.pythonhosted.org` | `pip`, `uv` and `poetry` installs (not publishing) |
| `npm` | `registry.npmjs.org`, `registry.yarnpkg.com` | `npm`, `pnpm` and `yarn` installs |
| `anthropic` | `api.anthropic.com` | The Anthropic API; requests are recorded as model calls |
| `openai` | `api.openai.com` | The OpenAI API; requests are recorded as model calls |
| `claude-code` | `api.anthropic.com`, `statsig.anthropic.com` | Claude Code (set `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` so it does not try other telemetry hosts) |
| `apt-ubuntu` | `archive.ubuntu.com`, `security.ubuntu.com`, `ports.ubuntu.com` | `apt-get` on Ubuntu images (plain HTTP) |
| `debian` | `deb.debian.org`, `security.debian.org` | `apt-get` on Debian images, such as `python:3.12-slim` |
| `go-proxy` | `proxy.golang.org`, `sum.golang.org` | Go modules through the module proxy (`GOPROXY=direct` needs the VCS hosts as well) |

A host that is not allowed is not refused outright: the connection waits up to 2 minutes (the daemon's
`--approval-timeout`) for a person on the host to run `tkbox approve <id>`, except with `inspect: all`, which refuses it (and a port the allowlist does not name for the host)
at once. Loopback, private, link-local, metadata and this host's own addresses are refused whatever the allowlist says.

### Secrets

```yaml
secrets:
  NAME:
    from_env: VAR        # or from_file: PATH (exactly one of the two)
    hosts: [host, ...]   # required: the only hosts the value may be sent to
    header: Header-Name  # optional, default Authorization: the only request header it is swapped into
```

| Field | Meaning |
|---|---|
| `NAME` | The environment variable the box sees: upper-case letters, digits and `_`, not starting with a digit (`GITHUB_TOKEN`) |
| `from_env` | Read the value from this environment variable of the `tkbox run` process. Unset or empty is an error |
| `from_file` | Read the value from this file; trailing line breaks are dropped. `~/` is expanded; a relative path is relative to the `tkbox.yaml` |
| `hosts` | Exact host names, without ports and without wildcards (`*.github.com` is refused: `host "*.github.com" is a wildcard: a secret goes to exact hosts only; list each one (e.g. [api.github.com, uploads.github.com])`). Required. A secret's hosts join the box's allowlist |
| `header` | The one request header the placeholder is replaced in, for example `Authorization` or `X-Api-Key`. Left out or empty, it is `Authorization`; it is never "any header". `Host` and hop-by-hop headers cannot be used. `tkbox run` prints each secret's header when the box starts |

The value must not be empty, must be at most 64 KiB and must be one line (no line break or NUL), because it travels in
a header.

Inside the box, `$NAME` holds a placeholder such as `tkbox_GH_3f9c…`, never the value. The agent uses it as if it were
the value (`Authorization: Bearer $GH`); on a request to one of `hosts`, the host proxy replaces the placeholder in the
bound header with the real value. A request that carries the placeholder anywhere else (another header, the URL, the
body) or to any other host whose traffic the proxy reads is blocked and recorded as `tkbox.secret.leak`. On those
connections the proxy also blocks the real value itself (raw, base64, percent- or JSON-escaped) wherever it is not
being swapped in, and redacts it from response headers, bodies and trailers. Requests to bound hosts are sent with
`Accept-Encoding: identity`, so their responses can be checked. The value is resolved by the CLI, sent to the daemon over its socket and
never written to the box, its disks, its events or the record.

The same secrets on the command line, where a value is never given directly:
`--secret GH=env:GH_TOKEN@api.github.com,github.com#Authorization` or
`--secret KEY=file:/path/to/key@api.example.com#X-Api-Key`. The spec is split at its last `@`, so a path may contain
`@`.

### Limits

| Key | Unit | Default | Range |
|---|---|---|---|
| `cpus` | vCPUs | 2 | 1 to 32 |
| `memory` | a size: `2GiB`, `512MiB`, or a plain number of MiB | 2GiB | 128MiB to 64GiB |
| `disk` | a size, for writes to `/workspace` | 4GiB | 64MiB to 1TiB |
| `timeout` | a duration: `90m`, `2h`, `1h30m` | `1h` | 10s to 168h; the box is stopped when it expires |
| `exec_timeout` | a duration | `30m` | 1s to 24h, per exec; `tkbox exec --timeout` overrides it |

Sizes take the units `KiB`, `MiB`, `GiB`, `TiB` (or `K`, `M`, `G`, `T`, also binary) and `KB`, `MB`, `GB`, `TB`
(decimal), are case-sensitive and are rounded up to whole MiB. In the file a plain integer means MiB (`memory: 2048`);
on the command line the unit is required (`--memory 4GiB`, `--disk 16GiB`). Durations always need a unit (`h`, `m`,
`s`); there is no `d`. `exec_timeout` can only be set in the file; per command, use `tkbox exec --timeout`.

A value out of range is refused when the box is created, for example `limits.memory 64MiB: use 128MiB..64GiB`.
What happens when a limit is hit, and what to do: [limits.md](limits.md).
