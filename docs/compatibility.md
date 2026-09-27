# E2B SDK compatibility

Weft Sandboxes implements the REST API the E2B SDKs call, and runs the
upstream, unmodified **envd** agent (Apache-2.0, built from a pinned revision,
see [guest/envd/VERSION](../guest/envd/VERSION)) inside every sandbox. Commands,
files, PTY and directory watches therefore behave exactly as envd implements
them. The API layer is tested with the E2B SDKs below.

| SDK | Version tested | Suite |
| --- | --- | --- |
| Python `e2b` (PyPI) | 2.51.0 | [packages/compat-tests/python](../packages/compat-tests/python) |
| JavaScript `e2b` (npm) | 2.51.0 | [packages/compat-tests/js](../packages/compat-tests/js) |

The suites run against a live stack. See
[development.md](development.md#testing-an-installed-stack) to run them
against yours.

## Configuration

Set three environment variables, the same ones E2B's hosted service uses:

| Variable | Value |
| --- | --- |
| `E2B_API_URL` | `https://api.<domain>` (the `ApiUrl` stack output) |
| `E2B_DOMAIN` | `<domain>` (the `Domain` stack output) |
| `E2B_API_KEY` | A team API key (`weft_sk_...`) |

Passing `api_url`/`apiUrl`, `domain` and `api_key`/`apiKey` to the SDK calls
works too. Leave `E2B_DEBUG` unset: it points the SDKs at `localhost`.

## Feature matrix

Status: ✅ supported · ⚠️ supported with differences · ❌ not supported (the
API answers with an error rather than ignoring the option). **Tested** means
the compatibility suite exercises the feature through the SDK.

### Sandboxes

| Feature | Status | Tested | Notes |
| --- | --- | --- | --- |
| `Sandbox.create` with template, timeout, metadata, envs | ✅ | yes | Default template `base`, default timeout 300 s; longer timeouts are capped at 24 h. Metadata up to 32 KiB and environment variables up to 128 KiB in total |
| `Sandbox.connect` to a running or paused sandbox | ✅ | yes | Resumes a paused sandbox |
| `Sandbox.list` with metadata and state filters, pagination | ✅ | yes | |
| `get_info`, `is_running`, `kill`, `set_timeout` | ✅ | yes | |
| `pause` and resume | ✅ | yes | Firecracker: full memory snapshot to S3, kept 30 days. Processes and files survive |
| `lifecycle.on_timeout = "pause"` | ✅ | yes | |
| `on_timeout` pause with `keep_memory=False` | ⚠️ | no | Memory is kept anyway; resume restores running processes |
| `lifecycle.auto_resume` | ❌ | yes | Traffic does not wake a paused sandbox; call `Sandbox.connect()` |
| `get_metrics` | ✅ | yes | CPU, memory and disk from envd |
| `secure` (envd access token) | ✅ | yes | Always on: every sandbox gets its own envd token |
| `get_host(port)` and traffic to sandbox ports | ✅ | yes | `https://<port>-<id>.<domain>`, WebSockets included |
| `network.allow_public_traffic = False` | ✅ | yes | Port traffic then needs the sandbox's traffic token |
| `allow_internet_access`, `network.allow_out` / `deny_out` | ⚠️ | yes | Can only narrow the team's egress policy; see [egress.md](egress.md#sdk-options) |
| Updating network settings of a running sandbox | ⚠️ | no | Same narrowing rules as at create |
| `network.rules`, `egress_proxy`, `mask_request_host` | ❌ | no | Use the team egress policy and credential rules instead |
| Sandbox logs | ⚠️ | no | Always an empty list |
| Snapshots and `fork` | ❌ | no | 501. Use pause and connect |
| Volume mounts, MCP gateway, sandbox IAM | ❌ | no | 400 |

### Inside the sandbox (envd)

| Feature | Status | Tested | Notes |
| --- | --- | --- | --- |
| `commands.run`: output, exit codes, env, cwd, user, timeouts | ✅ | yes | Default user `user`, home `/home/user` |
| Background commands, `list`, `kill`, `send_stdin`, `connect` | ✅ | yes | |
| Streaming stdout and stderr callbacks | ✅ | yes | |
| `files.read` / `write` / `write_files` (text, bytes, large files) | ✅ | yes | |
| `files.list`, `exists`, `get_info`, `make_dir`, `rename`, `remove` | ✅ | yes | |
| `files.watch_dir` | ✅ | yes | |
| Signed upload and download URLs | ✅ | yes | |
| `pty.create`, `send_stdin`, `resize`, `kill` | ✅ | yes | |
| `git` helpers | ✅ | no | They run `git` through commands; need egress to the Git host |

### Templates

| Feature | Status | Tested | Notes |
| --- | --- | --- | --- |
| `Template.build` with `from_image` | ✅ | yes | Public registries (needs `HostInternetAccess=enabled`) or your stack's ECR repository |
| `from_base_image`, `from_python_image` and similar | ✅ | no | Pull the named public image |
| `from_template` | ✅ | yes | Starts from that template's image and environment |
| Private registry with username and password | ✅ | no | |
| `from_aws_registry`, `from_gcp_registry` | ❌ | no | Push the image to your stack's ECR repository instead |
| `set_envs`, `set_workdir` | ✅ | yes | |
| `set_user` | ⚠️ | no | Accepted; commands still default to user `user` |
| `set_start_cmd`, `set_ready_cmd` | ✅ | yes | Firecracker runs them once at build time and captures their state in the snapshot |
| `cpu_count`, `memory_mb` | ✅ | yes | |
| `run_cmd`, `copy`, `pip_install`, `apt_install` and other steps that change files | ❌ | yes | 400 with an explanation. Build an image with a Dockerfile instead |
| Build logs and status polling | ✅ | yes | |
| `e2b template` CLI (`e2b.toml`, `e2b.Dockerfile`) | ❌ | no | Use `weft-sandbox templates build --dockerfile` |

See [templates.md](templates.md) for building templates.

### Errors

Errors have the same shape as E2B's (`{"code": <status>, "message": "..."}`),
so the SDKs raise their usual exceptions, such as `NotFoundException` and
`AuthenticationException`. A stack with no free host capacity answers `503`.

## Known limitations

These are the gaps between this release and the full E2B feature set, or
behavior worth knowing about. Each is either rejected with a clear error or
documented here.

- **Template steps that change files** (`RUN`, `COPY` and the helpers built on
  them) are not supported. Build a container image instead.
- **Auto-resume, snapshots, fork, volumes, MCP and sandbox IAM roles** are not
  supported.
- **Sandbox logs** are empty.
- **Egress**: per-sandbox options can narrow the team policy but never widen
  it. `network.rules` (per-request transforms) and egress proxies are not
  supported. The credential proxy handles HTTP/1.1 and TLS; it does not
  inject credentials into HTTP/2-only or non-HTTP protocols. Response bodies
  are not scrubbed: if an upstream API echoes the injected credential back,
  the sandbox can read it.
- **Paused sandboxes** are kept for 30 days by default
  (`WEFT_PAUSED_RETENTION_DAYS`).
- **Scale-in and Spot interruptions** stop the sandboxes on the affected host.
  There is no live migration. Keep `HostMinSize` and
  `HostOnDemandBaseCapacity` at your baseline (see [operations.md](operations.md)).
- **Snapshots are tied to one CPU family and Firecracker release.** Keep the
  host fleet on one instance family. A Firecracker upgrade rebuilds templates.
- **Egress wildcards**: `*.example.com` is checked only for not being a
  top-level domain. A wildcard on a public suffix such as `*.co.uk` is
  accepted, so review wildcard rules with care.
