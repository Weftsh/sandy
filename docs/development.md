# Development

## Requirements

Linux with root (network namespaces and iptables), Rust (the version in
[rust-toolchain.toml](../rust-toolchain.toml)), Node.js 22 with pnpm, Go (to
build envd), Python 3.11 or later, `iproute2`, `iptables` and `openssl`.
Docker is needed only for container images and Dockerfile templates, and KVM
only for the Firecracker runtime.

## Local stack

```sh
scripts/dev-stack.sh build                                 # as you; about 5 minutes the first time
sudo env "PATH=$PATH" scripts/dev-stack.sh up --no-build   # root: namespaces and iptables
source .weft/dev/e2b.env                                   # E2B_*, the admin CLI settings and test settings
python3 -m venv .weft/venv && .weft/venv/bin/pip install -q e2b
.weft/venv/bin/python -c 'from e2b import Sandbox; s = Sandbox.create(); print(s.commands.run("uname -a").stdout); s.kill()'
node packages/sdk/dist/cli.js teams list                   # the admin CLI, already configured
sudo scripts/dev-stack.sh down
```

Building runs as you, so your own toolchains are used and nothing in the
checkout ends up owned by root; only starting needs root, and `PATH` is passed
through so it finds `node`. The files you need afterwards (the environment
file, test certificates) are handed back to you. When you are already root, as
in a container, `scripts/dev-stack.sh up` builds and starts in one step.

`up` starts, as local processes:

- the control plane with all three roles and the in-memory store, on
  `127.0.0.1:3000` (API) and `:3001` (edge)
- the egress gateway, with a local CA, a development secrets file and a test
  upstream `echo.weft.test` that needs no internet access
- the host agent with the **namespace runtime** (`--insecure-namespace-runtime`)
- a `base` template built from `mirror.gcr.io/library/python:3.12-slim`
  (override with `WEFT_DEV_BASE_IMAGE`)

Options: `--https` serves the edge with TLS on `*.127-0-0-1.sslip.io:3443`,
like a real stack's host-based routing; without it, clients use the
single-URL header routing (`E2B_SANDBOX_URL`). `--no-build` skips the builds.
`scripts/dev-stack.sh env` prints the environment file. State and logs are in
`.weft/dev/`, which git ignores.

The development control plane also trusts a throwaway license signing key
(`kid` `dev-1`), so licensing can be tried end to end:

```sh
node packages/license/dist/cli.js issue --payload payload.json --private-key "$WEFT_DEV_LICENSE_KEY"
node packages/sdk/dist/cli.js license install <key>
```

See [licensing.md](licensing.md#license-keys) for the payload fields.

**The namespace runtime is not an isolation boundary.** Sandboxes are
processes on your kernel, in their own namespaces, with the production
network plumbing. Do not run untrusted code in it.

### Firecracker locally

On a Linux machine with `/dev/kvm` and cgroup v2, the same stack runs every
sandbox as a Firecracker microVM through the jailer, as production hosts do:

```sh
scripts/dev-stack.sh build --firecracker                                 # also builds the guest kernel (about 20 minutes, once)
sudo env "PATH=$PATH" scripts/dev-stack.sh up --no-build --firecracker
```

`build --firecracker` builds the guest kernel into `dist/guest/vmlinux`
(delete it to rebuild after changing `guest/kernel/`) and downloads the
Firecracker and jailer release that host AMIs install, checked against the
hashes pinned in `deploy/packer/firecracker.auto.pkrvars.hcl`. VM data and
jails live in `/var/lib/weft-dev` (`WEFT_DEV_FC_DIR`). The environment file
sets `WEFT_ESCAPE_RUNTIME=firecracker`, so the escape suite adds its microVM
boundary checks. CI runs this on every change
([.github/workflows/firecracker.yml](../.github/workflows/firecracker.yml)).

## Tests

| Suite | Command | Needs |
| --- | --- | --- |
| Rust unit tests (all crates, including the Firecracker runtime against a fake API and jailer) | `cargo test --workspace` | |
| Lints | `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings` | |
| TypeScript typecheck and unit and integration tests | `pnpm -r run typecheck && pnpm test` | |
| DynamoDB store contract tests | `WEFT_TEST_DYNAMODB_ENDPOINT=http://127.0.0.1:8000 pnpm --filter @weftsh/sandbox-control-plane test` | DynamoDB Local |
| E2B SDK compatibility | `packages/compat-tests/run.sh` | A running stack (`source .weft/dev/e2b.env`) |
| Escape attempts | `.weft/compat-venv/bin/pytest tests/escape` | A running stack |
| Deployment | See [deploy/README.md](../deploy/README.md#development) | `cfn-lint`, `checkov`, `packer`, `shellcheck` |

`run.sh` writes JUnit reports to `packages/compat-tests/reports/` and fails
below `WEFT_COMPAT_MIN_PASS_RATE` percent (default 100).

CI ([.github/workflows/ci.yml](../.github/workflows/ci.yml)) runs all of these
on pull requests. Its end-to-end job starts the development stack in both
routing modes and runs the compatibility and escape suites against it.

## Testing an installed stack

Both suites run against any stack. Set:

```sh
export E2B_API_URL=https://api.sandbox.example.com
export E2B_DOMAIN=sandbox.example.com
export E2B_API_KEY=<team key>
export WEFT_ADMIN_KEY=<admin key>       # the suites create teams and clean up templates
export WEFT_DEV_IMAGE=python:3.12-slim  # image for the template tests
export WEFT_ESCAPE_RUNTIME=firecracker  # adds the microVM boundary checks
export WEFT_ESCAPE_HOST_IP=<a host's VPC address>   # optional: probe host ports
packages/compat-tests/run.sh
.weft/compat-venv/bin/pytest tests/escape
```

The credential proxy tests need the development stack's test upstream and
skip elsewhere. On a host, `sudo tests/escape/host_checks.sh` checks the
jails, namespaces, UIDs and seccomp filters of running VMMs (with the
Firecracker development stack, set `WEFT_JAIL_BASE=/var/lib/weft-dev/jail`).

## Website

The marketing site in [site/](../site) is plain HTML styled with Tailwind CSS
and published to GitHub Pages by
[.github/workflows/pages.yml](../.github/workflows/pages.yml) on every push to
`main` that changes it.

```sh
cd site && pnpm install
pnpm run dev                     # rebuilds dist/ as you edit; serve it with any static server
python3 -m http.server -d dist 8080
node og/render.cjs               # regenerate the social images after editing og/card.html
```

## Publishing the SDK

`@weftsh/sandbox` (the helpers and the `weft-sandbox` CLI in
[packages/sdk](../packages/sdk)) is published to npm with provenance by
[.github/workflows/npm.yml](../.github/workflows/npm.yml). To release, bump the
version in `packages/sdk/package.json` and merge to `main`: CI publishes any
version npm does not have yet and skips one it already has. It authenticates
with npm trusted publishing (the workflow's GitHub identity, configured on
npmjs.com), falling back to an `NPM_TOKEN` secret if one is set. Pre-release versions (`0.2.0-beta.1`) go to the `next` dist-tag.
Pull requests that touch the package build, test and pack it without
publishing.

## Repository conventions

- Source files start with a comment saying what they do and why.
- Rust: no `unsafe` (denied workspace-wide); errors with `thiserror` in
  libraries and `anyhow` in binaries.
- TypeScript: ES modules, strict mode, no runtime dependencies beyond the AWS
  SDK and Fastify in the control plane.
- Never commit secrets, private keys, real account IDs or customer data.
  Tests generate keys at run time.
- Contributions: see [CONTRIBUTING.md](../CONTRIBUTING.md). Changes to the
  isolation boundary need two code-owner approvals.
