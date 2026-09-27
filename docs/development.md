# Development

## Requirements

Linux with root (network namespaces and iptables), Rust (the version in
[rust-toolchain.toml](../rust-toolchain.toml)), Node.js 22 with pnpm, Go (to
build envd), Python 3.11 or later, `iproute2`, `iptables` and `openssl`.
Docker is needed only for container images and Dockerfile templates, and KVM
only for the Firecracker runtime.

## Local stack

```sh
pnpm install
sudo scripts/dev-stack.sh up            # builds everything (about 5 minutes the first time), then starts it
source .weft/dev/e2b.env                # E2B_*, WEFT_ADMIN_KEY and test settings
python3 -m venv .weft/venv && .weft/venv/bin/pip install -q e2b
.weft/venv/bin/python -c 'from e2b import Sandbox; s = Sandbox.create(); print(s.commands.run("uname -a").stdout); s.kill()'
sudo scripts/dev-stack.sh down
```

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

On a Linux machine with `/dev/kvm`:

```sh
guest/kernel/build.sh                   # dist/guest/vmlinux (about 20 minutes)
guest/envd/build.sh                     # dist/guest/envd
cargo build --release -p weft-guest-init --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/weft-guest-init dist/guest/
cargo build --release -p weft-host-agent
```

Install Firecracker and the jailer from the release pinned in
[guest/kernel/VERSION](../guest/kernel/VERSION), then run the host agent with
`--runtime firecracker` and `--kernel`, `--firecracker-bin`, `--jailer-bin`
and `--chroot-base` pointing at them. See `weft-host-agent run --help`.

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
jailer, the UIDs and the seccomp filters of running VMMs.

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
