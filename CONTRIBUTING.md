# Contributing

Thanks for helping. Please read this before opening a pull request.

## Contributor License Agreement

Contributions are accepted under a Contributor License Agreement. A bot
comments on your first pull request with a link to sign it; we cannot merge
until it is signed.

## Before you start

- Security issues go to [SECURITY.md](SECURITY.md), never to public issues.
- For anything larger than a small fix, open an issue first so we can agree
  on the approach.

## Review rules

Code on the isolation boundary needs **two human approvals** from code
owners (see [.github/CODEOWNERS](.github/CODEOWNERS)):

- `crates/host-agent/` (networking, Firecracker and jailer, the tunnel)
- `crates/egress-gateway/` and `crates/netpolicy/`
- `crates/guest-init/`
- `deploy/` (IAM, security groups, release verification)

Automated tools and AI agents may propose changes anywhere, but a person
reviews and approves every boundary change.

## Local development

Requirements: Linux, root (for network namespaces and iptables), Rust (the
version in `rust-toolchain.toml`), Node.js 22 with pnpm, Go (to build envd),
Python 3.11+, `iproute2`, `iptables` and `openssl`.

```sh
pnpm install
sudo scripts/dev-stack.sh up          # control plane, egress gateway, host agent
source .weft/dev/e2b.env              # E2B_API_URL, E2B_DOMAIN, E2B_API_KEY, ...
packages/compat-tests/run.sh          # E2B SDK compatibility suite
.weft/compat-venv/bin/pytest tests/escape   # escape-attempt suite
```

The development stack uses the namespace runtime, which does **not** isolate
sandboxes from your machine. See [docs/development.md](docs/development.md).

## Checks

CI runs all of these; please run the relevant ones before pushing:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm -r run typecheck && pnpm test
```

## Style

- Match the surrounding code. Modules start with a comment that says what
  they do and why.
- Keep dependencies few and well known; every new dependency is reviewed.
- No `unsafe` Rust (the workspace denies it).
- Never commit secrets, private keys, real account IDs or customer data.
  Tests generate their keys at run time.
