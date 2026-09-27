# Weft Sandboxes

Self-hosted sandboxes for AI agents and untrusted code, installed as one
CloudFormation stack in **your own AWS account**. Each sandbox is a Firecracker
microVM. The service is compatible with the open-source E2B SDKs, so existing
code keeps working after you change three environment variables:

```sh
export E2B_API_URL=https://api.sandbox.example.com
export E2B_DOMAIN=sandbox.example.com
export E2B_API_KEY=weft_sk_...
```

```python
from e2b import Sandbox

sbx = Sandbox.create()
print(sbx.commands.run("python3 -c 'print(6 * 7)'").stdout)
sbx.kill()
```

Your code, data, secrets and logs stay in your AWS account. Nothing is sent to
Weft except a daily license check with four fields: license ID, version,
Region and peak concurrent sandboxes (see [docs/licensing.md](docs/licensing.md)).
Offline and AWS Marketplace licenses send nothing.

> **Status: pre-release.** Read [Project status](#project-status) for what has
> been verified and what has not.

## Features

- **Compatible with the E2B SDKs.** The unmodified `e2b` packages for Python
  and JavaScript work: create, connect, list, kill, timeouts, pause and
  resume, commands, files, directory watches, PTY and custom templates. The
  [feature matrix](docs/compatibility.md) lists what is not supported yet.
- **Firecracker isolation.** One microVM per sandbox, started through the
  jailer with its own UID/GID, chroot, PID namespace, cgroup limits and rate
  limits. Guests cannot reach instance metadata, the host, other sandboxes or
  the host agent's API. An [escape-attempt suite](tests/escape) checks this.
- **Egress denied by default.** Each team gets an allowlist of hostnames,
  wildcard domains and CIDRs. Every connection passes through an egress
  gateway that enforces it and writes an audit log. See [docs/egress.md](docs/egress.md).
- **Credential proxy.** The gateway adds API keys from AWS Secrets Manager to
  allowed requests. The secret never enters the sandbox.
- **Custom templates** from any container image: public registries, your
  stack's ECR repository or a Dockerfile. See [docs/templates.md](docs/templates.md).
- **Supply chain.** Releases are Sigstore-signed. The stack verifies the
  release manifest and refuses images and AMIs that do not match it.
- **Clean uninstall.** Deleting the stack removes everything it created.

## Install

You need an AWS account, a domain (for example `sandbox.example.com`) with a
Route 53 public hosted zone or an ACM certificate, and a license key. Open the
release's **Launch Stack** link, fill in three parameters and wait about 15
minutes. See [docs/install.md](docs/install.md), and
[deploy/README.md](deploy/README.md) for every parameter and output.

After the stack is up:

```sh
npm install -g @weftsh/sandbox
weft-sandbox login --api-url https://api.sandbox.example.com --key <admin key>
weft-sandbox teams create my-team            # prints the team's API key once
weft-sandbox env --key <team key>            # E2B_* variables for your clients
```

Moving an existing E2B SDK code base? See [docs/migration.md](docs/migration.md).

## Architecture

```
 clients (E2B SDK) --HTTPS--> internal ALB
                                 |-- api.<domain> ----> control plane: api (ECS Fargate)
                                 '-- *.<domain> ------> control plane: edge (ECS Fargate)
                                                          |
                    host agents (EC2 Auto Scaling group) <'  tunnel to envd in each microVM
                      Firecracker microVMs, one per sandbox
                      every outbound connection --PROXY v2--> egress gateway (ECS Fargate)
                                                                  '--> allowed destinations
 state: DynamoDB (7 tables), S3 (templates, paused sandboxes), KMS, Secrets Manager
```

[docs/architecture.md](docs/architecture.md) describes each component and
request flow.

## Documentation

| Document | For |
| --- | --- |
| [docs/install.md](docs/install.md) | Installing, first team and key, verifying, uninstalling |
| [docs/migration.md](docs/migration.md) | Pointing existing E2B SDK code at your stack |
| [docs/compatibility.md](docs/compatibility.md) | SDK feature matrix and known differences |
| [docs/templates.md](docs/templates.md) | Custom sandbox images |
| [docs/egress.md](docs/egress.md) | Egress policies, credential injection, audit log |
| [docs/security.md](docs/security.md) | Threat model, isolation layers, data flows |
| [docs/licensing.md](docs/licensing.md) | License keys, what the daily check sends, Marketplace and offline modes |
| [docs/operations.md](docs/operations.md) | Upgrades, scaling, logs, metrics, troubleshooting |
| [docs/architecture.md](docs/architecture.md) | Components, ports and request flows |
| [docs/development.md](docs/development.md) | Local development stack and test suites |
| [deploy/README.md](deploy/README.md) | CloudFormation parameters, outputs, IAM, host AMI, releases |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities |

## Repository layout

| Path | What it is | License |
| --- | --- | --- |
| `packages/control-plane` | API, edge proxy and worker (TypeScript, Fastify) | FSL-1.1-ALv2 |
| `packages/license` | License key format, verification and daily check | FSL-1.1-ALv2 |
| `crates/host-agent` | Host agent: Firecracker runtime, slot networking, DNS, egress forwarder, tunnel | FSL-1.1-ALv2 |
| `crates/egress-gateway` | Egress policy enforcement and credential proxy | FSL-1.1-ALv2 |
| `crates/netpolicy` | Egress policy compiler shared by host agent and gateway | FSL-1.1-ALv2 |
| `crates/guest-init` | PID 1 inside each sandbox | FSL-1.1-ALv2 |
| `crates/awsauth` | IAM authentication between hosts, gateway and control plane | FSL-1.1-ALv2 |
| `packages/sdk` | `@weftsh/sandbox`: helpers and the `weft-sandbox` CLI | Apache-2.0 |
| `packages/compat-tests` | E2B SDK compatibility suite (Python and JS) | Apache-2.0 |
| `tests/escape` | Escape-attempt suite | Apache-2.0 |
| `deploy` | CloudFormation stack, Lambda custom resources, host AMI (Packer) | Apache-2.0 |
| `guest` | Pinned builds of envd and the guest kernel | Apache-2.0 (build scripts) |
| `templates/base` | The default `base` template image | Apache-2.0 |

## Project status

Pre-release (0.1.0). What has been verified, and how:

- **Verified end to end on Linux** with the real host agent, the real envd and
  the unmodified E2B SDKs (e2b 2.51.0 on PyPI and npm), using the development
  namespace runtime: the full compatibility suite passes, over both
  header-based routing and TLS host-based routing. The network half of the
  escape-attempt suite passes: metadata service over IPv4 and IPv6, host
  addresses, other sandboxes, direct internet, UDP, ICMP and DNS bypasses,
  envd tokens. The CI workflow (`.github/workflows/ci.yml`) runs the same
  suites on every pull request.
- **Unit and integration tested:** control plane (against DynamoDB Local),
  egress gateway, policy compiler, licensing, host agent, Firecracker runtime
  (against a fake Firecracker API and jailer), CloudFormation custom resources.
  The template passes `cfn-lint` and `checkov`.
- **Not yet verified:** Firecracker microVMs on real KVM, including the
  VM-boundary half of the escape suite (`WEFT_ESCAPE_RUNTIME=firecracker`),
  and a full install in an AWS account. Both need a release, which in turn
  needs the release signing key described in [deploy/README.md](deploy/README.md#releases-githubworkflowsreleaseyml).
  The guest kernel has been built and booted under QEMU, not yet under
  Firecracker.

Known limitations are listed in [docs/compatibility.md](docs/compatibility.md#known-limitations).

## License

The core (the control plane, the license package and the Rust crates) is
under the [Functional Source License 1.1, Apache 2.0 future license](LICENSES/FSL-1.1-ALv2.md).
You can use, modify and self-host it for any purpose except offering a
competing commercial service; each release becomes Apache-2.0 two years after
it ships. The SDK, tests, deployment templates and build scripts are under
[Apache-2.0](LICENSES/Apache-2.0.txt). See [LICENSE.md](LICENSE.md) for the
split and [NOTICE](NOTICE) for third-party software.

"E2B" is a trademark of its owner. Weft Sandboxes is an independent project,
is not affiliated with or endorsed by E2B, and uses the name only to describe
compatibility with the open-source E2B SDKs.
