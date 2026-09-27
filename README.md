# Weft Sandboxes

**Secure sandboxes for AI agents, running in your own AWS account.**

Give your agents a real computer: run the code they write, install packages,
work with files, start servers. Each sandbox is its own Firecracker microVM,
and the whole service runs in *your* AWS account, so the code, data and
credentials your agents work with stay under your control.

It works with the open-source E2B SDKs you may already use. Point them at your
stack with three environment variables and your code runs unchanged.

[![CI](https://github.com/Weftsh/sandy/actions/workflows/ci.yml/badge.svg)](https://github.com/Weftsh/sandy/actions/workflows/ci.yml)
[![License: FSL-1.1-ALv2](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue)](LICENSE.md)

> **Pre-release.** The first release has not been published yet. You can
> [try it locally](#try-it-locally) today. See [Project status](#project-status)
> for exactly what has been verified.

---

## Why Weft Sandboxes

- **Your data stays in your account.** Sandboxes, templates, logs and
  secrets live in your VPC, encrypted with your KMS key. Weft has no access to
  your stack. Online licenses make one daily license check with four fields
  (license ID, version, Region, peak sandbox count); offline and AWS
  Marketplace licenses make none.
- **No new SDK to learn.** The unmodified `e2b` packages for Python and
  JavaScript work as they are. Switching an existing code base is three
  environment variables.
- **Real isolation for untrusted code.** Every sandbox runs its own Linux
  kernel in a Firecracker microVM, started through the jailer. Sandboxes
  cannot reach the host, the EC2 metadata service or each other, and an
  [escape-attempt suite](tests/escape) checks this.
- **You decide what agents can reach.** Outbound traffic is denied by
  default. Allow the hosts each team needs, and every connection is checked
  and written to an audit log.
- **Secrets agents can use but never see.** The egress gateway adds API keys
  from AWS Secrets Manager to allowed requests. The key never enters the
  sandbox, so agents can call APIs without ever holding the credentials.
- **It's your infrastructure.** One CloudFormation stack with your IAM, VPC,
  CloudWatch and Auto Scaling. Deleting the stack removes what it created
  ([details](docs/install.md#uninstall)).

## What using it looks like

```python
from e2b import Sandbox

sbx = Sandbox.create()                                  # a fresh microVM

# Run code your agent wrote
sbx.files.write("/home/user/analysis.py", "print(sum(range(101)))")
print(sbx.commands.run("python3 analysis.py").stdout)   # 5050

# Let it start a web app and open it in your browser
sbx.commands.run("python3 -m http.server 8000", background=True)
print("https://" + sbx.get_host(8000))                  # https://8000-<id>.sandbox.example.com

sbx.kill()
```

The same in JavaScript:

```js
import { Sandbox } from "e2b";

const sbx = await Sandbox.create();
await sbx.files.write("/home/user/hello.txt", "hello from JS\n");
const result = await sbx.commands.run("cat hello.txt && echo \"6 x 7 = $((6 * 7))\"");
console.log(result.stdout); // hello from JS
                            // 6 x 7 = 42
await sbx.kill();
```

Everything else in the SDKs works the same way: streaming output, background
processes, file upload and download, directory watches, interactive
terminals, pause and resume, and custom templates.
[docs/compatibility.md](docs/compatibility.md) lists every feature and the
few that are not supported yet.

## What you can build

- **Code interpreters** for LLM apps: analyze data, make charts, run
  generated code.
- **Coding agents** that clone repositories, install dependencies and run
  tests in a real environment.
- **Live previews** of apps an agent builds, each on its own URL inside your
  network.
- **Evaluations and batch jobs** that run many isolated attempts in parallel.
- **Untrusted user code** in notebooks, playgrounds and grading systems.

## How it works

```
 your app (E2B SDK)
        |  HTTPS
        v
 +------------------------------ your AWS account ------------------------------+
 |  load balancer --> control plane (API, sandbox URLs)                          |
 |                        |                                                      |
 |                        v                                                      |
 |  EC2 hosts --> Firecracker microVMs, one per sandbox                          |
 |                        |  every outbound connection                           |
 |                        v                                                      |
 |               egress gateway: allowlist, credential injection, audit log --> internet
 |                                                                               |
 |  DynamoDB (state)  S3 (templates, paused sandboxes)  KMS  Secrets Manager    |
 +-------------------------------------------------------------------------------+
```

Templates are booted once and saved as snapshots, so a new sandbox restores
from a snapshot with the template's processes already running. Hosts scale
with demand. [docs/architecture.md](docs/architecture.md) has the details.

## Get started

### Try it locally

The development stack runs the whole service on one Linux machine. Sandboxes
there are namespaced processes, not microVMs, so use it to evaluate the API,
not to run untrusted code. You need root, Rust, Node.js 22 with pnpm, Go,
Python 3.11 or later, `iproute2`, `iptables` and `openssl`.

```sh
git clone https://github.com/Weftsh/sandy && cd sandy
scripts/dev-stack.sh build                                 # as you; about 5 minutes the first time
sudo env "PATH=$PATH" scripts/dev-stack.sh up --no-build   # starts everything (root: namespaces, iptables)
source .weft/dev/e2b.env                                   # points the E2B SDKs at it
python3 -m venv .weft/venv && .weft/venv/bin/pip install -q e2b
.weft/venv/bin/python -c 'from e2b import Sandbox; s = Sandbox.create(); print(s.commands.run("echo hello from a sandbox").stdout); s.kill()'
sudo scripts/dev-stack.sh down                             # stops everything and cleans up
```

The same environment file sets up the admin CLI, so
`node packages/sdk/dist/cli.js teams list` works right away.
[docs/development.md](docs/development.md) covers the rest.

### Install in your AWS account

*Available with the first release.*

1. **Launch the stack** from the release's Launch Stack link. Enter a domain
   (such as `sandbox.example.com`), its Route 53 hosted zone or an ACM
   certificate, and your license key. With the defaults the stack is ready in
   about 15 minutes.
2. **Create a team and an API key** with the admin CLI:

   ```sh
   npm install -g @weftsh/sandbox
   weft-sandbox login --api-url https://api.sandbox.example.com --key <admin key>
   weft-sandbox teams create research       # prints the team's API key once
   ```

3. **Allow the network access your agents need.** Teams start with none:

   ```sh
   echo '{"allow": [{"host": "pypi.org"}, {"host": "files.pythonhosted.org"}]}' > policy.json
   weft-sandbox egress set <team-id> policy.json
   ```

4. **Point your code at the stack** (next section).

[docs/install.md](docs/install.md) walks through it, including networking,
verification and uninstalling.

### Point your code at it

```sh
export E2B_API_URL=https://api.sandbox.example.com
export E2B_DOMAIN=sandbox.example.com
export E2B_API_KEY=weft_sk_...
```

`weft-sandbox env --key <team key>` prints these for you. Already using the
E2B SDKs elsewhere? [docs/migration.md](docs/migration.md) lists what to check.

## Everyday tasks

| To | Run |
| --- | --- |
| Create a team and its first API key | `weft-sandbox teams create <name>` |
| Rotate a key | `weft-sandbox keys create <team-id>`, then `weft-sandbox keys revoke <team-id> <key-id>` |
| Allow hosts, or inject a credential | `weft-sandbox egress set <team-id> policy.json` ([format](docs/egress.md)) |
| Build a template from an image | `weft-sandbox templates build --name data --team <team-id> --image python:3.12 --wait` |
| Build a template from a Dockerfile | `weft-sandbox templates build --name app --team <team-id> --dockerfile Dockerfile --repository <ECR URI> --wait` |
| See hosts and running sandboxes | `weft-sandbox hosts`, `weft-sandbox sandboxes` |
| Check the license | `weft-sandbox license status` |

Developers can also build templates from code with the SDK's
`Template.build()`; see [docs/templates.md](docs/templates.md).

## What it costs to run

You pay AWS directly for what the stack uses. With default settings in
us-east-1, the always-on services (NAT gateways, load balancer, Fargate
tasks, KMS, logs) cost about $220 to $230 a month, plus about $290 a month
per host (`c8i.2xlarge` On-Demand with its data volume). Spot hosts cost
less. [deploy/README.md](deploy/README.md#idle-cost) has the breakdown. A
Weft license is separate.

## FAQ

**Do I have to change my code?**
No, only the three environment variables. A few SDK features are not
supported yet (auto-resume, snapshots and fork, template build steps like
`RUN`); they return a clear error instead of misbehaving.
[docs/compatibility.md](docs/compatibility.md) has the full list.

**Can sandboxes reach the internet?**
Only what a team's egress policy allows, including over DNS. Change a policy
and running sandboxes follow within 30 seconds.

**What if an agent tries to escape or misbehave?**
It is inside its own microVM, with its own kernel, CPU and memory limits and
network namespace, and its traffic passes through the egress gateway. See
[docs/security.md](docs/security.md) for the threat model, and
[SECURITY.md](SECURITY.md) to report a vulnerability.

**How many sandboxes fit on a host?**
It depends on template memory. A `c8i.2xlarge` runs about 21 sandboxes of
512 MiB, and hosts are added automatically as utilization grows.

**Which AWS instance types?**
C8i, M8i and R8i with nested virtualization, or bare-metal instances. The
stack checks your choice.

**Is it open source?**
The core is source-available: public, and free to use, modify and self-host
for anything except offering a competing service, under the Functional
Source License. Each release becomes Apache-2.0 open source two years after
it ships. The SDK, CLI, deployment templates and tests are Apache-2.0 today.

## Project status

Pre-release (0.1.0).

- **Verified**, on every push to `main` in CI and by hand: the full E2B SDK
  compatibility suite (Python and JavaScript, e2b 2.51.0) and the network
  half of the escape-attempt suite. That half covers the metadata service,
  host addresses, other sandboxes, direct internet, UDP, ICMP and DNS
  tunnels. Both run against the real host agent, egress gateway and envd,
  using the development runtime.
- **Unit and integration tested:** control plane (including against
  DynamoDB Local), egress gateway, policy engine, licensing, host agent,
  Firecracker runtime (against a simulated Firecracker), and the
  CloudFormation custom resources. The stack template passes `cfn-lint` and
  `checkov`.
- **Not yet verified:** Firecracker microVMs on real KVM hardware, including
  the VM-boundary half of the escape suite, and a full install in an AWS
  account. Both are planned before the first release.

Known limitations are listed in
[docs/compatibility.md](docs/compatibility.md#known-limitations).

## Documentation

| Guide | Covers |
| --- | --- |
| [Install](docs/install.md) | Installing, first team and key, verifying, uninstalling |
| [Migration](docs/migration.md) | Pointing existing E2B SDK code at your stack |
| [Compatibility](docs/compatibility.md) | Every SDK feature, tested or not, and known limitations |
| [Templates](docs/templates.md) | Custom sandbox images |
| [Egress](docs/egress.md) | Allowlists, credential injection, audit log |
| [Security](docs/security.md) | Threat model, isolation layers, data flows |
| [Licensing](docs/licensing.md) | License keys and exactly what the daily check sends |
| [Operations](docs/operations.md) | Upgrades, scaling, logs, metrics, troubleshooting |
| [Architecture](docs/architecture.md) | Components, ports and request flows |
| [Development](docs/development.md) | Local stack and test suites |
| [Deployment reference](deploy/README.md) | Every stack parameter and output, IAM, host image, releases |

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
for the repository layout, review rules and checks. Report security issues
privately as described in [SECURITY.md](SECURITY.md).

## License

The core (control plane, license package and Rust crates) is under the
[Functional Source License 1.1, Apache 2.0 future license](LICENSES/FSL-1.1-ALv2.md).
The SDK, tests, deployment templates and build scripts are under
[Apache-2.0](LICENSES/Apache-2.0.txt). See [LICENSE.md](LICENSE.md) and
[NOTICE](NOTICE).

"E2B" is a trademark of its owner. Weft Sandboxes is an independent project,
not affiliated with or endorsed by E2B, and uses the name only to describe
compatibility with the open-source E2B SDKs.
