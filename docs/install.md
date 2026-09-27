# Installing Weft Sandboxes

Weft Sandboxes installs as one CloudFormation stack in your AWS account. This
page walks through an install from start to first sandbox. Every parameter,
output and IAM role is documented in [deploy/README.md](../deploy/README.md).

## Before you start

- **An AWS account and a supported Region.** The stack checks that the
  release has a host AMI for the Region.
- **A domain for sandboxes**, such as `sandbox.example.com`. Clients use it as
  `E2B_DOMAIN`. The API is served at `https://api.<domain>`, and every
  sandbox port at `https://<port>-<sandbox-id>.<domain>`.
- **TLS for that domain**, either:
  - a Route 53 **public hosted zone** containing the domain; the stack then
    creates and DNS-validates an ACM certificate for `api.<domain>` and
    `*.<domain>`, or
  - an existing ACM certificate in the same Region covering both names.
- **A license key**, or an AWS Marketplace subscription. See
  [licensing.md](licensing.md).
- **Quota** for the host instance type: the default is one `c8i.2xlarge`
  On-Demand host. Hosts use nested virtualization (C8i, M8i and R8i) or bare
  metal instances; the stack checks the types you choose.

## Create the stack

1. Open the **Launch Stack** link on the GitHub release page for your Region.
   The template URL has the form
   `https://weft-sandboxes-releases-<region>.s3.<region>.amazonaws.com/v<version>/weft-sandboxes.yaml`.
2. Fill in:
   - `DomainName`: for example `sandbox.example.com`
   - `PublicHostedZoneId` or `CertificateArn`
   - `LicenseKey` (or set `LicenseMode=marketplace`)
3. Leave everything else at its default for a first install. The defaults
   create a new two-AZ VPC with private subnets and an internal load balancer.
   To use an existing VPC, set `VpcId` and `PrivateSubnetIds`.
4. Acknowledge that the stack creates IAM resources, and create it.

With the defaults the stack is ready in about 12 to 15 minutes. NAT
gateways, certificate validation and the first ECS deployment take most of
that time. Before it starts any service or host, the stack verifies the
signed release manifest, and it stops if the AMI, the container images or the
Lambda code do not match it.

## Reach the stack

The domain resolves only inside the stack's VPC, through a Route 53 private
hosted zone. Clients in other networks (peered VPCs, Transit Gateway, VPN,
Direct Connect) need one of:

- a Route 53 Resolver inbound endpoint in the VPC, with your DNS forwarding
  the domain to it, or
- the private hosted zone (`PrivateHostedZoneId` output) associated with the
  clients' VPCs.

Their CIDRs must also be allowed by `ClientCidr` (default: the VPC CIDR).

For a short evaluation from outside AWS, set `LoadBalancerScheme` to
`internet-facing` and `PublicAllowedCidr` to your own address range. The stack
then adds a second, public load balancer that only that range can reach.
`0.0.0.0/0` is rejected.

## Create a team and an API key

The stack generates a bootstrap admin key in Secrets Manager:

```sh
aws secretsmanager get-secret-value --secret-id <AdminKeySecretArn output> \
  --query SecretString --output text
```

Use it with the `weft-sandbox` CLI (Node.js 22 or later):

```sh
npm install -g @weftsh/sandbox
weft-sandbox login --api-url https://api.sandbox.example.com --key <admin key> \
  --domain sandbox.example.com
weft-sandbox license status
weft-sandbox teams create my-team      # prints the team ID and its first API key, once
weft-sandbox env --key <team key>      # the three E2B_* variables for clients
```

The admin key manages teams, keys, egress policies and templates. Give
clients team keys only. Team keys start with `weft_sk_`, and the stack stores
only their hashes.

Teams start with **no outbound network access**. Allow what they need with
`weft-sandbox egress set` (see [egress.md](egress.md)).

## Check that it works

```sh
pip install e2b
export E2B_API_URL=https://api.sandbox.example.com
export E2B_DOMAIN=sandbox.example.com
export E2B_API_KEY=<team key>
python3 - <<'PY'
from e2b import Sandbox
sbx = Sandbox.create()
print(sbx.commands.run("uname -r && id").stdout)
sbx.files.write("/home/user/hello.txt", "hi")
print(sbx.files.read("/home/user/hello.txt"))
sbx.kill()
PY
```

`uname -r` prints the guest kernel version (`...-weft`), not the host's.

To run the full compatibility and escape-attempt suites against your stack,
see [development.md](development.md#testing-an-installed-stack).

## Operators

Hosts have no SSH. Use AWS Systems Manager Session Manager:
`aws ssm start-session --target <instance-id>`. Logs, metrics, upgrades and
scaling are covered in [operations.md](operations.md).

## Uninstall

Delete the stack. A custom resource first empties and deletes the artifacts
bucket and schedules the stack's KMS key for deletion (7-day waiting period).
CloudFormation then deletes everything else it created. Set
`RetainBucketsOnDelete=true` before deleting if you want to keep the bucket and
its key. What is deliberately left behind (ACM validation records, AWS
service-linked roles) is listed in
[deploy/README.md](../deploy/README.md#uninstall).
