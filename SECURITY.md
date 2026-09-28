# Security policy

Weft Sandboxes runs untrusted, often AI-written code inside customer AWS
accounts. We treat every report about isolation, credential handling or the
supply chain as urgent.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through either:

- GitHub private vulnerability reporting: the **Security** tab of this
  repository, then **Report a vulnerability**; or
- email to **security@weft.sh**.

Please include the affected component and version, the steps to reproduce,
and the impact you observed. You will get an acknowledgement within two
business days and a status update at least weekly until the issue is closed.

## Disclosure

We follow a **90-day coordinated disclosure** window from the date of your
report, shorter if a fix ships sooner or the issue is being exploited. We
credit reporters in the advisory unless you ask us not to.

## What is in scope

- Escaping a sandbox: reaching the host, the instance metadata service,
  other sandboxes, the host agent's API, or network destinations outside the
  sandbox's egress policy.
- Reading or using credentials the credential proxy injects, from inside a
  sandbox.
- Bypassing API key checks, team isolation or the internal IAM
  authentication between hosts, the egress gateway and the control plane.
- Tampering with release artifacts, or making a stack accept an unsigned
  image.
- Anything that sends customer code, data, secrets or logs out of the
  customer's AWS account.

The development namespace runtime (`--insecure-namespace-runtime`) does not
isolate sandboxes by design; escaping it is not a vulnerability.

## Patch commitment

Security fixes for Firecracker, KVM or guest-kernel advisories ship as
rebuilt, signed host AMIs within **72 hours** of the upstream advisory, to
every account with an active license.

## Supported versions

Security fixes land on the latest release, which is the only supported
version.
