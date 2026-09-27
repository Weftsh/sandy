# Licensing

Weft Sandboxes is published under two licenses. Each directory carries its
own `LICENSE` file, and each package manifest names its license.

| Component | Paths | License |
| --- | --- | --- |
| SDK, CLI, install templates, AMI build, guest build scripts, docs, test suites | `packages/sdk`, `packages/compat-tests`, `deploy/`, `guest/`, `templates/`, `tests/`, `docs/`, `scripts/` | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| Control plane, edge proxy, licensing client, host agent, egress gateway, guest init | `packages/control-plane`, `packages/license`, `crates/` | [FSL-1.1-ALv2](LICENSES/FSL-1.1-ALv2.md) |

The Functional Source License lets you read, audit, modify and run the
software for any purpose other than offering a competing product or service.
Each released version becomes available under Apache-2.0 on the second
anniversary of its release.

Anything not covered by a more specific `LICENSE` file is Apache-2.0.

Third-party components that are redistributed with the product, such as the
E2B `envd` in-guest agent (Apache-2.0) and Firecracker (Apache-2.0), are
listed in [NOTICE](NOTICE) with their licenses.
