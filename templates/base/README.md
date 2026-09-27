# Base template image

`ghcr.io/weftsh/sandbox-base` is the image the stack builds into the default
`base` template (the one `Sandbox.create()` uses when no template is named):
Ubuntu 24.04 with Python 3, Node.js 24 (LTS, from the official release,
pinned by SHA-256 in the Dockerfile), git and build tools.
Build your own templates from any image instead; see
[docs/templates.md](../../docs/templates.md).

Published by `.github/workflows/base-template.yml`, signed with cosign
(keyless, this repository's workflow identity).
