# Base template image

`ghcr.io/weftsh/sandbox-base` is the image the stack builds into the default
`base` template (the one `Sandbox.create()` uses when no template is named).
Build your own templates from any image instead; see
[docs/templates.md](../../docs/templates.md).

Published by `.github/workflows/base-template.yml`, signed with cosign
(keyless, this repository's workflow identity).
