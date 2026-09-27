# @weftsh/sandbox

Helpers and an admin CLI for [Weft Sandboxes](https://github.com/weftsh/byoc),
self-hosted sandboxes that are compatible with the E2B SDKs.

Create and use sandboxes with the unmodified `e2b` package. Use this package
to point it at your stack and to manage teams, API keys, egress policies and
templates.

```sh
npm install @weftsh/sandbox e2b
```

## Configure the E2B SDK

```ts
import { configureE2B } from "@weftsh/sandbox";
import { Sandbox } from "e2b";

configureE2B({ apiUrl: "https://api.sandbox.example.com", domain: "sandbox.example.com", apiKey: process.env.TEAM_KEY! });
const sbx = await Sandbox.create();
```

`e2bEnvironment()` returns the same settings as `E2B_API_URL`, `E2B_DOMAIN`
and `E2B_API_KEY` variables, for child processes or other languages.

## Admin client

```ts
import { WeftAdmin } from "@weftsh/sandbox";

const admin = new WeftAdmin({ apiUrl: "https://api.sandbox.example.com", apiKey: process.env.WEFT_ADMIN_KEY });
const { team, apiKey } = await admin.teams.create("research");
await admin.teams.setEgressPolicy(team.teamId, { allow: [{ host: "pypi.org" }] });
const t = await admin.templates.build({ name: "data", image: "python:3.12-slim", memoryMB: 1024 });
await admin.templates.waitUntilReady(t.templateId);
```

Namespaces: `license`, `teams`, `apiKeys`, `templates`, `hosts`, `sandboxes`.

## CLI

```sh
weft-sandbox login --api-url https://api.sandbox.example.com --key <admin key>
weft-sandbox help
```

Commands cover the license, teams, keys, egress policies, templates (from an
image or a Dockerfile pushed to the stack's ECR repository), hosts and
sandboxes. Settings are saved to `~/.config/weft-sandbox/config.json` with
mode 0600.

## License

Apache-2.0. "E2B" is a trademark of its owner; this project is not affiliated
with or endorsed by E2B.
