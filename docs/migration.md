# Moving E2B SDK code to Weft Sandboxes

Code written for the E2B SDKs runs against Weft Sandboxes unmodified. The work
is in the environment around it: API keys, templates and egress. This page
lists the steps and the differences to check.

## 1. Install and create a team

Follow [install.md](install.md) to create the stack, a team and a team API
key.

## 2. Allow the network access your sandboxes need

This is the biggest difference. **Sandboxes on Weft Sandboxes start with no
outbound access**, while E2B's hosted sandboxes default to full internet
access. List what your agents reach (package indexes, APIs, Git hosts) and put
it in the team policy:

```json
{
  "allow": [
    { "host": "pypi.org" },
    { "host": "files.pythonhosted.org" },
    { "host": "registry.npmjs.org" },
    { "host": "github.com" },
    { "host": "*.githubusercontent.com" }
  ]
}
```

```sh
weft-sandbox egress set <team-id> policy.json
```

`{"host": "*"}` allows any public destination, which is the closest match to
E2B's default, but consider starting narrow. The audit log
([egress.md](egress.md#audit-log)) shows what sandboxes try to reach and what
was denied.

If your code puts API keys into sandboxes through `envs`, move them into
credential rules instead. The gateway then adds the key to requests, and the
sandbox never holds it.

## 3. Recreate your templates

Template IDs and names from E2B do not carry over. Rebuild each template on
your stack under the same name, so `Sandbox.create("my-template")` keeps
working:

| You have | Do |
| --- | --- |
| An `e2b.Dockerfile` | `weft-sandbox templates build --name my-template --team <team-id> --dockerfile e2b.Dockerfile --repository <EcrRepositoryUri output> --cpu 2 --memory 1024 --wait` |
| `Template()` code using only `from_image`, `set_envs`, `set_workdir`, `set_start_cmd` | Run it unchanged against your stack |
| `Template()` code with `run_cmd`, `copy`, `pip_install` and similar | Move those steps into a Dockerfile, then build it as above |
| The default template | Nothing: `base` exists on every stack |

Add `--start-cmd` and `--ready-cmd` if the E2B template had them. See
[templates.md](templates.md).

## 4. Point your code at the stack

```sh
export E2B_API_URL=https://api.sandbox.example.com
export E2B_DOMAIN=sandbox.example.com
export E2B_API_KEY=weft_sk_...
```

`weft-sandbox env --key <team key>` prints these. In code that configures the
SDK explicitly, pass the same values as `api_url`/`apiUrl`, `domain` and
`api_key`/`apiKey`.

Your clients must be able to resolve and reach the domain. It resolves only
inside the stack's VPC unless you connect other networks
([install.md](install.md#reach-the-stack)).

## 5. Check the differences

Go through [compatibility.md](compatibility.md). The ones most likely to
matter:

- **`lifecycle={"auto_resume": True}`** is rejected. Resume paused sandboxes
  with `Sandbox.connect()`.
- **Snapshots and `fork`** are not supported. Use pause and connect.
- **Sandbox logs** are empty.
- **Network options** (`allow_internet_access`, `network.allow_out`) can only
  narrow the team policy. An `allow_out` entry outside the team policy fails
  with 403 instead of opening access.
- **Paused sandboxes** are kept 30 days.
- **Capacity** is your host fleet. When it is full, creates fail with 503 until
  Auto Scaling adds a host, which takes a few minutes. Size `HostMinSize` for
  your peak or retry on 503.

## 6. Verify

Run your own integration tests against the stack, and optionally the
compatibility and escape-attempt suites from this repository
([development.md](development.md#testing-an-installed-stack)).
