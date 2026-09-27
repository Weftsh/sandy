# Templates

A template is the image a sandbox starts from. Any Linux container image
(`linux/amd64`) can become a template. The host agent adds the sandbox init
and envd while building it, so images need nothing Weft-specific.

## The `base` template

`Sandbox.create()` without a template name uses `base`. The stack builds it at
first start from `ghcr.io/weftsh/sandbox-base:<version>`
([templates/base](../templates/base)): Ubuntu 24.04 with Python 3, Node.js,
git, build tools and a `user` account with passwordless sudo. The image is
published and cosign-signed by `.github/workflows/base-template.yml`.

To start from other images at install time, change the `BootstrapTemplates`
stack parameter: a comma-separated list of `name=image` pairs. Bootstrap
templates are public, which means every team can use them.

## Building a template

### From an existing image

```sh
weft-sandbox templates build --name data-science \
  --image ghcr.io/example/data-science:1.4 --cpu 2 --memory 2048 --wait
```

Images come from public registries (hosts need `HostInternetAccess=enabled`,
the default) or from your stack's ECR repository (`EcrRepositoryUri` output).
Hosts never get ECR permissions of their own: the control plane gives them a
short-lived pull token for that one repository.

Pin images by digest (`image@sha256:...`) for reproducible templates.

### From a Dockerfile

```sh
weft-sandbox templates build --name my-agent \
  --dockerfile ./Dockerfile --context . \
  --repository <EcrRepositoryUri output> --wait
```

This runs `docker build --platform linux/amd64` locally, pushes the image to
the stack's ECR repository (using `aws ecr get-login-password`), and builds the
template from the pushed digest. It needs Docker and the AWS CLI, with
credentials allowed to push to the repository.

### With the E2B SDK

`Template.build` works for image-based templates:

```python
from e2b import Template

template = (
    Template()
    .from_image("123456789012.dkr.ecr.us-east-1.amazonaws.com/weft-sandboxes:my-agent")
    .set_envs({"APP_ENV": "sandbox"})
    .set_workdir("/app")
    .set_start_cmd("python3 -m my_agent.server", "curl -sf http://127.0.0.1:8000/health")
)
Template.build(template, "my-agent", cpu_count=2, memory_mb=2048)
```

Steps that change files (`run_cmd`, `copy`, `pip_install`, `apt_install` and
similar) are rejected with a 400. Put them in a Dockerfile instead. The full
list is in [compatibility.md](compatibility.md#templates).

### Options

| Option | CLI flag | SDK | Default | Range |
| --- | --- | --- | --- | --- |
| vCPUs | `--cpu` | `cpu_count` | 2 | 1 to 64 |
| Memory (MiB) | `--memory` | `memory_mb` | 512 | 128 to 262144 |
| Disk (MiB) | `--disk` | none | 4096 | 512 to 1048576 |
| Environment | `--env K=V` (repeatable) | `set_envs` | the image's `ENV` | |
| Start command | `--start-cmd` | `set_start_cmd` | none | |
| Ready command | `--ready-cmd` | `set_start_cmd` / `set_ready_cmd` | none | |
| Visible to every team | `--public` | none | no | |

Template names are 1 to 63 lowercase letters, digits, `-` or `_`.

## What happens during a build

1. A host pulls the image's `linux/amd64` manifest and verifies every layer
   against its digest.
2. It unpacks the layers in a chroot, applying whiteouts and refusing paths
   that escape the root.
3. It adds `weft-guest-init` (PID 1) and envd, and creates the `user` account
   unless the image has one. The account gets passwordless sudo when the
   image has `sudo`. The image needs `/bin/sh`; `bash` is recommended.
4. **Firecracker**: the root filesystem becomes an ext4 image. A microVM boots
   it, runs the start command until the ready command succeeds (up to five
   minutes), and is saved as a full snapshot.
5. The snapshot is compressed and uploaded to the stack's S3 bucket. Other
   hosts download it the first time they start a sandbox from it.

Sandboxes then start by restoring the snapshot, so whatever the start command
launched is already running. Every restored sandbox gets its own envd access
token and fresh kernel randomness (VMGenID and virtio-rng). Userspace random
state created by the start command, and `/proc/sys/kernel/random/boot_id`, are
shared by every sandbox from the same build. Do not generate secrets in a start
command.

Snapshots load only on the CPU family and Firecracker release that created
them. Keep the host fleet on one instance family. After a Firecracker upgrade,
rebuild each template with `weft-sandbox templates rebuild <template-id>`.

## Managing templates

```sh
weft-sandbox templates list
weft-sandbox templates get <template-id>      # status, build ID, build log
weft-sandbox templates rebuild <template-id> --wait
weft-sandbox templates delete <template-id>
```

Deleting a template does not affect sandboxes that are already running.
