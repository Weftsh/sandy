# Architecture

```
 clients (E2B SDK, weft-sandbox CLI)
        |  HTTPS: api.<domain>, <port>-<sandbox-id>.<domain>
        v
 internal ALB --------------------------------------------------------------+
   api.<domain> -> api tasks :3000        *.<domain> -> edge tasks :3001    |
        |                                        |                          |
        |   ECS Fargate (control plane image, three roles)                  |
        |   api: E2B REST API, admin API, internal API for hosts/gateway    |
        |   edge: routes sandbox traffic to hosts                           |
        |   worker: timeouts, dead hosts, bootstrap templates, metrics      |
        |                                        |                          |
        |  TLS (pinned), bearer token            |  TLS tunnel (CONNECT)    |
        v                                        v                          |
 host agents :5007 API, :5008 tunnel (EC2 Auto Scaling group)               |
   one Firecracker microVM per sandbox, each in its own network namespace   |
   envd :49983 inside every guest                                           |
        |  every sandbox TCP connection, PROXY v2 header with sandbox ID    |
        v                                                                   |
 egress gateway :15000 (ECS Fargate) --> allowed destinations (NAT)         |
                                                                            |
 DynamoDB (7 tables) . S3 artifacts bucket . ECR (templates) . KMS . Secrets Manager
```

## Components

| Component | Code | Runs as | Responsibilities |
| --- | --- | --- | --- |
| **api** | [packages/control-plane](../packages/control-plane) | ECS Fargate, 2+ tasks | E2B REST API (`/sandboxes`, `/v2/sandboxes`, `/templates`, ...), admin API (`/weft/v1/*`), host heartbeats and gateway policy lookups (`/internal/v1/*`), placement, template builds, license state |
| **edge** | same image | ECS Fargate, 2+ tasks | Routes `https://<port>-<id>.<domain>` (or the `E2b-Sandbox-Id`/`E2b-Sandbox-Port` headers) to the right host through its tunnel. Forwards only the envd endpoints the SDKs use. Checks traffic tokens. WebSockets |
| **worker** | same image | ECS Fargate, 1 task | Kills or pauses expired sandboxes, drops sandboxes of dead hosts, builds bootstrap templates, publishes CloudWatch metrics, runs the daily license check |
| **host agent** | [crates/host-agent](../crates/host-agent) | systemd on each EC2 host | Starts, stops, pauses and resumes microVMs; builds templates from OCI images; per-sandbox network namespaces, DNS resolver and egress forwarder; initializes envd; tunnel for the edge; heartbeats |
| **guest init** | [crates/guest-init](../crates/guest-init) | PID 1 in every guest | Mounts filesystems, supervises envd, reaps processes |
| **envd** | upstream, [guest/envd](../guest/envd) | Inside every guest | The E2B SDKs' agent: processes, files, PTY, watches |
| **egress gateway** | [crates/egress-gateway](../crates/egress-gateway) | ECS Fargate, 2+ tasks | Enforces egress policies, injects credentials, writes the audit log |
| **netpolicy** | [crates/netpolicy](../crates/netpolicy) | Library | Compiles and evaluates egress policies for the host agent and the gateway |
| **awsauth** | [crates/awsauth](../crates/awsauth) | Library | Signs and verifies the IAM identity hosts and the gateway present to the control plane |

## State

| Store | Holds |
| --- | --- |
| DynamoDB | Teams, API key hashes, templates and builds, sandboxes (with optimistic versioning), hosts, license and usage state. Point-in-time recovery on |
| S3 | Template snapshots (root filesystem, memory, VM state, zstd-compressed) and paused sandboxes. Hosts read and write only through presigned URLs |
| ECR | Template images you push |
| Secrets Manager | Admin key, license key, egress CA private key, and the secrets you tag for the credential proxy |

The control plane is stateless: any api task can serve any request. Hosts
hold only running sandboxes and caches of template files.

## Request flows

**Create a sandbox**

1. The SDK calls `POST /v2/sandboxes` with a team key.
2. The api resolves the template, computes the sandbox's egress policy from
   the team policy and the SDK's network options, and picks a host: live, with
   room in slots and memory, preferring hosts that have the template cached.
3. It calls `PUT /v1/sandboxes/<id>` on the host with the template's presigned
   S3 URLs (if the host lacks them), the policy and fresh envd and traffic
   tokens. If the host is full, it tries the next one.
4. The host reserves a slot, creates the network namespace and tap device,
   restores the template snapshot in a jailed Firecracker, and calls envd
   `/init` with the access token, clock, environment and, when the policy has
   credential rules, the egress CA.
5. The api returns the sandbox ID, domain and envd token (E2B's response shape).

**Commands, files and PTY**

The SDK talks to envd at `https://49983-<id>.<domain>`. The edge looks up the
sandbox's host, opens `CONNECT <id>:49983` through the host's TLS tunnel
(pinned certificate, bearer token), and streams the request. The host
forwards the connection into the sandbox's network namespace. envd checks the
access token.

**Outbound connections**

Inside the slot namespace, all guest TCP is redirected to the host agent's
forwarder (port 15001). The forwarder recovers the original destination and
opens a connection to the gateway with a PROXY v2 header whose TLV `0xE0`
carries the sandbox ID. The gateway fetches the sandbox's policy and host
address from the api (cached 30 s), checks the connection comes from that
host, reads the SNI or `Host` header, decides, connects and splices. DNS goes
to the host agent's resolver (port 15053), which answers only names the policy
allows.

**Pause and resume**

Pause snapshots the microVM's memory and state, stops it, and uploads the
snapshot and root filesystem to S3 through presigned multipart URLs. Resume
(`Sandbox.connect`) places the sandbox on any host with room, which downloads
the files and restores them.

## Ports

| Port | Where | Purpose |
| --- | --- | --- |
| 443 | Load balancers | Clients |
| 3000, 3001 | api and edge tasks | From the load balancer |
| 5007 | Hosts | Host agent API (from api, edge and worker tasks) |
| 5008 | Hosts | Tunnel to sandboxes (from api and edge tasks) |
| 15000 | Gateway tasks | Sandbox connections (from hosts) |
| 15001, 15053 | Host, inside sandbox namespaces only | Egress forwarder, DNS resolver |
| 49983 | Inside each guest | envd |

Security groups allow exactly these paths; see
[deploy/README.md](../deploy/README.md#what-the-stack-creates-and-why).
